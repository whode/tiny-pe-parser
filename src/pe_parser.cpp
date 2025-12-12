#include "pe_parser.h"

#include <limits>
#include <stdexcept>
#include <utility>

namespace pe {
namespace {

constexpr uint16_t kDosMagic = 0x5A4D;
constexpr uint32_t kPeMagic = 0x00004550;
constexpr uint16_t kOptionalHeaderMagicPE32 = 0x10B;
constexpr uint16_t kOptionalHeaderMagicPE32Plus = 0x20B;

}  // namespace

PeParser::PeParser(std::vector<uint8_t> data) : data_(std::move(data)) {}

void PeParser::EnsureBounds(size_t offset, size_t size) const {
  if (offset > data_.size() || size > data_.size() - offset) {
    throw std::runtime_error("Unexpected end of file while reading PE data.");
  }
}

uint16_t PeParser::ReadU16(size_t offset) const {
  EnsureBounds(offset, sizeof(uint16_t));
  return static_cast<uint16_t>(data_[offset]) |
         (static_cast<uint16_t>(data_[offset + 1]) << 8);
}

uint32_t PeParser::ReadU32(size_t offset) const {
  EnsureBounds(offset, sizeof(uint32_t));
  return static_cast<uint32_t>(data_[offset]) |
         (static_cast<uint32_t>(data_[offset + 1]) << 8) |
         (static_cast<uint32_t>(data_[offset + 2]) << 16) |
         (static_cast<uint32_t>(data_[offset + 3]) << 24);
}

uint64_t PeParser::ReadU64(size_t offset) const {
  EnsureBounds(offset, sizeof(uint64_t));
  uint64_t value = 0;
  for (size_t i = 0; i < sizeof(uint64_t); ++i) {
    value |= static_cast<uint64_t>(data_[offset + i]) << (8u * i);
  }
  return value;
}

std::string PeParser::ReadString(size_t offset, size_t max_len) const {
  EnsureBounds(offset, max_len);
  std::string value;
  value.reserve(max_len);
  for (size_t i = 0; i < max_len; ++i) {
    char c = static_cast<char>(data_[offset + i]);
    if (c == '\0') {
      break;
    }
    value.push_back(c);
  }
  return value;
}

PeMetadata PeParser::Parse() const {
  if (data_.size() < 0x40) {
    throw std::runtime_error("File too small to contain a valid DOS header.");
  }

  if (ReadU16(0) != kDosMagic) {
    throw std::runtime_error("Invalid DOS signature. Not a PE file.");
  }

  uint32_t pe_offset = ReadU32(0x3C);
  EnsureBounds(pe_offset, sizeof(uint32_t));

  if (ReadU32(pe_offset) != kPeMagic) {
    throw std::runtime_error("Invalid PE signature.");
  }

  size_t file_header_offset = pe_offset + sizeof(uint32_t);
  EnsureBounds(file_header_offset, 20);

  FileHeader file_header;
  file_header.machine = ReadU16(file_header_offset + 0);
  file_header.number_of_sections = ReadU16(file_header_offset + 2);
  file_header.time_date_stamp = ReadU32(file_header_offset + 4);
  file_header.pointer_to_symbol_table = ReadU32(file_header_offset + 8);
  file_header.number_of_symbols = ReadU32(file_header_offset + 12);
  file_header.size_of_optional_header = ReadU16(file_header_offset + 16);
  file_header.characteristics = ReadU16(file_header_offset + 18);

  if (file_header.size_of_optional_header < 0x46) {
    throw std::runtime_error("Optional header is too small.");
  }

  size_t optional_header_offset = file_header_offset + 20;
  EnsureBounds(optional_header_offset, file_header.size_of_optional_header);

  OptionalHeader optional_header;
  optional_header.magic = ReadU16(optional_header_offset);
  if (optional_header.magic == kOptionalHeaderMagicPE32) {
    optional_header.is_pe32_plus = false;
  } else if (optional_header.magic == kOptionalHeaderMagicPE32Plus) {
    optional_header.is_pe32_plus = true;
  } else {
    throw std::runtime_error("Unknown optional header magic.");
  }

  optional_header.address_of_entry_point =
      ReadU32(optional_header_offset + 0x10);

  if (optional_header.is_pe32_plus) {
    optional_header.image_base = ReadU64(optional_header_offset + 0x18);
  } else {
    optional_header.image_base = ReadU32(optional_header_offset + 0x1C);
  }

  optional_header.subsystem = ReadU16(optional_header_offset + 0x44);

  size_t section_table_offset =
      optional_header_offset + file_header.size_of_optional_header;
  constexpr size_t kSectionSize = 40;
  if (file_header.number_of_sections >
      std::numeric_limits<size_t>::max() / kSectionSize) {
    throw std::runtime_error("Section table size overflows address space.");
  }
  size_t section_table_size =
      static_cast<size_t>(file_header.number_of_sections) * kSectionSize;
  EnsureBounds(section_table_offset, section_table_size);

  std::vector<SectionHeader> sections;
  sections.reserve(file_header.number_of_sections);
  for (size_t i = 0; i < file_header.number_of_sections; ++i) {
    size_t section_offset = section_table_offset + i * kSectionSize;
    SectionHeader section;
    section.name = ReadString(section_offset, 8);
    section.virtual_size = ReadU32(section_offset + 8);
    section.virtual_address = ReadU32(section_offset + 12);
    section.size_of_raw_data = ReadU32(section_offset + 16);
    section.pointer_to_raw_data = ReadU32(section_offset + 20);
    sections.push_back(std::move(section));
  }

  PeMetadata metadata;
  metadata.file_header = file_header;
  metadata.optional_header = optional_header;
  metadata.sections = std::move(sections);
  return metadata;
}

std::string MachineToString(uint16_t machine) {
  switch (machine) {
    case 0x014C:
      return "x86";
    case 0x8664:
      return "x64";
    case 0x01C0:
      return "ARM";
    case 0x01C4:
      return "ARM Thumb-2";
    case 0xAA64:
      return "ARM64";
    case 0x0200:
      return "Intel Itanium";
    case 0x01F0:
      return "PowerPC";
    default:
      return "Unknown";
  }
}

std::string SubsystemToString(uint16_t subsystem) {
  switch (subsystem) {
    case 1:
      return "Native";
    case 2:
      return "Windows GUI";
    case 3:
      return "Windows CUI";
    case 5:
      return "OS/2 CUI";
    case 7:
      return "POSIX CUI";
    case 9:
      return "Windows CE GUI";
    case 10:
      return "EFI Application";
    case 11:
      return "EFI Boot Service";
    case 12:
      return "EFI Runtime Service";
    case 13:
      return "EFI ROM";
    case 14:
      return "Xbox";
    case 16:
      return "Windows Boot Application";
    default:
      return "Unknown";
  }
}

}  // namespace pe
