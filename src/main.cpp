#include "pe_parser.h"

#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr std::streamsize kMaxInputFileSizeBytes =
    static_cast<std::streamsize>(64) * 1024 * 1024;  // 64 MiB

std::vector<uint8_t> ReadFile(const std::string& path) {
  std::ifstream file(path, std::ios::binary | std::ios::ate);
  if (!file) {
    throw std::runtime_error("Unable to open file: " + path);
  }

  std::streamsize size = file.tellg();
  if (size < 0) {
    throw std::runtime_error("Unable to determine file size: " + path);
  }
  if (size == 0) {
    throw std::runtime_error("File is empty: " + path);
  }
  if (size > kMaxInputFileSizeBytes) {
    throw std::runtime_error(
        "File is too large: maximum supported size is 64 MiB.");
  }

  std::vector<uint8_t> data(static_cast<size_t>(size));
  file.seekg(0, std::ios::beg);
  if (!file.read(reinterpret_cast<char*>(data.data()), size)) {
    throw std::runtime_error("Failed to read file: " + path);
  }
  return data;
}

std::string Hex(uint64_t value, int width = 0) {
  std::ostringstream oss;
  oss << "0x" << std::hex << std::uppercase;
  if (width > 0) {
    oss << std::setw(width) << std::setfill('0');
  }
  oss << value;
  return oss.str();
}

std::string FormatTimestamp(uint32_t timestamp) {
  std::time_t raw = static_cast<std::time_t>(timestamp);
  std::tm utc_time{};
#if defined(_WIN32)
  if (gmtime_s(&utc_time, &raw) != 0) {
    return "n/a";
  }
#else
  if (gmtime_r(&raw, &utc_time) == nullptr) {
    return "n/a";
  }
#endif

  std::ostringstream oss;
  oss << std::put_time(&utc_time, "%Y-%m-%d %H:%M:%S UTC");
  return oss.str();
}

void PrintMetadata(const pe::PeMetadata& metadata) {
  const auto& file_header = metadata.file_header;
  const auto& optional_header = metadata.optional_header;

  std::cout << "File Header:\n";
  std::cout << "  Machine: " << Hex(file_header.machine, 4) << " ("
            << pe::MachineToString(file_header.machine) << ")\n";
  std::cout << "  Number of Sections: " << file_header.number_of_sections
            << "\n";
  std::cout << "  Time Date Stamp: " << Hex(file_header.time_date_stamp, 8)
            << " (" << FormatTimestamp(file_header.time_date_stamp) << ")\n";
  std::cout << "  Characteristics: " << Hex(file_header.characteristics, 4)
            << "\n\n";

  std::cout << "Optional Header:\n";
  std::cout << "  Magic: " << Hex(optional_header.magic, 4) << " ("
            << (optional_header.is_pe32_plus ? "PE32+" : "PE32") << ")\n";
  std::cout << "  Entry Point: "
            << Hex(optional_header.address_of_entry_point, 8) << "\n";
  std::cout << "  Image Base: "
            << Hex(optional_header.image_base,
                   optional_header.is_pe32_plus ? 16 : 8)
            << "\n";
  std::cout << "  Subsystem: " << Hex(optional_header.subsystem, 4) << " ("
            << pe::SubsystemToString(optional_header.subsystem) << ")\n\n";

  std::cout << "Sections:\n";
  if (metadata.sections.empty()) {
    std::cout << "  (none)\n";
    return;
  }

  std::cout << "  Index  Name      VirtSize    VirtAddr    RawSize     RawPtr\n";
  for (size_t i = 0; i < metadata.sections.size(); ++i) {
    const auto& section = metadata.sections[i];
    std::cout << "  " << std::setw(5) << i << "  " << std::left << std::setw(8)
              << section.name << std::right << "  " << std::setw(10)
              << Hex(section.virtual_size, 8) << "  " << std::setw(10)
              << Hex(section.virtual_address, 8) << "  " << std::setw(10)
              << Hex(section.size_of_raw_data, 8) << "  " << std::setw(10)
              << Hex(section.pointer_to_raw_data, 8) << "\n";
  }
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "Usage: tiny-pe-parser <path-to-pe>\n";
    return 1;
  }

  try {
    auto data = ReadFile(argv[1]);
    pe::PeParser parser(std::move(data));
    pe::PeMetadata metadata = parser.Parse();
    PrintMetadata(metadata);
  } catch (const std::exception& ex) {
    std::cerr << "Error: " << ex.what() << "\n";
    return 1;
  }

  return 0;
}
