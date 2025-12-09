#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace pe {

struct FileHeader {
  uint16_t machine = 0;
  uint16_t number_of_sections = 0;
  uint32_t time_date_stamp = 0;
  uint32_t pointer_to_symbol_table = 0;
  uint32_t number_of_symbols = 0;
  uint16_t size_of_optional_header = 0;
  uint16_t characteristics = 0;
};

struct OptionalHeader {
  bool is_pe32_plus = false;
  uint16_t magic = 0;
  uint32_t address_of_entry_point = 0;
  uint64_t image_base = 0;
  uint16_t subsystem = 0;
};

struct SectionHeader {
  std::string name;
  uint32_t virtual_size = 0;
  uint32_t virtual_address = 0;
  uint32_t size_of_raw_data = 0;
  uint32_t pointer_to_raw_data = 0;
};

struct PeMetadata {
  FileHeader file_header;
  OptionalHeader optional_header;
  std::vector<SectionHeader> sections;
};

class PeParser {
 public:
  explicit PeParser(std::vector<uint8_t> data);
  PeMetadata Parse() const;

 private:
  void EnsureBounds(size_t offset, size_t size) const;
  uint16_t ReadU16(size_t offset) const;
  uint32_t ReadU32(size_t offset) const;
  uint64_t ReadU64(size_t offset) const;
  std::string ReadString(size_t offset, size_t max_len) const;

  std::vector<uint8_t> data_;
};

std::string MachineToString(uint16_t machine);
std::string SubsystemToString(uint16_t subsystem);

}  // namespace pe
