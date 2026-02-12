# Tiny PE Parser

[![version](https://img.shields.io/github/v/tag/whode/tiny-pe-parser?label=version&sort=semver)](https://github.com/whode/tiny-pe-parser/tags)
[![Workflow Status](https://img.shields.io/github/actions/workflow/status/whode/tiny-pe-parser/ci.yml?branch=main)](https://github.com/whode/tiny-pe-parser/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/whode/tiny-pe-parser)](LICENSE)

A lightweight C++17 utility for analyzing Windows Portable Executable (PE) headers with no third-party libraries.
Focused on clear output and careful, bounds-checked parsing.

## Features

- **Std-lib only**: No external dependencies.
- **Safe parsing**: Strict bounds checks for all reads.
- **Architecture aware**: Supports PE32 (x86) and PE32+ (x64).
- **Resource bounded**: Rejects files larger than 64 MiB.
- **Cross-platform build**: CMake project for MSVC/GCC/Clang.

## Build

### Prerequisites
- C++17 compatible compiler
- CMake 3.15+

### Build Steps

```bash
# 1. Create a build directory
mkdir build
cd build

# 2. Generate build files
cmake ..

# 3. Compile
cmake --build . --config Release
```

The executable `tiny-pe-parser` (or `tiny-pe-parser.exe`) will be generated in the build directory.

## Usage

Pass the path to a Windows executable (`.exe`) or library (`.dll`) as an argument.
Input files larger than 64 MiB are rejected by design.

On Linux:
```bash
./tiny-pe-parser <path/to/file.exe>
```
On Windows:
```powershell
.\tiny-pe-parser.exe <path\to\file.exe>
```

## Example Output

Running the parser against a standard Windows executable:

```text
File Header:
  Machine: 0x8664 (x64)
  Number of Sections: 6
  Time Date Stamp: 0x69580D0E (2026-01-02 18:23:10 UTC)
  Characteristics: 0x0022

Optional Header:
  Magic: 0x020B (PE32+)
  Entry Point: 0x00006E9C
  Image Base: 0x0000000140000000
  Subsystem: 0x0003 (Windows CUI)

Sections:
  Index  Name      VirtSize    VirtAddr    RawSize     RawPtr
      0  .text     0x00006EF7  0x00001000  0x00007000  0x00000400
      1  .rdata    0x000044E0  0x00008000  0x00004600  0x00007400
      2  .data     0x00000A70  0x0000D000  0x00000600  0x0000BA00
      3  .pdata    0x00000738  0x0000E000  0x00000800  0x0000C000
      4  .rsrc     0x000001E0  0x0000F000  0x00000200  0x0000C800
      5  .reloc    0x000000C4  0x00010000  0x00000200  0x0000CA00
```

## Project Structure

- **src/**: Core implementation files.
  - `main.cpp`: Entry point and output formatting.
  - `pe_parser.cpp`: Implementation of binary stream parsing logic.
  - `pe_parser.h`: Data structures (DOS/NT headers, Section headers) and class definitions.
- **CMakeLists.txt**: Build configuration.

## License

This project is open-sourced software licensed under the [MIT license](LICENSE).
