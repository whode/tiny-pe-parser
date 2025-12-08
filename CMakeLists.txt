cmake_minimum_required(VERSION 3.15)

project(tiny-pe-parser LANGUAGES CXX)

add_executable(tiny-pe-parser
    src/main.cpp
    src/pe_parser.cpp
)

target_include_directories(tiny-pe-parser PRIVATE src)
target_compile_features(tiny-pe-parser PRIVATE cxx_std_17)

if(MSVC)
    target_compile_options(tiny-pe-parser PRIVATE /W4 /permissive-)
else()
    target_compile_options(tiny-pe-parser PRIVATE -Wall -Wextra -Wpedantic)
endif()
