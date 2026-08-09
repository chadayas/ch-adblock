cmake_minimum_required(VERSION 3.20)
project(adb LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()
add_compile_options(-Wall -Wextra -Wno-unused-parameter)

find_package(OpenSSL 3.0 REQUIRED)
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCRE2 REQUIRED IMPORTED_TARGET libpcre2-8)
pkg_check_modules(ZLIB  REQUIRED IMPORTED_TARGET zlib)

add_library(adbcore STATIC
  src/url.cpp
  src/parser.cpp
  src/engine.cpp
  src/cosmetic.cpp
  src/ca.cpp
  src/http.cpp
  src/proxy.cpp
)
target_include_directories(adbcore PUBLIC include)
target_link_libraries(adbcore
  PUBLIC  OpenSSL::SSL OpenSSL::Crypto Threads::Threads
  PRIVATE PkgConfig::PCRE2 PkgConfig::ZLIB)

add_executable(adb src/main.cpp)
target_link_libraries(adb PRIVATE adbcore)

enable_testing()
add_executable(adb_tests
  tests/test_main.cpp
  tests/test_url.cpp
  tests/test_parser.cpp
  tests/test_engine.cpp
  tests/test_cosmetic.cpp
  tests/test_http.cpp
  tests/test_ca.cpp
)
target_link_libraries(adb_tests PRIVATE adbcore)
add_test(NAME unit COMMAND adb_tests)
