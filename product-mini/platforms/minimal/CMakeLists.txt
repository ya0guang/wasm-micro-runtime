cmake_minimum_required (VERSION 2.8)

project(minimal)

set (WAMR_BUILD_PLATFORM "linux")

# Reset default linker flags
set (CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set (CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")

# Steal from linux-sgx platform CMake file
# Set WAMR_BUILD_TARGET
if (NOT DEFINED WAMR_BUILD_TARGET)
  if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    # Build as X86_64 by default in 64-bit platform
    set (WAMR_BUILD_TARGET "X86_64")
  else ()
    # Build as X86_32 by default in 32-bit platform
    set (WAMR_BUILD_TARGET "X86_32")
  endif ()
endif ()

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif ()

if (NOT DEFINED WAMR_BUILD_INTERP)
  # Enable Interpreter by default
  set (WAMR_BUILD_INTERP 1)
endif ()

if (NOT DEFINED WAMR_BUILD_AOT)
  # Enable AOT by default
  # Please install Intel SGX SDKv2.8 or later.
  set (WAMR_BUILD_AOT 1)
endif ()

if (NOT DEFINED WAMR_BUILD_JIT)
  # Disable JIT by default.
  set (WAMR_BUILD_JIT 0)
endif ()

if (NOT DEFINED WAMR_BUILD_LIBC_BUILTIN)
  # Enable libc builtin support by default
  # Changed to 0 here
  set (WAMR_BUILD_LIBC_BUILTIN 0)
endif ()

if (NOT DEFINED WAMR_BUILD_LIBC_WASI)
  # Enable libc wasi support by default
  set (WAMR_BUILD_LIBC_WASI 0)
endif ()

if (NOT DEFINED WAMR_BUILD_FAST_INTERP)
  # Enable fast interpreter
  set (WAMR_BUILD_FAST_INTERP 1)
endif ()

if (NOT DEFINED WAMR_BUILD_MULTI_MODULE)
  # Enable multiple modules
  set (WAMR_BUILD_MULTI_MODULE 0)
endif ()

if (NOT DEFINED WAMR_BUILD_MINI_LOADER)
  # Disable wasm mini loader by default
  set (WAMR_BUILD_MINI_LOADER 0)
endif ()

if (NOT DEFINED WAMR_BUILD_SIMD)
  # Enable SIMD by default
  set (WAMR_BUILD_SIMD 0)
endif ()

if (NOT DEFINED WAMR_BUILD_REF_TYPES)
  # Disable reference types by default
  set (WAMR_BUILD_REF_TYPES 0)
endif ()


set (WAMR_BUILD_LIB_PTHREAD 0)

set (WAMR_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../..)

include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)
add_library(vmlib ${WAMR_RUNTIME_LIB_SOURCE})

set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections -pie -fPIE")

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wformat -Wformat-security")

include (${SHARED_DIR}/utils/uncommon/shared_uncommon.cmake)

add_executable (minimal main.c ${UNCOMMON_SHARED_SOURCE})

# install (TARGETS minimal DESTINATION bin)

target_link_libraries (minimal vmlib ${LLVM_AVAILABLE_LIBS} ${UV_A_LIBS} -lm -ldl -lpthread)