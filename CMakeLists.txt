# SPDX-License-Identifier: MIT
# Copyright (c) 2020-2026 RVX Project Contributors

cmake_minimum_required(VERSION 3.28)

# Architecture
if(NOT DEFINED RVX_ARCH)
  if (DEFINED RVX_ENABLE_ZMMUL)
    set(RVX_ARCH "rv32i_zicsr_zmmul" CACHE STRING "RISC-V architecture to target")
    message(STATUS "Selected RISC-V architecture for RVX: ${RVX_ARCH}")
  else()
    set(RVX_ARCH "rv32i_zicsr" CACHE STRING "RISC-V architecture to target")
    message(STATUS "Selected RISC-V architecture for RVX: ${RVX_ARCH}")
  endif()
endif()

# Toolchain setup
if(NOT CMAKE_C_COMPILER)
  if(NOT DEFINED RISCV_TOOLCHAIN_PREFIX)
    set(RISCV_TOOLCHAIN_PREFIX "riscv32-unknown-elf-" CACHE STRING "Toolchain prefix for RISC-V cross compiler")
    message(STATUS "Using default RISCV_TOOLCHAIN_PREFIX: ${RISCV_TOOLCHAIN_PREFIX}")
  endif()
  set(CMAKE_C_COMPILER "${RISCV_TOOLCHAIN_PREFIX}gcc" CACHE FILEPATH "C compiler")
  set(CMAKE_ASM_COMPILER "${RISCV_TOOLCHAIN_PREFIX}gcc" CACHE FILEPATH "ASM compiler")
  set(CMAKE_OBJCOPY "${RISCV_TOOLCHAIN_PREFIX}objcopy" CACHE FILEPATH "objcopy tool")
  set(CMAKE_OBJDUMP "${RISCV_TOOLCHAIN_PREFIX}objdump" CACHE FILEPATH "objdump tool")
  set(CMAKE_SIZE "${RISCV_TOOLCHAIN_PREFIX}size" CACHE FILEPATH "size tool")

  # Prevent CMake from testing the compiler (important for cross-compilation)
  set(CMAKE_C_COMPILER_FORCED TRUE)
  set(CMAKE_ASM_COMPILER_FORCED TRUE)

  # Set system info
  set(CMAKE_SYSTEM_NAME Generic)
  set(CMAKE_SYSTEM_PROCESSOR riscv32)
endif()

# Tightly Coupled Memory Size
if(NOT DEFINED RVX_MEMORY_SIZE)
  set(RVX_MEMORY_SIZE "8192" CACHE STRING "Total RAM size in bytes")
  message(STATUS "Using default RVX_MEMORY_SIZE: ${RVX_MEMORY_SIZE} bytes")
endif()

# Stack Size
if(NOT DEFINED RVX_STACK_SIZE)
    set(RVX_STACK_SIZE "1024" CACHE STRING "Stack size in bytes")
    message(STATUS "Using default RVX_STACK_SIZE: ${RVX_STACK_SIZE} bytes")
endif()

# Heap Size
if(NOT DEFINED RVX_HEAP_SIZE)
    set(RVX_HEAP_SIZE "0" CACHE STRING "Heap size in bytes")
    message(STATUS "Using default RVX_HEAP_SIZE: ${RVX_HEAP_SIZE} bytes")
endif()

# Define INTERFACE library
add_library(rvx_hal INTERFACE)

# Include directories
target_include_directories(rvx_hal
  INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}/include
)

# Compiler options
target_compile_options(rvx_hal
  INTERFACE
    -Wall
    -Wextra
    -Wpedantic
    -mstrict-align
    -ffreestanding
    -fno-builtin
    -ffunction-sections
    -fdata-sections
    -march=${RVX_ARCH}
    -mabi=ilp32
    -mno-relax
)

# Linker options
target_link_options(rvx_hal
  INTERFACE
    -T${CMAKE_CURRENT_LIST_DIR}/linker/rvx.ld
    -Wl,--gc-sections
    -mstrict-align
    -march=${RVX_ARCH}
    -mabi=ilp32
    -Wl,--defsym=__memory_size=${RVX_MEMORY_SIZE}
    -Wl,--defsym=__stack_size=${RVX_STACK_SIZE}
    -Wl,--defsym=__heap_size=${RVX_HEAP_SIZE}
    $<$<BOOL:${RVX_BARE_METAL}>:-nostartfiles>
)

# Add compile definition if RVX_BARE_METAL is defined
if(DEFINED RVX_BARE_METAL)
  target_compile_definitions(rvx_hal INTERFACE RVX_BARE_METAL)
endif()

# Provide startup file to be compiled by consuming targets
target_sources(rvx_hal INTERFACE ${CMAKE_CURRENT_LIST_DIR}/startup/startup_rvx.S)

# Function to attach memory file generation to a target
function(rvx_generate_memory_init_file TARGET_NAME)
  add_custom_command(TARGET ${TARGET_NAME} POST_BUILD

    # Generate binary
    COMMAND ${CMAKE_OBJCOPY} -O binary $<TARGET_FILE:${TARGET_NAME}> $<TARGET_FILE_DIR:${TARGET_NAME}>/${TARGET_NAME}.bin

    # Generate Verilog hex file (memory init)
    COMMAND ${CMAKE_OBJCOPY} -O verilog --verilog-data-width=4 $<TARGET_FILE:${TARGET_NAME}> $<TARGET_FILE_DIR:${TARGET_NAME}>/${TARGET_NAME}.hex

    # Generate disassembly
    COMMAND ${CMAKE_OBJDUMP} -D $<TARGET_FILE:${TARGET_NAME}> > $<TARGET_FILE_DIR:${TARGET_NAME}>/${TARGET_NAME}.objdump

    # Print info
    COMMAND ${CMAKE_COMMAND} -E echo ""
    COMMAND ${CMAKE_COMMAND} -E echo "Memory init file:   $<TARGET_FILE_DIR:${TARGET_NAME}>/${TARGET_NAME}.hex"
    COMMAND ${CMAKE_COMMAND} -E echo "ELF binary:         $<TARGET_FILE_DIR:${TARGET_NAME}>/${TARGET_NAME}.bin"
    COMMAND ${CMAKE_COMMAND} -E echo "Disassembly:        $<TARGET_FILE_DIR:${TARGET_NAME}>/${TARGET_NAME}.objdump"
    COMMAND ${CMAKE_COMMAND} -E echo ""
    COMMAND ${CMAKE_COMMAND} -E echo "Memory usage report \\(total memory size: ${RVX_MEMORY_SIZE} bytes\\)"

    # Run size tool
    COMMAND ${TOOLCHAIN_PREFIX}size -G $<TARGET_FILE:${TARGET_NAME}>
    COMMAND ${CMAKE_COMMAND} -E echo ""

  )
  # Add generated files to clean
  set_property(TARGET ${TARGET_NAME} APPEND PROPERTY ADDITIONAL_CLEAN_FILES
    $<TARGET_FILE_DIR:${TARGET_NAME}>/${TARGET_NAME}.bin
    $<TARGET_FILE_DIR:${TARGET_NAME}>/${TARGET_NAME}.hex
    $<TARGET_FILE_DIR:${TARGET_NAME}>/${TARGET_NAME}.objdump

  )
endfunction()