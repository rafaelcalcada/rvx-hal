/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2020-2026 RVX Project Contributors */

OUTPUT_ARCH("riscv")
ENTRY(rvx_startup)

MEMORY
{
  BOOTLOADER_ROM (wx)   : ORIGIN = 0x00000000, LENGTH = __memory_size
}

SECTIONS
{

  __stack_size = DEFINED(__stack_size) ? __stack_size : 0;
  __heap_size = DEFINED(__heap_size) ? __heap_size : 0;

  .text :
  {
    *(SORT_NONE(.init))
    *(SORT_NONE(.fini))

    . = ALIGN(4);
    PROVIDE_HIDDEN (__preinit_array_start = .);
    *(.preinit_array*)
    PROVIDE_HIDDEN (__preinit_array_end = .);

    . = ALIGN(4);
    PROVIDE_HIDDEN (__init_array_start = .);
    *(SORT_BY_INIT_PRIORITY(.init_array.*) SORT_BY_INIT_PRIORITY(.ctors.*))
    *(.init_array .ctors)
    PROVIDE_HIDDEN (__init_array_end = .);

    . = ALIGN(4);
    *(.text*)
    *(.gnu.linkonce.t.*)

    . = ALIGN(4);
    *(.rodata*)

    . = ALIGN(4);
    *(.srodata*)
  } > BOOTLOADER_ROM

  .data :
  {
    *(.data*)
    *(.gnu.linkonce.d.*)

    . = ALIGN(8);
    __sdata_start = .;
    PROVIDE(__global_pointer$ = __sdata_start + 0x800);
    *(.sdata*)
    *(.gnu.linkonce.s.*)
    __sdata_end = .;
  } > BOOTLOADER_ROM

  .bss (NOLOAD) : ALIGN(4)
  {
    PROVIDE(__bss_start = .);
    *(.sbss*)
    *(.gnu.linkonce.sb.*)
    *(.bss*)
    *(.gnu.linkonce.b.*)
    *(COMMON)
    . = ALIGN(4);
    PROVIDE(__bss_end = .);
  } > BOOTLOADER_ROM

  /DISCARD/ :
  {
    *(.boot_header)
    *(.init.rvx_startup)
    *(.init.rvx_trap_vector)
    *(.text.rvx_trap_handler_*)
    *(.comment)
    *(.riscv.attributes)
  }

}

PROVIDE( __stack_limit              = ORIGIN(BOOTLOADER_ROM) + LENGTH(BOOTLOADER_ROM) - __stack_size);
PROVIDE( __stack_top                = ORIGIN(BOOTLOADER_ROM) + LENGTH(BOOTLOADER_ROM));

PROVIDE( _end = ALIGN(ADDR(.bss) + SIZEOF(.bss), 8));
PROVIDE( end  = _end);

PROVIDE( __program_size = _end - ORIGIN(BOOTLOADER_ROM));

PROVIDE( __heap_start = _end);
PROVIDE( __heap_end   = __heap_start + __heap_size);

ASSERT( __heap_end <= __stack_limit, "ERROR: Program won't fit in RVX bootloader ROM. Please increase memory size or reduce program, heap or stack sizes.");

PROVIDE( __freertos_irq_stack_top   = __stack_top);