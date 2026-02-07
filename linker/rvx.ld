/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2020-2026 RVX Project Contributors */

OUTPUT_ARCH("riscv")
ENTRY(rvx_startup)

MEMORY
{
  RVX_TCM (wx)   : ORIGIN = 0x00001010, LENGTH = __memory_size
}

SECTIONS
{

  __stack_size = DEFINED(__stack_size) ? __stack_size : 0;
  __heap_size = DEFINED(__heap_size) ? __heap_size : 0;

  /* Header for Flash SPI Boot Image */
  .boot_header :
  {
    LONG(0x52563332);               /* Magic number: "RV32" (0x52563332) */
    LONG(__boot_image_size);        /* Boot image size in bytes */
    LONG(rvx_startup);              /* Entry point address */
    LONG(0x52565834)                /* Magic number: "RVX4" */
  }

  .text : AT(SIZEOF(.boot_header))
  {
    *(.init.rvx_startup)
    *(.init.rvx_trap_vector)
    *(.text.rvx_trap_handler_*)
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
  } > RVX_TCM

  .data : AT(SIZEOF(.boot_header) + SIZEOF(.text)) ALIGN(4)
  {
    *(.data*)
    *(.gnu.linkonce.d.*)

    . = ALIGN(8);
    __sdata_start = .;
    PROVIDE(__global_pointer$ = __sdata_start + 0x800);
    *(.sdata*)
    *(.gnu.linkonce.s.*)
    __sdata_end = .;
  } > RVX_TCM

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
  } > RVX_TCM

  /DISCARD/ :
  {
    *(.comment)
    *(.riscv.attributes)
  }

}

PROVIDE( __stack_limit              = ORIGIN(RVX_TCM) + LENGTH(RVX_TCM) - __stack_size);
PROVIDE( __stack_top                = ORIGIN(RVX_TCM) + LENGTH(RVX_TCM));

PROVIDE( _end = ALIGN(ADDR(.bss) + SIZEOF(.bss), 8));
PROVIDE( end  = _end);

PROVIDE( __boot_image_size = SIZEOF(.text) + SIZEOF(.data) + SIZEOF(.boot_header));

PROVIDE( __heap_start = _end);
PROVIDE( __heap_end   = __heap_start + __heap_size);

ASSERT( __heap_end <= __stack_limit, "ERROR: Program won't fit in RVX tightly coupled memory. Please increase memory size or reduce program, heap or stack sizes.");

PROVIDE( __freertos_irq_stack_top   = __stack_top);