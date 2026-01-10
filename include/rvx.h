// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 RVX Project Contributors

#ifndef RVX_HAL_H
#define RVX_HAL_H

#if __riscv_xlen != 32
#error "Unsupported XLEN"
#endif

#include <stdbool.h> // for bool type
#include <stdint.h>  // for uint32_t, uint16_t, uint8_t types

/// Mark a function or variable as weak, allowing it to be overridden by other definitions.
#define RVX_WEAK __attribute__((weak))

/// Define a function without prologue/epilogue code.
#define RVX_NAKED __attribute__((naked))

/// Create an alias for a function.
#define RVX_ALIAS(weak_alias) __attribute__((alias(weak_alias)))

/// Mark a function as weak and define it as an alias for another.
/// This allows for default function implementations that can be overridden by a strong definition
/// elsewhere.
#define RVX_WEAK_ALIAS(weak_alias) __attribute__((weak, alias(weak_alias)))

/// Enforce 4-byte alignment on variables or structs.
#define RVX_ALIGNED __attribute__((aligned(4)))

/// Define a M-mode interrupt handler function.
#define RVX_IRQ_HANDLER_M(vector) __attribute__((interrupt("machine"))) void vector(void)

/// Set the specified bits in a Memory-Mapped IO register given a bitmask.
#define RVX_SET_MASK(register, bitmask) ((register) |= (bitmask))

/// Clear the specified bits in a Memory-Mapped IO register given a bitmask.
#define RVX_CLR_MASK(register, bitmask) ((register) &= ~(bitmask))

/// Set a specific bit in a Memory-Mapped IO register.
#define RVX_SET_BIT(register, bit_index) ((register) |= (1U << (bit_index)))

/// Clear a specific bit in a Memory-Mapped IO register.
#define RVX_CLR_BIT(register, bit_index) ((register) &= ~(1U << (bit_index)))

/// Read a specific bit from a Memory-Mapped IO register.
#define RVX_READ_BIT(register, bit_index) (((register) >> (bit_index)) & 1U)

/// @name U-mode Counter CSRs
/// @{
#define RVX_CYCLE_CSR 0xC00    ///< Address of the U-mode Cycle CSR (lower 32 bits).
#define RVX_TIME_CSR 0xC01     ///< Address of the U-mode Time CSR (lower 32 bits).
#define RVX_INSTRET_CSR 0xC02  ///< Address of the U-mode Instructions Retired CSR (lower 32 bits).
#define RVX_CYCLEH_CSR 0xC80   ///< Address of the U-mode Cycle CSR (upper 32 bits).
#define RVX_TIMEH_CSR 0xC81    ///< Address of the U-mode Time CSR (upper 32 bits).
#define RVX_INSTRETH_CSR 0xC82 ///< Address of the U-mode Instructions Retired CSR (upper 32 bits).
/// @}

/// @name M-mode Information CSRs
/// @{
#define RVX_MARCHID_CSR 0xF12 ///< Address of the M-mode Architecture ID CSR.
#define RVX_MIMPID_CSR 0xF13  ///< Address of the M-mode Implementation ID CSR.
/// @}

/// @name M-mode Trap Setup CSRs
/// @{
#define RVX_MSTATUS_CSR 0x300  ///< Address of the M-mode Status CSR (lower 32 bits).
#define RVX_MISA_CSR 0x301     ///< Address of the M-mode ISA CSR.
#define RVX_MIE_CSR 0x304      ///< Address of the M-mode Interrupt Enable CSR.
#define RVX_MTVEC_CSR 0x305    ///< Address of the M-mode Trap-Vector Base Address CSR.
#define RVX_MSTATUSH_CSR 0x310 ///< Address of the M-mode Status CSR (upper 32 bits).
/// @}

/// @name M-mode Trap Handling CSRs
/// @{
#define RVX_MSCRATCH_CSR 0x340 ///< Address of the M-mode Scratch CSR.
#define RVX_MEPC_CSR 0x341     ///< Address of the M-mode Exception Program Counter CSR.
#define RVX_MCAUSE_CSR 0x342   ///< Address of the M-mode Trap Cause CSR.
#define RVX_MTVAL_CSR 0x343    ///< Address of the M-mode Trap Value CSR.
#define RVX_MIP_CSR 0x344      ///< Address of the M-mode Interrupt Pending CSR.
/// @}

/// @name M-mode Counter CSRs
/// @{
#define RVX_MCYCLE_CSR 0xB00    ///< Address of the M-mode Cycle CSR (lower 32 bits).
#define RVX_MINSTRET_CSR 0xB02  ///< Address of the M-mode Instructions Retired CSR (lower 32 bits).
#define RVX_MCYCLEH_CSR 0xB80   ///< Address of the M-mode Cycle CSR (upper 32 bits).
#define RVX_MINSTRETH_CSR 0xB82 ///< Address of the M-mode Instructions Retired CSR (upper 32 bits).
/// @}

/// @name Bit masks for MSTATUS register fields.
/// @{
#define RVX_MSTATUS_MIE_MASK (1U << 3U)  ///< Mask for the MIE bit in MSTATUS.
#define RVX_MSTATUS_MPIE_MASK (1U << 7U) ///< Mask for the MPIE bit in MSTATUS.
/// @}

/// @name Bit masks for MTVEC register fields.
/// @{
#define RVX_MTVEC_MODE_MASK 0x00000003U ///< Mask for the `mode` field in MTVEC.
#define RVX_MTVEC_BASE_MASK 0xFFFFFFFCU ///< Mask for the `base` field in MTVEC.
/// @}

/// @name Bit masks for MIE and MIP interrupt enable/pending bits.
/// @{
#define RVX_IRQ_MSI_MASK (1U << 3U)              ///< Mask for the MSI enable/pending bit.
#define RVX_IRQ_MTI_MASK (1U << 7U)              ///< Mask for the MTI enable/pending bit.
#define RVX_IRQ_MEI_MASK (1U << 11U)             ///< Mask for the MEI enable/pending bit.
#define RVX_IRQ_FAST_MASK(n) (1U << (16U + (n))) ///< Mask for the Fast IRQ `n` enable/pending bit.
/// @}

/// @brief Standard RISC-V trap cause codes for the MCAUSE CSR.
typedef enum RvxTrapCauseCode
{
  // Exception codes
  RVX_TRAP_CAUSE_INSTRUCTION_ADDRESS_MISALIGNED = 0U, ///< Trap cause: Instruction address misaligned.
  RVX_TRAP_CAUSE_INSTRUCTION_ACCESS_FAULT = 1U,       ///< Trap cause: Instruction access fault.
  RVX_TRAP_CAUSE_ILLEGAL_INSTRUCTION = 2U,            ///< Trap cause: Illegal instruction.
  RVX_TRAP_CAUSE_BREAKPOINT = 3U,                     ///< Trap cause: Breakpoint exception.
  RVX_TRAP_CAUSE_LOAD_ADDRESS_MISALIGNED = 4U,        ///< Trap cause: Load address misaligned.
  RVX_TRAP_CAUSE_LOAD_ACCESS_FAULT = 5U,              ///< Trap cause: Load access fault.
  RVX_TRAP_CAUSE_STORE_AMO_ADDRESS_MISALIGNED = 6U,   ///< Trap cause: Store/AMO address misaligned.
  RVX_TRAP_CAUSE_STORE_AMO_ACCESS_FAULT = 7U,         ///< Trap cause: Store/AMO access fault.
  RVX_TRAP_CAUSE_ENVIRONMENT_CALL_FROM_U_MODE = 8U,   ///< Trap cause: Environment call from U-mode.
  RVX_TRAP_CAUSE_ENVIRONMENT_CALL_FROM_S_MODE = 9U,   ///< Trap cause: Environment call from S-mode.
  RVX_TRAP_CAUSE_ENVIRONMENT_CALL_FROM_M_MODE = 11U,  ///< Trap cause: Environment call from M-mode.
  RVX_TRAP_CAUSE_INSTRUCTION_PAGE_FAULT = 12U,        ///< Trap cause: Instruction page fault.
  RVX_TRAP_CAUSE_LOAD_PAGE_FAULT = 13U,               ///< Trap cause: Load page fault.
  RVX_TRAP_CAUSE_STORE_AMO_PAGE_FAULT = 15U,          ///< Trap cause: Store/AMO page fault.

  // Interrupt codes (MSB set)
  RVX_TRAP_CAUSE_MSI = (int)((1U << 31) | 3U),      ///< Trap cause: M-mode Software Interrupt (MSI).
  RVX_TRAP_CAUSE_MTI = (int)((1U << 31) | 11U),     ///< Trap cause: M-mode External Interrupt (MEI).
  RVX_TRAP_CAUSE_FAST_0 = (int)((1U << 31) | 16U),  ///< Trap cause: Fast-Interrupt 0
  RVX_TRAP_CAUSE_FAST_1 = (int)((1U << 31) | 17U),  ///< Trap cause: Fast-Interrupt 1
  RVX_TRAP_CAUSE_FAST_2 = (int)((1U << 31) | 18U),  ///< Trap cause: Fast-Interrupt 2
  RVX_TRAP_CAUSE_FAST_3 = (int)((1U << 31) | 19U),  ///< Trap cause: Fast-Interrupt 3
  RVX_TRAP_CAUSE_FAST_4 = (int)((1U << 31) | 20U),  ///< Trap cause: Fast-Interrupt 4
  RVX_TRAP_CAUSE_FAST_5 = (int)((1U << 31) | 21U),  ///< Trap cause: Fast-Interrupt 5
  RVX_TRAP_CAUSE_FAST_6 = (int)((1U << 31) | 22U),  ///< Trap cause: Fast-Interrupt 6
  RVX_TRAP_CAUSE_FAST_7 = (int)((1U << 31) | 23U),  ///< Trap cause: Fast-Interrupt 7
  RVX_TRAP_CAUSE_FAST_8 = (int)((1U << 31) | 24U),  ///< Trap cause: Fast-Interrupt 8
  RVX_TRAP_CAUSE_FAST_9 = (int)((1U << 31) | 25U),  ///< Trap cause: Fast-Interrupt 9
  RVX_TRAP_CAUSE_FAST_10 = (int)((1U << 31) | 26U), ///< Trap cause: Fast-Interrupt 10
  RVX_TRAP_CAUSE_FAST_11 = (int)((1U << 31) | 27U), ///< Trap cause: Fast-Interrupt 11
  RVX_TRAP_CAUSE_FAST_12 = (int)((1U << 31) | 28U), ///< Trap cause: Fast-Interrupt 12
  RVX_TRAP_CAUSE_FAST_13 = (int)((1U << 31) | 29U), ///< Trap cause: Fast-Interrupt 13
  RVX_TRAP_CAUSE_FAST_14 = (int)((1U << 31) | 30U), ///< Trap cause: Fast-Interrupt 14
  RVX_TRAP_CAUSE_FAST_15 = (int)((1U << 31) | 31U)  ///< Trap cause: Fast-Interrupt 15
} RvxTrapCauseCode;

/// The direction of a GPIO pin.
typedef enum RvxGpioPinDirection
{
  RVX_GPIO_INPUT = 0, ///< Input direction.
  RVX_GPIO_OUTPUT = 1 ///< Output direction.
} RvxGpioPinDirection;

/// The SPI mode configuration.
typedef enum RvxSpiMode
{
  RVX_SPI_MODE_0 = 0, ///< SPI Mode 0 (CPOL 0 / CPHA 0).
  RVX_SPI_MODE_1 = 1, ///< SPI Mode 1 (CPOL 0 / CPHA 1).
  RVX_SPI_MODE_2 = 2, ///< SPI Mode 2 (CPOL 1 / CPHA 0).
  RVX_SPI_MODE_3 = 3  ///< SPI Mode 3 (CPOL 1 / CPHA 1).
} RvxSpiMode;

/// Provide access to GPIO registers.
typedef struct RVX_ALIGNED RvxGpio
{
  volatile uint32_t RVX_GPIO_READ_REG;          ///< RVX GPIO Read Register.
  volatile uint32_t RVX_GPIO_OUTPUT_ENABLE_REG; ///< RVX GPIO Output Enable Register.
  volatile uint32_t RVX_GPIO_OUTPUT_REG;        ///< RVX GPIO Output Register.
  volatile uint32_t RVX_GPIO_CLEAR_REG;         ///< RVX GPIO Clear Register.
  volatile uint32_t RVX_GPIO_SET_REG;           ///< RVX GPIO Set Register.
} RvxGpio;

/// Provide access to SPI Manager registers.
typedef struct RVX_ALIGNED RvxSpiManager
{
  volatile uint32_t RVX_SPI_MODE;        ///< RVX SPI Mode Register.
  volatile uint32_t RVX_SPI_CHIP_SELECT; ///< RVX SPI Chip Select register.
  volatile uint32_t RVX_SPI_DIVIDER;     ///< RVX SPI Clock Divider Register.
  volatile uint32_t RVX_SPI_WRITE;       ///< RVX SPI Write Register.
  volatile uint32_t RVX_SPI_READ;        ///< RVX SPI Read Register.
  volatile uint32_t RVX_SPI_STATUS;      ///< RVX SPI Status Register.
} RvxSpiManager;

// Provide access to RVX Timer registers.
typedef struct RVX_ALIGNED RvxTimer
{
  volatile uint32_t RVX_TIMER_COUNTER_ENABLE; ///< RVX Timer Counter Enable Register.
  volatile uint32_t RVX_TIMER_COUNTERL;       ///< Lower 32-bits of the RVX Timer Counter Register.
  volatile uint32_t RVX_TIMER_COUNTERH;       ///< Upper 32-bits of the RVX Timer Counter Register.
  volatile uint32_t RVX_TIMER_COMPAREL;       ///< Lower 32-bits of the RVX Timer Compare Register.
  volatile uint32_t RVX_TIMER_COMPAREH;       ///< Upper 32-bits of the RVX Timer Compare Register.
} RvxTimer;

/// Provide access to UART registers.
typedef struct RVX_ALIGNED RvxUart
{
  volatile uint32_t RVX_UART_WRITE_REG;  ///< RVX UART Write Register.
  volatile uint32_t RVX_UART_READ_REG;   ///< RVX UART Read Register.
  volatile uint32_t RVX_UART_STATUS_REG; ///< RVX UART Status Register.
  volatile uint32_t RVX_UART_BAUD_REG;   ///< RVX UART Baud Rate Configuration Register.
} RvxUart;

/**
 * @brief Read the value of a Control and Status Register (CSR).
 *
 * This macro reads the 32-bit value from the CSR specified by `csr_address` and
 * stores it in `csr_read_value`.
 *
 * Example usage:
 * ```c
 * // Read MSTATUS
 * uint32_t mstatus_value;
 * RVX_CSR_READ(RVX_MSTATUS_CSR, mstatus_value);
 * ```
 *
 * @param csr_address The address of the CSR to read.
 * @param csr_read_value `uint32_t` variable to store the value read from the specified CSR.
 */
#define RVX_CSR_READ(csr_address, csr_read_value) asm volatile("csrr %0, %1" : "=r"(csr_read_value) : "i"(csr_address));

/**
 * @brief Write a value to a Control and Status Register (CSR).
 *
 * This macro writes the 32-bit `value` to the CSR specified by `csr_address`.
 *
 * Example usage:
 * ```c
 * // Write 0 to MTVEC
 * RVX_CSR_WRITE(RVX_MTVEC_CSR, 0);
 * ```
 *
 * @param csr_address The address of the CSR to write.
 * @param value `uint32_t` value to write to the specified CSR.
 */
#define RVX_CSR_WRITE(csr_address, value) asm volatile("csrw %0, %1" : : "i"(csr_address), "r"(value))

/**
 * @brief Read the value of a Control and Status Register (CSR) and write a new value, atomically.
 *
 * This macro performs an atomic read-write operation on the CSR specified by `csr_address`. The
 * old value of the CSR is stored in `csr_old_value`, and then `csr_new_value` is written to the CSR.
 *
 * Atomicity is guaranteed, meaning no other operations can interleave between the read and write.
 *
 * Example usage:
 * ```c
 * // Atomically read MSTATUS value and then replace it with 0x00000004
 * uint32_t csr_old_value;
 * RVX_CSR_READ_WRITE(RVX_MSTATUS_CSR, csr_old_value, 0x00000004);
 * ```
 *
 * @param csr_address The address of the CSR to read/write.
 * @param csr_old_value `uint32_t` variable to store the previous value of the specified CSR.
 * @param csr_new_value `uint32_t` value to write to the specified CSR.
 */
#define RVX_CSR_READ_WRITE(csr_address, csr_old_value, csr_new_value)                                                  \
  asm volatile("csrrw %0, %1, %2" : "=r"(csr_old_value) : "i"(csr_address), "r"(csr_new_value));

/**
 * @brief Set specific bits in a Control and Status Register (CSR).
 *
 * This macro sets to 1 the bits of the CSR specified by `csr_address` that are set to 1 in
 * `bit_mask`. All other bits remain unchanged.
 *
 * Example usage:
 * ```c
 * // Set MIE bit in MSTATUS
 * RVX_CSR_SET(RVX_MSTATUS_CSR, 0x8);
 * ```
 *
 * @param csr_address The address of the CSR to modify.
 * @param bit_mask `uint32_t` bit mask indicating which bits should be set.
 */
#define RVX_CSR_SET(csr_address, bit_mask) asm volatile("csrrs zero, %0, %1" : : "i"(csr_address), "r"(bit_mask))

/**
 * @brief Clear specific bits in a Control and Status Register (CSR).
 *
 * This macro sets to 0 the bits of the CSR specified by `csr_address` that are set to 1 in
 * `bit_mask`. All other bits remain unchanged.
 *
 * Example usage:
 * ```c
 * // Clear MIE bit in MSTATUS
 * RVX_CSR_CLEAR(RVX_MSTATUS_CSR, 0x8);
 * ```
 *
 * @param csr_address The address of the CSR to modify.
 * @param bit_mask `uint32_t` bit mask indicating which bits should be cleared.
 */
#define RVX_CSR_CLEAR(csr_address, bit_mask) asm volatile("csrrc zero, %0, %1" : : "i"(csr_address), "r"(bit_mask))

/**
 * @brief Read a Control and Status Register (CSR) and set specific bits, atomically.
 *
 * This macro performs an atomic read-write operation on the CSR specified by `csr_address`. The
 * old value of the CSR is returned, and then the bits specified in `bit_mask` are set to 1. All
 * other bits remain unchanged.
 *
 * Atomicity is guaranteed, meaning no other operations can interleave between the read and set.
 *
 * Example usage:
 * ```c
 * // Atomically read MSTATUS and then set its MIE bit
 * uint32_t csr_old_value;
 * RVX_CSR_READ_SET(RVX_MSTATUS_CSR, csr_old_value, 0x8);
 * ```
 *
 * @param csr_address The address of the CSR to read-and-set.
 * @param csr_old_value `uint32_t` variable to store the previous value of the specified CSR.
 * @param bit_mask `uint32_t` bit mask indicating which bits should be set.
 */
#define RVX_CSR_READ_SET(csr_address, csr_old_value, bit_mask)                                                         \
  asm volatile("csrrs %0, %1, %2" : "=r"(csr_old_value) : "i"(csr_address), "r"(bit_mask));

/**
 * @brief Read a Control and Status Register (CSR) and clear specific bits, atomically.
 *
 * This macro performs an atomic read-write operation on the CSR specified by `csr_address`. The
 * old value of the CSR is returned, and then the bits specified in `bit_mask` are cleared (set
 * to 0). All other bits remain unchanged.
 *
 * Atomicity is guaranteed, meaning no other operations can interleave between the read and clear.
 *
 * Example usage:
 * ```c
 * // Atomically read MSTATUS and then clear its MIE bit
 * uint32_t csr_old_value;
 * RVX_CSR_READ_CLEAR(RVX_MSTATUS_CSR, csr_old_value, 0x8);
 * ```
 *
 * @param csr_address The address of the CSR to read/clear.
 * @param csr_old_value `uint32_t` variable to store the previous value of the specified CSR.
 * @param bit_mask `uint32_t` bit mask indicating which bits should be cleared.
 */
#define RVX_CSR_READ_CLEAR(csr_address, csr_old_value, bit_mask)                                                       \
  asm volatile("csrrc %0, %1, %2" : "=r"(csr_old_value) : "i"(csr_address), "r"(bit_mask));

/**
 * @brief Enable specific machine-level interrupts by setting bits in the MIE CSR.
 *
 * This function sets the bits specified in `bit_mask` in the MIE CSR, enabling those interrupt
 * sources. Previously enabled interrupts remain unaffected.
 *
 * @note An interrupt is only effectively enabled if the global MIE bit in MSTATUS is also set.
 *
 * Example usage:
 * ```c
 * // Enable Machine Timer and Machine External interrupts
 * rvx_irq_enable(RVX_IRQ_MTI_MASK | RVX_IRQ_MEI_MASK);
 *
 * // Enable RVX Fast Interrupt 2
 * rvx_irq_enable(RVX_IRQ_FAST_MASK(2));
 *
 * // Globally enable interrupts to make the above effective
 * rvx_irq_enable_global();
 * ```
 *
 * @param bit_mask Bitmask of interrupts to enable in the MIE CSR.
 */
static inline void rvx_irq_enable(uint32_t bit_mask)
{
  RVX_CSR_SET(RVX_MIE_CSR, bit_mask);
}

/**
 * @brief Globally enable machine-level interrupts by setting the MIE bit in MSTATUS.
 *
 * This function sets the global Machine Interrupt Enable (MIE) bit in the Machine Status
 * (MSTATUS) CSR.
 *
 * @note Interrupts will only trigger traps if they are also enabled in the MIE CSR.
 *
 * Example usage:
 * ```c
 * // Globally enable interrupts
 * rvx_irq_enable_global();
 * ```
 */
static inline void rvx_irq_enable_global(void)
{
  RVX_CSR_SET(RVX_MSTATUS_CSR, RVX_MSTATUS_MIE_MASK);
}

/**
 * @brief Disable specific machine-level interrupts by clearing bits in the MIE CSR.
 *
 * This function clears the bits specified in `bit_mask` in the MIE CSR. The selected
 * interrupts will no longer trigger traps, even if the global MIE bit in MSTATUS is set.
 *
 * Example usage:
 * ```c
 * // Disable Machine Timer and Machine External interrupts
 * rvx_irq_disable(RVX_IRQ_MTI_MASK | RVX_IRQ_MEI_MASK);
 *
 * // Disable RVX Fast Interrupt 2
 * rvx_irq_disable(RVX_IRQ_FAST_MASK(2));
 * ```
 *
 * @param bit_mask Bitmask of interrupts to disable in the MIE CSR.
 */
static inline void rvx_irq_disable(uint32_t bit_mask)
{
  RVX_CSR_CLEAR(RVX_MIE_CSR, bit_mask);
}

/**
 * @brief Globally disable all machine-level interrupts by clearing the MIE bit in MSTATUS.
 *
 * This function clears the global Machine Interrupt Enable (MIE) bit in the Machine Status
 * (MSTATUS) CSR. Individual interrupt enable bits in the MIE CSR remain unchanged, but
 * no interrupts will trigger traps while the global MIE bit is cleared.
 *
 * Example usage:
 * ```c
 * // Globally disable all interrupts
 * rvx_irq_disable_global();
 * ```
 */
static inline void rvx_irq_disable_global(void)
{
  RVX_CSR_CLEAR(RVX_MSTATUS_CSR, RVX_MSTATUS_MIE_MASK);
}

/**
 * @brief Enable vectored mode for machine-level interrupts.
 *
 * This function sets the `mode` field of the MTVEC CSR to 1, enabling vectored interrupt handling.
 * In vectored mode, the trap vector address is calculated as defined by RISC-V Privileged specs.
 *
 * Example usage:
 * ```c
 * // Enables handling of interrupt requests in vectored mode
 * rvx_irq_enable_vectored_mode();
 * ```
 */
static inline void rvx_irq_enable_vectored_mode(void)
{
  uint32_t base;
  RVX_CSR_READ(RVX_MTVEC_CSR, base);
  base = base & RVX_MTVEC_BASE_MASK;
  RVX_CSR_WRITE(RVX_MTVEC_CSR, base | 1);
}

/**
 * @brief Enable direct mode for machine-level interrupts.
 *
 * This function clears the `mode` field of the MTVEC CSR, enabling direct interrupt handling. In
 * direct mode, all traps jump to the base address specified in MTVEC.
 *
 * Example usage:
 * ```c
 * // Enables handling of interrupt requests in direct mode
 * rvx_irq_enable_direct_mode();
 * ```
 */
static inline void rvx_irq_enable_direct_mode(void)
{
  RVX_CSR_CLEAR(RVX_MTVEC_CSR, RVX_MTVEC_MODE_MASK);
}

/**
 * @brief Configure the direction of the GPIO pin specified by `pin_index`.
 *
 * Valid values for `direction` are `RVX_GPIO_INPUT` or `RVX_GPIO_OUTPUT`. If `direction` is invalid
 * or if `pin_index` refers to a non-existent pin (beyond the number of implemented GPIO pins), no
 * action is taken and no error is reported.
 *
 * Example usage:
 * ```c
 * // Assume GPIO is mapped at address 0x80002000.
 * RvxGpio *gpio_address = (RvxGpio *)0x80002000;
 *
 * // Configure pin 0 as output and pin 1 as input.
 * rvx_gpio_pin_configure(gpio_address, 0, RVX_GPIO_OUTPUT);
 * rvx_gpio_pin_configure(gpio_address, 1, RVX_GPIO_INPUT);
 * ```
 *
 * @param gpio_address Pointer to the base address of the GPIO peripheral.
 * @param pin_index Index of the GPIO pin to configure as input or output.
 * @param direction Desired pin direction as `RvxGpioPinDirection` (`RVX_GPIO_INPUT` or
 * `RVX_GPIO_OUTPUT`).
 */
static inline void rvx_gpio_pin_configure(RvxGpio *gpio_address, const uint8_t pin_index, RvxGpioPinDirection direction)
{
  if (direction == RVX_GPIO_OUTPUT)
  {
    RVX_SET_BIT(gpio_address->RVX_GPIO_OUTPUT_ENABLE_REG, pin_index);
  }
  else if (direction == RVX_GPIO_INPUT)
  {
    RVX_CLR_BIT(gpio_address->RVX_GPIO_OUTPUT_ENABLE_REG, pin_index);
  }
}

/**
 * @brief Read the logic value of a GPIO pin.
 *
 * Returns the current logic value of the pin specified by `pin_index`. Both input and output pins
 * can be read.
 *
 * If `pin_index` refers to a non-existent pin (beyond the number of implemented GPIO pins), the
 * return value is `false`.
 *
 * Example usage:
 * ```c
 * // Assume GPIO is mapped at address 0x80002000.
 * RvxGpio *gpio_address = (RvxGpio *)0x80002000;
 *
 * // Configure pin 0 as input.
 * rvx_gpio_pin_configure(gpio_address, 0, RVX_GPIO_INPUT);
 *
 * // Read the state of pin 0.
 * bool pin0_value = rvx_gpio_pin_read(gpio_address, 0);
 * ```
 *
 * @param gpio_address Pointer to the base address of the GPIO peripheral.
 * @param pin_index Index of the GPIO pin to read.
 * @return The pin logic state as `bool` (`true` or `false`).
 */
static inline bool rvx_gpio_pin_read(RvxGpio *gpio_address, const uint8_t pin_index)
{
  return RVX_READ_BIT(gpio_address->RVX_GPIO_READ_REG, pin_index);
}

/**
 * @brief Write a logic value to a GPIO output pin.
 *
 * If `value` is `true`, the pin is set to logic 1; if `false`, the pin is cleared to logic 0.
 * Writing to input pins updates their output latch but does not affect the pin state until the pin
 * is reconfigured as output.
 *
 * If `pin_index` refers to a non-existent pin (beyond the number of implemented GPIO pins), the
 * operation is ignored without error.
 *
 * Example usage:
 * ```c
 * // Assume GPIO is mapped at address 0x80002000.
 * RvxGpio *gpio_address = (RvxGpio *)0x80002000;
 *
 * // Configure pins 0 and 1 as outputs.
 * rvx_gpio_pin_configure(gpio_address, 0, RVX_GPIO_OUTPUT);
 * rvx_gpio_pin_configure(gpio_address, 1, RVX_GPIO_OUTPUT);
 *
 * // Write logic 0 to pin 0 and 1 to pin 1.
 * rvx_gpio_pin_write(gpio_address, 0, false);
 * rvx_gpio_pin_write(gpio_address, 1, true);
 * ```
 *
 * @param gpio_address Pointer to the base address of the GPIO peripheral.
 * @param pin_index Index of the GPIO pin to write.
 * @param value Desired logic value (`true` for logic 1 or `false` for logic 0).
 */
static inline void rvx_gpio_pin_write(RvxGpio *gpio_address, const uint8_t pin_index, bool value)
{
  if (value)
    gpio_address->RVX_GPIO_SET_REG = 0x1U << pin_index;
  else
    gpio_address->RVX_GPIO_CLEAR_REG = 0x1U << pin_index;
}

/**
 * @brief Clear a GPIO output pin to logic 0.
 *
 * Drives the pin specified by `pin_index` to logic 0 if it is configured as an output. If the pin
 * is configured as an input, the output latch is updated without changing the pin state. The new
 * value takes effect when the pin is later configured as an output.
 *
 * If `pin_index` refers to a non-existent pin (beyond the number of implemented GPIO pins), the
 * operation is ignored without error.
 *
 * Example usage:
 * ```c
 * // Assume GPIO is mapped at address 0x80002000.
 * RvxGpio *gpio_address = (RvxGpio *)0x80002000;
 *
 * // Configure pin 0 as output.
 * rvx_gpio_pin_configure(gpio_address, 0, RVX_GPIO_OUTPUT);
 *
 * // Write logic 0 to pin 0.
 * rvx_gpio_pin_clear(gpio_address, 0);
 * ```
 *
 * @param gpio_address Pointer to the base address of the GPIO peripheral.
 * @param pin_index Index of the GPIO pin to clear.
 */
static inline void rvx_gpio_pin_clear(RvxGpio *gpio_address, const uint8_t pin_index)
{
  gpio_address->RVX_GPIO_CLEAR_REG = 0x1U << pin_index;
}

/**
 * @brief Set a GPIO output pin to logic 1.
 *
 * Drives the pin specified by `pin_index` to logic 1 if it is configured as an output. If the pin
 * is configured as an input, the output latch is updated without changing the pin state. The new
 * value takes effect when the pin is later configured as an output.
 *
 * If `pin_index` refers to a non-existent pin (beyond the number of implemented GPIO pins), the
 * operation is ignored without error.
 *
 * Example usage:
 * ```c
 * // Assume GPIO is mapped at address 0x80002000.
 * RvxGpio *gpio_address = (RvxGpio *)0x80002000;
 *
 * // Configure pin 0 as output.
 * rvx_gpio_pin_configure(gpio_address, 0, RVX_GPIO_OUTPUT);
 *
 * // Write logic 1 to pin 0.
 * rvx_gpio_pin_set(gpio_address, 0);
 * ```
 *
 * @param gpio_address Pointer to the base address of the GPIO peripheral.
 * @param pin_index Index of the GPIO pin to set.
 */
static inline void rvx_gpio_pin_set(RvxGpio *gpio_address, const uint8_t pin_index)
{
  gpio_address->RVX_GPIO_SET_REG = 0x1U << pin_index;
}

/**
 * @brief Configure the direction of all GPIO pins simultaneously.
 *
 * Sets the direction of all GPIO pins according to `direction_mask`. Each bit set to 1 configures
 * the corresponding pin as an output, and each bit set to 0 configures it as an input. Pins are
 * updated simultaneously in a single register write.
 *
 * Only the lower bits of `direction_mask` corresponding to implemented GPIO pins are used. Any
 * upper bits beyond the number of available pins are ignored by the hardware.
 *
 * Example usage:
 * ```c
 * // This example assumes the GPIO peripheral provides 4 pins and
 * // is mapped at address 0x80002000.
 * RvxGpio *gpio_address = (RvxGpio *)0x80002000;
 *
 * // Configure pins 1 and 3 as outputs, pins 0 and 2 as inputs simultaneously.
 * rvx_gpio_configure_all(gpio_address, 0b1010);
 * ```
 *
 * @note To set the direction of a single pin, use `rvx_gpio_pin_configure()` instead.
 *
 * @param gpio_address Pointer to the base address of the GPIO peripheral.
 * @param direction_mask 32-bit bitmask specifying the direction of each pin:
 *                       0 = input, 1 = output.
 */
static inline void rvx_gpio_configure_all(RvxGpio *gpio_address, const uint32_t direction_mask)
{
  gpio_address->RVX_GPIO_OUTPUT_ENABLE_REG = direction_mask;
}

/**
 * @brief Read the logic values of all GPIO pins simultaneously.
 *
 * Returns the current logic levels of all pins in a single 32-bit value. Only the lower bits
 * corresponding to implemented pins are valid; higher bits are zero-padded.
 *
 * Example usage:
 * ```c
 * // This example assumes the GPIO peripheral provides 4 pins and
 * // is mapped at address 0x80002000.
 * RvxGpio *gpio_address = (RvxGpio *)0x80002000;
 *
 * // Read all pins simultaneously.
 * uint32_t pin_values = rvx_gpio_read_all(gpio_address);
 *
 * // Extract individual pin values.
 * bool pin0_value = (pin_values >> 0) & 1;
 * bool pin1_value = (pin_values >> 1) & 1;
 * bool pin2_value = (pin_values >> 2) & 1;
 * bool pin3_value = (pin_values >> 3) & 1;
 * ```
 *
 * @param gpio_address Pointer to the base address of the GPIO peripheral.
 * @return 32-bit value representing the logic states of all GPIO pins.
 *         Only lower bits corresponding to implemented pins are valid; higher bits are zero-padded.
 */
static inline uint32_t rvx_gpio_read_all(RvxGpio *gpio_address)
{
  return gpio_address->RVX_GPIO_READ_REG;
}

/**
 * @brief Write logic values to all GPIO output pins simultaneously.
 *
 * Each bit set to 1 in `value_mask` sets the corresponding GPIO output pin to logic 1, and each
 * bit set to 0 sets the corresponding pin to logic 0, in a single operation. Writing to pins
 * configured as inputs updates their output latch but does not affect the actual pin state until
 * the pin is reconfigured as an output.
 *
 * Bits corresponding to non-existent pins (beyond the number of implemented GPIO pins) are ignored
 * without error.
 *
 * Example usage:
 * ```c
 * // This example assumes the GPIO peripheral provides 4 pins and
 * // is mapped at address 0x80002000.
 * RvxGpio *gpio_address = (RvxGpio *)0x80002000;
 *
 * // Configure pin directions.
 * // Pin 0 = input, pin 1 = output, pin 2 = output, pin 3 = output
 * rvx_gpio_configure_all(gpio_address, 0b1110);
 *
 * // Write values to pins 1, 2, and 3 simultaneously.
 * // Pin 1 = 0, Pin 2 = 1, Pin 3 = 0.
 * // Pin 0 (input) output latch is updated to 1, but pin state remains unaffected.
 * rvx_gpio_write_all(gpio_address, 0b0101);
 * ```
 *
 * @param gpio_address Pointer to the base address of the GPIO peripheral.
 * @param value_mask 32-bit bitmask specifying the logic values for the pins:
 *                   1 = set to logic 1, 0 = set to logic 0.
 */
static inline void rvx_gpio_write_all(RvxGpio *gpio_address, const uint32_t value_mask)
{
  gpio_address->RVX_GPIO_OUTPUT_REG = value_mask;
}

/**
 * @brief Clear multiple GPIO output pins to logic 0 simultaneously.
 *
 * Drives all GPIO pins corresponding to bits set to 1 in `bitmask` to logic 0 if they are
 * configured as outputs. Pins configured as inputs have their output latch updated without changing
 * the pin state. The new value takes effect when the pin is later configured as an output.
 *
 * Bits corresponding to non-existent pins (beyond the number of implemented GPIO pins) are ignored.
 * Bits set to 0 leave the corresponding pins unchanged.
 *
 * Example usage:
 * ```c
 * // This example assumes the GPIO peripheral provides 4 pins and
 * // is mapped at address 0x80002000.
 * RvxGpio *gpio_address = (RvxGpio *)0x80002000;
 *
 * // Configure pin directions.
 * // Pin 0 = input, pin 1 = output, pin 2 = output, pin 3 = output
 * rvx_gpio_configure_all(gpio_address, 0b1110);
 *
 * // Set pins 1 and 2 to logic 0 simultaneously.
 * // Pin 0 output latch is cleared to 0, but the pin state is not affected.
 * // Pin 3 remains unchanged.
 * rvx_gpio_multi_pin_clear(gpio_address, 0b0111);
 * ```
 *
 * @param gpio_address Pointer to the base address of the GPIO peripheral.
 * @param bitmask 32-bit bitmask specifying which pins to clear:
 *                1 = clear to logic 0, 0 = leave unchanged.
 */
static inline void rvx_gpio_multi_pin_clear(RvxGpio *gpio_address, const uint32_t bitmask)
{
  gpio_address->RVX_GPIO_CLEAR_REG = bitmask;
}

/**
 * @brief Set multiple GPIO output pins to logic 1 simultaneously.
 *
 * Drives all GPIO pins corresponding to bits set to 1 in `bitmask` to logic 1 if they are
 * configured as outputs. Pins configured as inputs have their output latch updated without changing
 * the pin state. The new value takes effect when the pin is later configured as an output.
 *
 * Bits corresponding to non-existent pins (beyond the number of implemented GPIO pins) are ignored.
 * Bits set to 0 leave the corresponding pins unchanged.
 *
 * Example usage:
 * ```c
 * // This example assumes the GPIO peripheral provides 4 pins and
 * // is mapped at address 0x80002000.
 * RvxGpio *gpio_address = (RvxGpio *)0x80002000;
 *
 * // Configure pin directions.
 * // Pin 0 = input, pin 1 = output, pin 2 = output, pin 3 = output
 * rvx_gpio_configure_all(gpio_address, 0b1110);
 *
 * // Set pins 1 and 2 to logic 1 simultaneously.
 * // Pin 0 output latch is set to 1, but the pin state is not affected.
 * // Pin 3 remains unchanged.
 * rvx_gpio_multi_pin_set(gpio_address, 0b0111);
 * ```
 *
 * @param gpio_address Pointer to the base address of the GPIO peripheral.
 * @param bitmask 32-bit bitmask specifying which pins to set:
 *                1 = set to logic 1, 0 = leave unchanged.
 */
static inline void rvx_gpio_multi_pin_set(RvxGpio *gpio_address, const uint32_t bitmask)
{
  gpio_address->RVX_GPIO_SET_REG = bitmask;
}

/**
 * @brief Configure the SPI Manager to operate on a given mode.
 *
 * The four possible modes are:
 *
 *   - RVX_SPI_MODE_0 (CPOL 0, CPHA 0).
 *
 *   - RVX_SPI_MODE_1 (CPOL 0, CPHA 1).
 *
 *   - RVX_SPI_MODE_2 (CPOL 1, CPHA 0).
 *
 *   - RVX_SPI_MODE_3 (CPOL 1, CPHA 1).
 *
 * @param spi_address Pointer to the base address of the SPI Manager.
 * @param mode Desired mode as `RvxSpiMode`.
 */
static inline void rvx_spi_mode_set(RvxSpiManager *spi_address, RvxSpiMode mode)
{
  spi_address->RVX_SPI_MODE = mode;
}

/**
 * @brief Read the current SPI Manager mode.
 *
 * @param spi_address Pointer to the base address of the SPI Manager.
 * @return The SPI Manager mode as `RvxSpiMode`.
 */
static inline RvxSpiMode rvx_spi_mode_get(RvxSpiManager *spi_address)
{
  return (RvxSpiMode)spi_address->RVX_SPI_MODE;
}

/**
 * @brief Assert the Chip Select (CS) line controlled by the SPI Manager.
 *
 * The SPI Manager hardware provides only one Chip Select output under its control.
 * To communicate with multiple SPI devices on the same bus, use additional GPIO pins
 * as software-controlled CS lines.
 *
 * @param spi_address Pointer to the base address of the SPI Manager.
 */
static inline void rvx_spi_chip_select_assert(RvxSpiManager *spi_address)
{
  spi_address->RVX_SPI_CHIP_SELECT = 0;
}

/**
 * @brief Deassert the Chip Select (CS) line controlled by the SPI Manager.
 *
 * The SPI Manager hardware provides only one Chip Select output under its control.
 * To communicate with multiple SPI devices on the same bus, use additional GPIO pins
 * as software-controlled CS lines.
 *
 * @param spi_address Pointer to the base address of the SPI Manager.
 */
static inline void rvx_spi_chip_select_deassert(RvxSpiManager *spi_address)
{
  spi_address->RVX_SPI_CHIP_SELECT = 1;
}

/**
 * @brief Set the SPI clock (SCLK) frequency.
 *
 * This function configures the divider that controls the frequency of the SCLK output pin.
 * The SCLK pin frequency is derived from the system clock according to:
 *
 *     `f_SCLK = f_clock / [2 * (divider + 1)]`
 *
 * where:
 *
 * - `f_clock` is the system clock frequency
 *
 * - `divider` is the value set by this function
 *
 * A smaller divider gives a faster SPI clock:
 *
 * - `divider = 0` → fastest clock: `f_SCLK = f_clock / 2`
 *
 * - `divider = 255` → slowest clock: `f_SCLK = f_clock / 512`
 *
 * @param spi_address Pointer to the base address of the SPI Manager.
 * @param divider Clock divider value (0–255) that determines the SCLK output frequency.
 */
static inline void rvx_spi_clock_set_divider(RvxSpiManager *spi_address, const uint8_t divider)
{
  spi_address->RVX_SPI_DIVIDER = divider;
}

/**
 * @brief Return the current `divider` value configured for the SCLK (SPI clock) frequency.
 *
 * This function reads the `divider` setting in the SPI Manager, which determines the frequency
 * of the SCLK output pin according to the formula:
 *
 *     `f_SCLK = f_clock / [2 * (divider + 1)]`
 *
 * @param spi_address Pointer to the base address of the SPI Manager.
 * @return The current divider configuration value.
 */
static inline uint8_t rvx_spi_clock_get_divider(RvxSpiManager *spi_address)
{
  return spi_address->RVX_SPI_DIVIDER;
}

/**
 * @brief Write a byte to the SPI peripheral.
 *
 * Sends a byte to the SPI device selected by the active CS line and blocks until the transfer
 * completes. The data received from the SPI peripheral during the transfer is ignored.
 *
 * @param spi_address Pointer to the base address of the SPI Manager.
 * @param wdata Byte to be transmitted.
 */
static inline void rvx_spi_write(RvxSpiManager *spi_address, const uint8_t wdata)
{
  spi_address->RVX_SPI_WRITE = wdata;
  while (spi_address->RVX_SPI_STATUS & 1)
    ;
}

/**
 * @brief Send a byte over SPI and receive a byte simultaneously.
 *
 * Transmits a byte to the SPI peripheral selected by the active CS line and blocks until the
 * transfer completes. Returns the byte received from the SPI peripheral during the transfer.
 *
 * @param spi_address Pointer to the base address of the SPI Manager.
 * @param wdata Byte to be transmitted.
 * @return Byte received from the selected SPI Peripheral during the transfer.
 */
static inline uint8_t rvx_spi_transfer(RvxSpiManager *spi_address, const uint8_t wdata)
{
  spi_address->RVX_SPI_WRITE = wdata;
  while (spi_address->RVX_SPI_STATUS & 1)
    ;
  return spi_address->RVX_SPI_READ;
}

/**
 * @brief Enable the timer. When enabled, the 64-bit timer counter increments on every rising
 * edge of the timer's input clock signal.
 *
 * @note If the timer is already enabled, calling this function has no effect.
 *
 * @param timer_address Pointer to the base address of the Timer peripheral.
 */
static inline void rvx_timer_enable(RvxTimer *timer_address)
{
  RVX_SET_BIT(timer_address->RVX_TIMER_COUNTER_ENABLE, 0);
}

/**
 * @brief Disable the timer. When disabled, the 64-bit timer counter stops incrementing and retains
 * its current value.
 *
 * @note If the timer is already disabled, calling this function has no effect.
 *
 * @param timer_address Pointer to the base address of the Timer peripheral.
 */
static inline void rvx_timer_disable(RvxTimer *timer_address)
{
  RVX_CLR_BIT(timer_address->RVX_TIMER_COUNTER_ENABLE, 0);
}

/**
 * @brief Check if the timer counter is enabled.
 *
 * @param timer_address Pointer to the base address of the Timer peripheral.
 * @return true if the timer is enabled, false otherwise.
 */
static inline bool rvx_timer_is_enabled(RvxTimer *timer_address)
{
  return RVX_READ_BIT(timer_address->RVX_TIMER_COUNTER_ENABLE, 0);
}

/**
 * @brief Set a new value for the timer counter. The value can be updated whether counting is
 * enabled or disabled.
 *
 * @param timer_address Pointer to the base address of the Timer peripheral.
 * @param new_value 64-bit value to assign to the timer counter.
 */
static inline void rvx_timer_set_counter(RvxTimer *timer_address, uint64_t new_value)
{
  timer_address->RVX_TIMER_COUNTERL = 0x00000000U; // Temporarily set lower 32 bits to 0
  timer_address->RVX_TIMER_COUNTERH = (uint32_t)(new_value >> 32);
  timer_address->RVX_TIMER_COUNTERL = (uint32_t)(new_value & 0xFFFFFFFFU);
}

/**
 * @brief Read the current value of the timer counter.
 *
 * @param timer_address Pointer to the base address of the Timer peripheral.
 * @return 64-bit value representing the current timer count.
 */
static inline uint64_t rvx_timer_get_counter(RvxTimer *timer_address)
{
  uint32_t hi1, hi2, lo;
  do
  {
    hi1 = timer_address->RVX_TIMER_COUNTERH;
    lo = timer_address->RVX_TIMER_COUNTERL;
    hi2 = timer_address->RVX_TIMER_COUNTERH;
  } while (hi1 != hi2);
  return ((uint64_t)hi2 << 32) | lo;
}

/**
 * @brief Clear the 64-bit timer counter by setting it to 0.
 *
 * The counter is set to zero regardless of whether counting is enabled or disabled.
 *
 * @param timer_address Pointer to the base address of the Timer peripheral.
 */
static inline void rvx_timer_clear_counter(RvxTimer *timer_address)
{
  timer_address->RVX_TIMER_COUNTERL = 0;
  timer_address->RVX_TIMER_COUNTERH = 0;
  timer_address->RVX_TIMER_COUNTERL = 0;
}

/**
 * @brief Set a new value for the 64-bit timer compare register.
 *
 * A timer interrupt is triggered when the timer counter is equal to or greater than the
 * compare register.
 *
 * To prevent spurious interrupts while updating the compare register, the value is written
 * according to the RISC-V Privileged Architecture Specification v2 (pp. 45-46):
 *
 * 1. Set the lower 32-bit register to 0xFFFFFFFF temporarily.
 *
 * 2. Write the upper 32-bit register.
 *
 * 3. Write the desired lower 32-bit value.
 *
 * @param timer_address Pointer to the base address of the Timer peripheral.
 * @param new_value 64-bit value to assign to the compare register.
 */
static inline void rvx_timer_set_compare(RvxTimer *timer_address, uint64_t new_value)
{
  timer_address->RVX_TIMER_COMPAREL = 0xFFFFFFFFU;
  timer_address->RVX_TIMER_COMPAREH = new_value >> 32;
  timer_address->RVX_TIMER_COMPAREL = new_value & 0xFFFFFFFFU;
}

/**
 * @brief Get the current value of the 64-bit timer compare register.
 *
 * @param timer_address Pointer to the base address of the Timer peripheral.
 * @return uint64_t The current value of the compare register.
 */
static inline uint64_t rvx_timer_get_compare(RvxTimer *timer_address)
{
  return ((uint64_t)timer_address->RVX_TIMER_COMPAREH << 32) | timer_address->RVX_TIMER_COMPAREL;
}

/**
 * @brief Clear the timer interrupt by setting the compare register to its maximum value.
 *
 * @param timer_address Pointer to the base address of the Timer peripheral.
 */
static inline void rvx_timer_clear_interrupt(RvxTimer *timer_address)
{
  timer_address->RVX_TIMER_COMPAREL = 0xFFFFFFFFU;
  timer_address->RVX_TIMER_COMPAREH = 0xFFFFFFFFU;
}

/**
 * @brief Check if the UART is ready to send data.
 *
 * @note In most cases, you do not need to call this function directly, as UART transmitting
 * functions (e.g., `rvx_uart_write`, `rvx_uart_write_string`) automatically wait until the UART is
 * ready to transmit.
 *
 * @param uart_address Pointer to the base address of the UART peripheral.
 * @return `true` if the UART is ready to send data, `false` otherwise.
 */
static inline bool rvx_uart_tx_ready(RvxUart *uart_address)
{
  return uart_address->RVX_UART_STATUS_REG & 1;
}

/**
 * @brief Busy-wait until the UART transmission is complete.
 *
 * This function continuously checks the UART status register and returns only when the UART is ready to
 * send new data.
 *
 * Example usage:
 *
 * ```c
 * // Assume UART is mapped at address 0x80000000
 * RvxUart *uart_address = (RvxUart *)0x80000000;
 *
 * // Send data
 * rvx_uart_write(uart_address, 'A');
 *
 * // Busy-wait until transmission above is complete
 * rvx_uart_wait_tx_complete(uart_address);
 * ```
 *
 * @param uart_address Pointer to the base address of the UART peripheral.
 */
static inline void rvx_uart_wait_tx_complete(RvxUart *uart_address)
{
  while (!rvx_uart_tx_ready(uart_address))
    ;
}

/**
 * @brief Check if the UART has received new data.
 *
 * Returns `true` if new data has been received and is waiting to be read, or `false` otherwise.
 *
 * Example usage:
 *
 * ```c
 * // Assume UART is mapped at address 0x80000000
 * RvxUart *uart_address = (RvxUart *)0x80000000;
 *
 * // Wait for data to be received (busy-wait)
 * while (!rvx_uart_rx_ready(uart_address));
 *
 * // Read the received byte
 * uint8_t rx_data = rvx_uart_read(uart_address);
 * ```
 *
 * @param uart_address Pointer to the base address of the UART peripheral.
 * @return `true` if new data is available, `false` if no new data has been received
 */
static inline bool rvx_uart_rx_ready(RvxUart *uart_address)
{
  return (uart_address->RVX_UART_STATUS_REG >> 1) & 1;
}

/**
 * @brief Read a received byte from the UART.
 *
 * This function returns the last byte received by the UART. After power-on or reset, if no data has
 * been received, the function returns `0x00`.
 *
 * To check if new data is available, use `rvx_uart_rx_ready()`.
 *
 * Example usage:
 * ```c
 * // Assume UART is mapped at address 0x80000000
 * RvxUart *uart_address = (RvxUart *)0x80000000;
 *
 * // Wait for data to be received (busy-wait)
 * while (!rvx_uart_rx_ready(uart_address));
 *
 * // Read the received byte
 * uint8_t rx_data = rvx_uart_read(uart_address);
 * ```
 *
 * @param uart_address Pointer to the base address of the UART peripheral.
 * @return The last received byte, or `0x00` if no data has been received since power-on or reset.
 */
static inline uint8_t rvx_uart_read(RvxUart *uart_address)
{
  return uart_address->RVX_UART_READ_REG;
}

/**
 * @brief Send a single byte over the UART.
 *
 * This function busy-waits until the UART is ready before performing the write. There is no
 * need to call `rvx_uart_tx_ready()` or `rvx_uart_wait_tx_complete()` beforehand, as this
 * function handles waiting internally.
 *
 * Example usage:
 *
 * ```c
 * // Assume UART is mapped at address 0x80000000
 * RvxUart *uart_address = (RvxUart *)0x80000000;
 *
 * // Send 'A' over UART
 * rvx_uart_write(uart_address, 'A');
 *
 * // Send 'B', busy-waits until 'A' has been fully transmitted
 * rvx_uart_write(uart_address, 'B');
 * ```
 *
 * @param uart_address Pointer to the base address of the UART peripheral.
 * @param data The byte to write (`uint8_t`).
 */
static inline void rvx_uart_write(RvxUart *uart_address, uint8_t data)
{
  rvx_uart_wait_tx_complete(uart_address);
  uart_address->RVX_UART_WRITE_REG = data;
}

/**
 * @brief Send a null-terminated C string over the UART.
 *
 * Transmits each character in `c_str` sequentially until the null terminator (`'\0'`)
 * is reached. This function busy-waits for the UART to be ready before sending each byte.
 *
 * Example usage:
 * ```c
 * // Assume UART is mapped at address 0x80000000
 * RvxUart *uart_address = (RvxUart *)0x80000000;
 *
 * // Send the string "Hello, World!" over UART, waiting if necessary
 * rvx_uart_write_string(uart_address, "Hello, World!");
 * ```
 *
 * @param uart_address Pointer to the base address of the UART peripheral.
 * @param c_str Pointer to the null-terminated C string to transmit.
 */
static inline void rvx_uart_write_string(RvxUart *uart_address, const char *c_str)
{
  while (*c_str)
  {
    rvx_uart_write(uart_address, *c_str++);
  }
}

/**
 * @brief Initialize the UART with a specified baud rate.
 *
 * This function configures the UART's baud rate by writing the number of clock cycles
 * per baud into the UART baud configuration register. The required value for
 * `cycles_per_baud` can be calculated using:
 *
 * ```
 * cycles_per_baud = f_clock / desired_baud_rate
 * ```
 *
 * For example, if the system clock is 50 MHz and the desired baud rate is 115200, then:
 *
 * ```
 * cycles_per_baud = 50000000 / 115200 ~= 434
 * ```
 *
 * After initialization, the UART will transmit and receive data at the configured
 * baud rate. This function does not modify any other UART settings.
 *
 * Example usage:
 *
 * ```c
 * // Assume UART is mapped at address 0x80000000
 * RvxUart *uart_address = (RvxUart *)0x80000000;
 *
 * // Initialize UART for 115200 baud with a 50 MHz clock
 * rvx_uart_init(uart_address, 50000000 / 115200);
 * ```
 *
 * @param uart_address Pointer to the base address of the UART peripheral.
 * @param cycles_per_baud Number of clock cycles per baud (`f_clock / desired_baud_rate`).
 */
static inline void rvx_uart_init(RvxUart *uart_address, uint32_t cycles_per_baud)
{
  uart_address->RVX_UART_BAUD_REG = cycles_per_baud;
}

#endif // RVX_HAL_H