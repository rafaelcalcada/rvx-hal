// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 RVX Project Contributors

#ifndef __RVX_CSR_H
#define __RVX_CSR_H

#if __riscv_xlen != 32
#error "Unsupported XLEN"
#endif

/// @name CSR Access and Modification
/// @{

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

/// @}

/// @name CSR Addresses
/// @{
#define RVX_CSR_CYCLEL_ADDR 0xC00    ///< Address of the U-mode Cycle CSR (lower 32 bits).
#define RVX_CSR_TIMEL_ADDR 0xC01     ///< Address of the U-mode Time CSR (lower 32 bits).
#define RVX_CSR_INSTRETL_ADDR 0xC02  ///< Address of the U-mode Instructions Retired CSR (lower 32 bits).
#define RVX_CSR_CYCLEH_ADDR 0xC80    ///< Address of the U-mode Cycle CSR (upper 32 bits).
#define RVX_CSR_TIMEH_ADDR 0xC81     ///< Address of the U-mode Time CSR (upper 32 bits).
#define RVX_CSR_INSTRETH_ADDR 0xC82  ///< Address of the U-mode Instructions Retired CSR (upper 32 bits).
#define RVX_CSR_MARCHID_ADDR 0xF12   ///< Address of the M-mode Architecture ID CSR.
#define RVX_CSR_MIMPID_ADDR 0xF13    ///< Address of the M-mode Implementation ID CSR.
#define RVX_CSR_MSTATUSL_ADDR 0x300  ///< Address of the M-mode Status CSR (lower 32 bits).
#define RVX_CSR_MISA_ADDR 0x301      ///< Address of the M-mode ISA CSR.
#define RVX_CSR_MIE_ADDR 0x304       ///< Address of the M-mode Interrupt Enable CSR.
#define RVX_CSR_MTVEC_ADDR 0x305     ///< Address of the M-mode Trap-Vector CSR.
#define RVX_CSR_MSTATUSH_ADDR 0x310  ///< Address of the M-mode Status CSR (upper 32 bits).
#define RVX_CSR_MSCRATCH_ADDR 0x340  ///< Address of the M-mode Scratch CSR.
#define RVX_CSR_MEPC_ADDR 0x341      ///< Address of the M-mode Exception Program Counter CSR.
#define RVX_CSR_MCAUSE_ADDR 0x342    ///< Address of the M-mode Trap Cause CSR.
#define RVX_CSR_MTVAL_ADDR 0x343     ///< Address of the M-mode Trap Value CSR.
#define RVX_CSR_MIP_ADDR 0x344       ///< Address of the M-mode Interrupt Pending CSR.
#define RVX_CSR_MCYCLEL_ADDR 0xB00   ///< Address of the M-mode Cycle CSR (lower 32 bits).
#define RVX_CSR_MINSTRETL_ADDR 0xB02 ///< Address of the M-mode Instructions Retired CSR (lower 32 bits).
#define RVX_CSR_MCYCLEH_ADDR 0xB80   ///< Address of the M-mode Cycle CSR (upper 32 bits).
#define RVX_CSR_MINSTRETH_ADDR 0xB82 ///< Address of the M-mode Instructions Retired CSR (upper 32 bits).
/// @}

/// @name Bitmasks for CSR Fields
/// @{
#define RVX_CSR_MSTATUSL_MIE_BITMASK (1U << 3U)  ///< Bitmask for the MIE bit in the M-mode Status CSR.
#define RVX_CSR_MSTATUSL_MPIE_BITMASK (1U << 7U) ///< Bitmask for the MPIE bit in the M-mode Status CSR.
#define RVX_CSR_MTVEC_MODE_BITMASK 0x00000003U   ///< Bitmask for the MODE field in the M-mode Trap-Vector CSR.
#define RVX_CSR_MTVEC_BASE_BITMASK 0xFFFFFFFCU   ///< Bitmask for the BASE field in the M-mode Trap-Vector CSR.
/// @}

#endif // __RVX_CSR_H