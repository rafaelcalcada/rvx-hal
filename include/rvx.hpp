// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 RVX Project Contributors

#ifndef RVX_RVX_HPP
#define RVX_RVX_HPP

#include "rvx.h"

namespace rvx
{
  struct Uart
  {
    Uart() : uart_address(RVX_UART_ADDRESS)
    {
    }
    Uart(uint32_t *uart_address) : uart_address((RvxUart *)uart_address)
    {
    }
    void init(uint32_t baud_rate = 115200, uint32_t clock_frequency_in_hz = 12000000)
    {
      rvx_uart_init(uart_address, baud_rate, clock_frequency_in_hz);
    }
    uint8_t read()
    {
      return rvx_uart_read(uart_address);
    }
    void write(uint8_t data)
    {
      rvx_uart_write(uart_address, data);
    }
    void write_string(const char *c_str)
    {
      rvx_uart_write_string(uart_address, c_str);
    }
    bool tx_ready()
    {
      return rvx_uart_tx_ready(uart_address);
    }
    void wait_tx_complete()
    {
      rvx_uart_wait_tx_complete(uart_address);
    }
    bool rx_ready()
    {
      return rvx_uart_rx_ready(uart_address);
    }
    RvxUart *uart_address;
  };
}

#endif