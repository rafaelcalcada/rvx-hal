<p align="center"><img src="https://github.com/user-attachments/assets/cbb99dc9-c2e8-4234-bad7-8bbcfa434a30" width="100"/></p>

## RVX HAL

RVX HAL is the Hardware Abstraction Layer for [RVX](https://github.com/rafaelcalcada/rvx), designed to make developing software for RVX fast, easy, and maintainable. It provides drivers for SPI, GPIO, UART, and simple access to core registers — so you can focus on your application rather than low-level hardware details. The drivers provide a simple, straightforward API that is easy to use.

Built with CMake and the RISC-V GNU Toolchain, RVX HAL sets up compiler flags and automatically compiles and links your code with RVX startup routines. Its lightweight design makes integration simple — just add it to your project’s CMake and start coding.

### Features

- **Fast to start** – Minimal setup, immediate integration.
- **Clean API** – Unified access to peripherals and processor registers.
- **Portable & lightweight** – Works across projects with minimal overhead.
- **Maintainable code** – Avoid manual register tweaks and keep your software readable.

Whether you’re prototyping or building full applications, RVX HAL simplifies development and lets you spend more time on what matters: your code.

Explore detailed documentation and examples in the [RVX Documentation](https://rafaelcalcada.github.io/rvx).