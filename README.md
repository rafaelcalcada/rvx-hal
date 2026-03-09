<p align="center"><img src="https://github.com/user-attachments/assets/cbb99dc9-c2e8-4234-bad7-8bbcfa434a30" width="100"/></p>

## About the RVX HAL

RVX HAL is the Hardware Abstraction Layer for [RVX](https://github.com/rafaelcalcada/rvx), designed to make software development for RVX fast, easy, and maintainable. It provides drivers for RVX peripherals and simple access to processor registers — so you can focus on your application rather than low-level hardware details.

Built with CMake and the RISC-V GNU Toolchain, RVX HAL is designed to be included in RVX application projects via CMake's FetchContent, setting up compiler and linker settings for RVX and providing CMake functions for generating boot images.

### Features

- **Fast to start** – Minimal setup, immediate integration.
- **Clean API** – Unified access to RVX peripherals and processor registers.
- **Lightweight** – Works across projects with minimal overhead.

### Documentation

For the complete API documentation, see the [RVX HAL Reference](https://rafaelcalcada.github.io/rvx/hal).

For instructions on how to develop applications using the RVX HAL, see the [RVX Developer Guide](https://rafaelcalcada.github.io/rvx/devguide).

### License

RVX HAL is distributed under the [MIT License](LICENSE).