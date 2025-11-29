<p align="center"><img src="https://github.com/user-attachments/assets/cbb99dc9-c2e8-4234-bad7-8bbcfa434a30" width="100"/></p>

## About RVX HAL

**RVX HAL** is a header-only library (`rvx.h`) that provides a Hardware Abstraction Layer (HAL) for the [RVX Microcontroller](https://github.com/rafaelcalcada/rvx), including drivers for SPI, GPIO, and UART. It also offers a clean API for accessing control and status registers of the RVX processor core.

With RVX HAL, developers can interact with the RVX microcontroller through a consistent, high-level interface — eliminating manual register manipulation while improving portability, maintainability, and code clarity.

### Key Features
- **Header-only design** – No separate compilation or linking required.  
- **Peripheral abstraction** – Unified APIs for SPI, GPIO, UART, and other peripherals.  
- **Core register access** – Simple functions for reading and writing RVX processor registers.  
- **Lightweight and portable** – Easy to integrate with minimal footprint.

## How to Use

You can integrate RVX HAL into your project in one of two ways: **direct include** or **CMake integration**.

### 1. Direct include

Copy the main header file **`rvx.h`** into your project and include it from your source files:

```c
#include "rvx.h"
```

Because the HAL is header-only, no additional build steps are needed.

### 2. CMake integration

If your project uses CMake, you can also fetch and include the latest version of RVX HAL automatically using CMake’s `FetchContent` module:

```cmake
include(FetchContent)

FetchContent_Declare(rvx
  GIT_REPOSITORY https://github.com/rafaelcalcada/rvx-hal.git
  GIT_TAG latest
)

FetchContent_MakeAvailable(rvx)

target_link_libraries(your_app_target rvx)
```

After this, `rvx.h` becomes available for inclusion just like any other header.

For detailed documentation and usage examples, see the [RVX Documentation](https://rafaelcalcada.github.io/rvx).
