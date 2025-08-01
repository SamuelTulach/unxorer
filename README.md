# unxorer
Yet another plugin for deobfuscating stack strings.

![demo](/assets/demo.gif)

## Concept
You can specify one or more starting addresses (e.g. entry point, cursor location, or all functions in the database), from which the plugin will emulate every feasible execution path using [Unicorn](https://www.unicorn-engine.org/). Conditional jumps are forced to branch, and emulation states are saved and restored as needed. Throughout this process, the stack is scanned for strings. When it encounters calls to unknown memory regions (typically imports) or unsupported instructions, it attempts to skip over them so that as many paths as possible can be emulated.

## Installation
1. Download the latest release from the [releases page](https://github.com/SamuelTulach/unxorer/releases) or compile it yourself (see **Compiling** below).  
2. Copy the plugin file into your IDA “plugins” directory:
   - **Windows:** `C:\Program Files\IDA <version>\plugins`
   - **Linux/macOS:** `~/ida/plugins`
3. Restart IDA if it is running.
4. Confirm that the plugin has loaded by opening the **Edit -> Plugins** menu in IDA.

## Usage
1. Load binary or memory blob into IDA.
1. Open the **Edit -> Plugins -> unxorer** menu. Configure options as needed. Click **Ok** to start.
   
   ![menu](/assets/menu.png)
1. Wait for the emulation to complete.
   
   ![progress](/assets/progress.png)
1. List of found strings will be displayed, search in it with Ctrl+F, double-click to jump to where it was found.
   
   ![results](/assets/results.png)

## Compiling
This plugin is targetting IDA Home SDK 9.1 and Windows, but in theory should work on any platform and hopefully future IDA versions as well. Those instructions are Windows specific.
1. Download and install [Visual Studio 2022](https://visualstudio.microsoft.com/) with [C++ development tools and CMake](https://learn.microsoft.com/en-us/cpp/build/vscpp-step-0-installation?view=msvc-170).
1. Download the [IDA SDK](https://cpp.docs.hex-rays.com/) and extract it to a directory, e.g. `C:\ida-sdk`.
1. Set `IDASDK` environment variable to the path of the extracted IDA SDK, e.g. `C:\ida-sdk`.
   - You can do this by searching for "Environment Variables" in the Start menu and adding a new variable.
1. Setup vcpkg by following [the setup instructions](https://learn.microsoft.com/en-us/vcpkg/get_started/get-started?pivots=shell-powershell).
1. Open the `CMakeLists.txt` file in Visual Studio.
1. Select desired build configuration (**release-x64** or **debug-x64**).
1. Build the project (Ctrl+Shift+B).
1. The plugin will be compiled into `out\build\plugins\unxorer.dll`.

## Limitations
- The branching algorithm is *very* basic, it might get stuck in infinite loop sometimes or skip actual loops.
- All of the limitations of [Unicorn](https://www.unicorn-engine.org/) apply, such as:
  - It does not support all instructions (e.g. [some AVX instructions](https://github.com/unicorn-engine/unicorn/issues/1879)).
  - It fails to emulate heavilly obfuscated or virtualized code.