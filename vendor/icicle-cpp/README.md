# Icicle
[Icicle](https://github.com/icicle-emu/icicle-emu) is an experimental fuzzing-specific, multi-architecture emulation framework.

## C/C++ Bindings
This project aims to provide C/C++ bindings for the icicle emulator. I'd also like to write full on documentation on this soon.

## Usage
Using these bindings is as simple as compiling the static library using cargo and then including it in your project using your compiler or make, cmake, etc.
If you just want the library and the header file, you can download it from the [releases page](https://github.com/HACKE-RC/icicle-cpp/tags)

### Compilation
Getting the static library is as simple as
```sh
git clone https://github.com/HACKE-RC/icicle-cpp
cd icicle-cpp
cd src
cargo build     # you can use cargo build --release if you want the release build
```

The static library will now be built in `icicle-cpp/src/target/<build_type>/libicicle.a`. Here, <build_type> will be `debug` if you do not use the `--release` flag with cargo
and `release` if you do.

# Comprehensive Icicle Hook Testing

This project provides a robust test for the Icicle emulator's hook functionality. The test demonstrates all three types of hooks:
1. Execution hooks - triggered when a block of code executes
2. Syscall hooks - triggered when the program makes a system call
3. Violation hooks - triggered when a memory access violation occurs

## Test Program Details

The test program:

1. Creates an x86_64 virtual machine
2. Maps various memory regions with different permissions
3. Loads a comprehensive test program that:
   - Executes various x86_64 instructions
   - Performs memory reads/writes
   - Attempts to write to read-only memory (triggers violation hook)
   - Makes a syscall (triggers syscall hook)
4. Registers all three types of hooks with detailed callbacks
5. Runs the emulation with hooks enabled
6. Tests hook removal by removing the syscall hook and verifying it no longer triggers

## Expected Output

The test program provides detailed output about:
- Hook registration
- Hook triggering with full context (addresses, permissions, etc.)
- Statistics on how many times each hook was triggered
- Verification that hook removal works

## Building and Running

To build and run the test:

```bash
# Compile the test program
make -f hook_test_Makefile

# Run the test
./hook_test
```

## Hook Implementations

The Rust implementation includes:

1. `icicle_add_violation_hook`: Adds a memory violation hook
2. `icicle_add_syscall_hook`: Adds a syscall interception hook
3. `icicle_add_execution_hook`: Adds a basic block execution hook
4. `icicle_remove_hook`: Removes a previously registered hook

Each hook has detailed callback functions that report what's happening during emulation.
