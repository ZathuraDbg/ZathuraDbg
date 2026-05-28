#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
set -u
# Pipelines return the exit status of the last command to exit with a non-zero status,
# or zero if no command exited with a non-zero status
set -o pipefail

# Define project directories
RUST_PROJECT_DIR="/home/rc/icicle-cpp/src"
CPP_TEST_DIR="/home/rc/icicle-cpp/tests"
INSTALL_DIR="/usr/local/lib"

echo "--- Starting Build and Test ---"

# 1. Build the Rust static library
echo "[1/3] Building Rust project in $RUST_PROJECT_DIR..."
cd "$RUST_PROJECT_DIR"

if cargo build; then
    echo "    Build successful."
else
    echo "Error: Rust build failed."
    exit 1
fi

# 2. Build C tests
echo "[2/3] Building C tests in $CPP_TEST_DIR..."
cd "$CPP_TEST_DIR"

echo "    Running 'make clean'..."
make clean

echo "    Running 'make'..."
make

# 3. Run the tests (GHIDRA_SRC is required for SLEIGH processor definitions)
echo "[3/3] Running C tests..."
export GHIDRA_SRC="../ghidra"

for test_bin in tests-debug serialization-test-debug compression-test-debug \
                 hook-tests-debug snapshot-tests-debug features-debug; do
    echo "    Running $test_bin..."
    ./"$test_bin"
done

echo "--- Build and Test Finished Successfully ---"
exit 0 