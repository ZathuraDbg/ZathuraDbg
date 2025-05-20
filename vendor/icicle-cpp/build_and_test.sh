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
TARGET_DIR="$RUST_PROJECT_DIR/target/debug"
LIB_NAME="libicicle.a"
INSTALL_DIR="/usr/local/lib"

echo "--- Starting Build and Test ---"

# 1. Navigate to the Rust project directory and build
echo "[1/4] Building Rust project in $RUST_PROJECT_DIR..."
cd "$RUST_PROJECT_DIR" || { echo "Error: Failed to cd into $RUST_PROJECT_DIR"; exit 1; }

if cargo build; then
    echo "    Build successful."
else
    echo "Error: Rust build failed."
    exit 1
fi

# 2. Copy the static library
echo "[2/4] Copying $LIB_NAME to $INSTALL_DIR..."
cd "$TARGET_DIR" || { echo "Error: Failed to cd into $TARGET_DIR"; exit 1; }

if sudo cp "$LIB_NAME" "$INSTALL_DIR/"; then
    echo "    Successfully copied $LIB_NAME."
else
    echo "Error: Failed to copy $LIB_NAME. Make sure you have sudo permissions."
    exit 1
fi

# 3. Navigate to the C++ test directory and build tests
echo "[3/4] Building C++ tests in $CPP_TEST_DIR..."
cd "$CPP_TEST_DIR" || { echo "Error: Failed to cd into $CPP_TEST_DIR"; exit 1; }

echo "    Running 'make clean'..."
if make clean; then
    echo "    'make clean' successful."
else
    echo "Warning: 'make clean' failed, continuing anyway..."
    # Don't exit here, maybe clean wasn't necessary
fi

echo "    Running 'make'..."
if make; then
    echo "    'make' successful."
else
    echo "Error: C++ test build failed."
    exit 1
fi

# 4. Run the tests
echo "[4/4] Running C++ tests..."
if ./tests-debug; then
    echo "    Tests completed successfully."
else
    echo "Error: C++ tests failed or encountered an error."
    exit 1
fi

echo "--- Build and Test Finished Successfully ---"
exit 0 