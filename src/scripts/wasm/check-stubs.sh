#!/usr/bin/env bash
# Guard against the wasm stub files drifting from the interfaces they replace.
#
# The browser build swaps gdbRemote.cpp -> gdbRemoteStub.cpp and
# tinyfiledialogs.c -> tinyfd_stub.c. If a new remote_gdb:: function (or a newly
# used tinyfd_ function) is added but the stub is not updated, only the wasm
# *link* breaks -- and only if someone builds it. This static check catches that
# drift in seconds, with no toolchain.
#
# Exit non-zero (and print what is missing) if a stub is incomplete.
set -euo pipefail
cd "$(dirname "$0")/../.."   # -> src/

fail=0

# --- remote_gdb:: API ----------------------------------------------------------
# Every function declared in gdbRemote.hpp must be defined in gdbRemoteStub.cpp.
HDR=app/integration/gdb/gdbRemote.hpp
STUB=app/integration/gdb/gdbRemoteStub.cpp

# Function names = identifier immediately before '(' on a declaration line that
# ends in ');'. Filters out control keywords just in case.
# Identifier immediately before '(' anywhere in the header (catches multi-line
# declarations too), minus control keywords and primitive types that show up
# inside typedefs like `std::function<void(...)>`.
declared=$(grep -oE '\b[A-Za-z_][A-Za-z0-9_]*\s*\(' "$HDR" \
    | sed -E 's/\s*\($//' \
    | grep -vE '^(if|for|while|switch|return|sizeof|void|bool|int|char|float|double|size_t|uint8_t|uint16_t|uint32_t|uint64_t)$' \
    | sort -u)

for fn in $declared; do
    # The stub must contain a definition: "<fn>(" with a body "{".
    if ! grep -qE "\b${fn}\s*\(" "$STUB"; then
        echo "MISSING in $STUB: remote_gdb::${fn}"
        fail=1
    fi
done

# --- tinyfiledialogs API -------------------------------------------------------
# Every tinyfd_ function actually called in the app must exist in the stub.
STUB_TFD=app/dialogs/tinyfd_stub.c
used=$(grep -rhoE '\btinyfd_[A-Za-z]+\s*\(' app main.cpp --include='*.cpp' \
    | sed -E 's/\s*\($//' | sort -u)

for fn in $used; do
    if ! grep -qE "\b${fn}\s*\(" "$STUB_TFD"; then
        echo "MISSING in $STUB_TFD: ${fn}"
        fail=1
    fi
done

if [[ $fail -ne 0 ]]; then
    echo
    echo "Wasm stub drift detected. Update the stub(s) above to match the interface."
    exit 1
fi

echo "OK: wasm stubs cover their interfaces."
