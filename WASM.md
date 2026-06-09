# Running ZathuraDbg in the browser (WebAssembly)

ZathuraDbg compiles to WebAssembly and runs entirely client-side — no server,
no backend. This works because the debugger does not ptrace a real process: it
assembles code with Keystone and emulates it with [icicle](https://github.com/icicle-emu/icicle-emu),
all of which is pure user-space computation that Emscripten can run.

The browser build is **emulation-only**: GDB remote debugging, native file
dialogs, the update check, and OS threads are stubbed or compiled out (see
"What changes in the wasm build" below). Assembling, emulating, stepping,
breakpoints, registers, memory and the stack views all work.

## Prerequisites (built once, out-of-tree)

The wasm build links three third-party static libraries and the icicle bindings,
all compiled for `wasm32-unknown-emscripten`. They live in a sibling workspace
(`/home/rc/icicle-wasm` by default; override with `-DWASM_LIBS_ROOT=...`):

| Artifact | Source | Notes |
|----------|--------|-------|
| `libicicle.a` | icicle-emu + icicle-cpp bindings | interpreter-only (JIT feature-gated off); see that workspace's README |
| `libkeystone.a` | vendored `vendor/keystone` | `emcmake` build, `LLVM_TARGETS=X86;AArch64;ARM` |
| `libcapstone.a` | capstone 5.x | headers used for `cs_*` enums; engine unused in wasm |
| `zathura-fs/` | staged MEMFS | `app/bin/test.asm`, `app/assets/*` (fonts), `ghidra/Ghidra/Processors/{x86,AARCH64,ARM}` |

Also needed: the Emscripten SDK (`emsdk`) and the `wasm32-unknown-emscripten`
Rust target (for rebuilding icicle).

## Build

```sh
cd src
EMSDK_ENV=/path/to/emsdk/emsdk_env.sh \
WASM_LIBS_ROOT=/path/to/icicle-wasm \
./build-wasm.sh
```

This runs `emcmake cmake` + `cmake --build` and produces, next to the source:

- `Zathura.html` — the fullscreen shell (from `wasm-shell.html`)
- `Zathura.js`   — Emscripten loader
- `Zathura.wasm` — ~14 MB, includes the embedded MEMFS (fonts + sleigh specs)

## Serve and open

The build needs no special COOP/COEP headers (single-threaded, no
SharedArrayBuffer). Any static server works:

```sh
cd src/build-wasm/dist   # or wherever you copied the 3 files
python3 -m http.server 8744
# open http://localhost:8744/Zathura.html
```

The canvas fills the viewport and resizes with the window. Press **F5** to
assemble and run the program in the editor; registers/memory/stack update live.

## What changes in the wasm build

Everything is gated behind `__EMSCRIPTEN__` / `if (EMSCRIPTEN)` so the native
build is unaffected.

| Concern | Native | Wasm |
|---------|--------|------|
| Emulator | icicle (JIT) | icicle (interpreter, `jit=0`) |
| Assembler | Keystone (system lib) | Keystone (wasm static lib) |
| Disassembler | Capstone (system lib) | unused; headers only for enums |
| GDB remote | `gdbRemote.cpp` (sockets) | `gdbRemoteStub.cpp` (inert no-ops) |
| File dialogs | tinyfiledialogs | `tinyfd_stub.c` (cancel + console log) |
| Update check | httplib + OpenSSL | reports current version |
| Background work | `std::thread` | runs synchronously (single-threaded) |
| Executable path | whereami | fixed `/app/bin` in MEMFS |
| Sleigh specs | `vendor/ghidra` via `GHIDRA_SRC` | embedded at `/ghidra` |
| Main loop | `while (!shouldClose)` | `emscripten_set_main_loop` |
| Window | desktop GLFW + OpenGL3 | Emscripten GLFW + WebGL2/GLES3 |
| Layout | saved `imgui.ini` | first-run `DockBuilder` default layout |

### Known limitations

- **No GDB remote / no native file open-save** in the browser (by design).
- **x86 `HLT` spins** (the Ghidra spec lifts it as `goto inst_start`); stop with
  `run_until`, breakpoints, or an instruction limit — same as native.
- HiDPI rendering uses CSS-pixel resolution (the Emscripten GLFW backend owns
  the canvas backing store); crisp at 1x, slightly soft on retina.

## Files specific to the wasm port

- `src/wasm-shell.html` — fullscreen HTML shell + loading overlay
- `src/build-wasm.sh` — configure + build wrapper
- `src/app/integration/gdb/gdbRemoteStub.cpp` — inert `remote_gdb::` API
- `src/app/dialogs/tinyfd_stub.c` — inert tinyfiledialogs
- `if (EMSCRIPTEN)` branches in `src/CMakeLists.txt`
