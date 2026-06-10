Keystone Engine
==============

[![Build Status](https://travis-ci.org/keystone-engine/keystone.svg?branch=master)](https://travis-ci.org/keystone-engine/keystone)
[![Build Status](https://semaphoreci.com/api/v1/aquynh/keystone/branches/master/badge.svg)](https://semaphoreci.com/aquynh/keystone)
[![Build status](https://ci.appveyor.com/api/projects/status/c27slvyrijiejvqs?svg=true)](https://ci.appveyor.com/project/aquynh/keystone)

Keystone is a lightweight multi-platform, multi-architecture assembler framework.
It offers some unparalleled features:

- Multi-architecture, with support for Arm, Arm64 (AArch64/Armv8), Ethereum Virtual Machine, Hexagon, Mips, PowerPC, RISC-V, Sparc, SystemZ & X86 (include 16/32/64bit).
- Clean/simple/lightweight/intuitive architecture-neutral API.
- Implemented in C/C++ languages, with bindings for Java, Masm, C#, PowerShell, Perl, Python, NodeJS, Ruby, Go, Rust, Haskell, VB6 & OCaml available.
- Native support for Windows & \*nix (with Mac OSX, Linux, \*BSD & Solaris confirmed).
- Thread-safe by design.
- Open source - with a dual license.

Keystone is based on LLVM, but it goes much further with [a lot more to offer](/docs/beyond_llvm.md).

Further information is available at http://www.keystone-engine.org


This fork
---------

This is a maintained fork of [keystone-engine/keystone](https://github.com/keystone-engine/keystone)
(upstream has had no commits since May 2023). It builds on modern toolchains and
substantially completes the x86 **NASM** dialect, with fixes verified
byte-for-byte against the NASM assembler, by the regression suite, and by
executing the assembled code in the [Unicorn](https://github.com/unicorn-engine/unicorn)
CPU emulator.

**Build / toolchain**
- Compiles with current CMake (CMP0051) and libstdc++ (`<cstdint>`).

**NASM syntax (x86)**
- Data: string literals in `db`/`dw`/`dd`/`dq`, float literals in `dd`/`dq`/`dt`
  (IEEE single / double / 80-bit), `dt`/`do`/`dy`/`dz`, and `resb`/`resw`/`resd`/`resq`/...
- Directives / pseudo-ops: `times`, `equ`, `align`, `extern`, `org`,
  `section`/`segment`, the `$` and `$$` location counters, and `0o`/`0q` octal
  and `0y` binary integer prefixes.
- Decimal is now the default radix (it was forcing hex — `db 12` produced `0x12`);
  hex stays opt-in via `KS_OPT_SYNTAX_RADIX16`.
- The boot-sector idiom `times 510-($-$$) db 0` works via a layout-time fill — a
  full 512-byte boot sector (and a 16→32-bit protected-mode switch with a
  GDT built from data directives) assembles and boots in Unicorn.

**Assembler bug fixes (x86)**
- `push word imm16` no longer loses the `0x66` prefix (matched `PUSHi32`).
- `[rax+rsp]` / `[rbx+rsp*1]` no longer encode RSP as an illegal SIB index (swapped to base).
- Symbol differences in memory displacements (`lea eax, [eax+b-a]`) resolve correctly.
- Segment overrides inside brackets (`[es:0x10]`, `[fs:eax]`) are accepted.
- Symbol-resolver call/jmp displacement is no longer off by 4.
- Spurious `0x66` operand-size prefix removed from `ret`/`retf`/`iret`/`pushf`/`popf`
  and 16-bit `push`/`call imm` in Intel/NASM syntax.

See `suite/regress/` (notably `x86_emulate_directives.py`, which runs the output
in Unicorn) for the tests covering these.

Further information is available at http://www.keystone-engine.org


License
-------

Keystone is available under a dual license:

- Version 2 of the GNU General Public License (GPLv2). (I.e. Without the "any later version" clause.).
  License information can be found in the [COPYING file](COPYING) and the [EXCEPTIONS-CLIENT file](EXCEPTIONS-CLIENT).

  This combination allows almost all of open source projects to use Keystone without conflicts.

- For commercial usage in production environments, contact the authors of Keystone to buy a royalty-free license.

  See [LICENSE-COM.TXT](LICENSE-COM.TXT) for more information.


Compilation & Docs
------------------

See [COMPILE.md](docs/COMPILE.md) file for how to compile and install Keystone.

More documentation is available in [docs/README.md](docs/README.md).


Contact
-------

[Contact us](http://www.keystone-engine.org/contact/) via mailing list, email or twitter for any questions.


Contribute
----------

Keystone is impossible without generous support from [our sponsors](/SPONSORS.TXT). We cannot thank them enough! 

[CREDITS.TXT](CREDITS.TXT) records other important contributors of our project.

If you want to contribute, please pick up something from our [Github issues](https://github.com/keystone-engine/keystone/issues).

We also maintain a list of more challenged problems in a [TODO list](https://github.com/keystone-engine/keystone/wiki/TODO).


