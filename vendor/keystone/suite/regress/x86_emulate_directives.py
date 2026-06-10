#!/usr/bin/python

# End-to-end test: assemble directive-heavy NASM code with Keystone and *run*
# the resulting bytes in the Unicorn CPU emulator, asserting on the runtime
# state. This validates that data directives (db/dw/dd/equ/times/$/$$), labels,
# org, segment overrides and a full boot sequence produce code that actually
# executes correctly -- not merely bytes that look right.
#
# Unicorn is an optional dependency; the whole module is skipped when it is not
# installed, so it never breaks the core regression run.
#
# Author: keystone-engine fork

import unittest

from keystone import *

import regress

try:
    from unicorn import *
    from unicorn.x86_const import *
    _HAVE_UNICORN = True
except ImportError:
    _HAVE_UNICORN = False


CODE = 0x100000      # where flat 32-bit test code is loaded
STACK = 0x308000     # stack pointer (middle of the stack map)


def _hlt_stops(uc):
    # Stop the emulator the moment a HLT (0xF4) is about to execute, so each
    # snippet can end with `hlt` instead of running off into garbage.
    def hook(uc, addr, size, user):
        if uc.mem_read(addr, 1)[0] == 0xF4:
            uc.emu_stop()
    uc.hook_add(UC_HOOK_CODE, hook)


@unittest.skipUnless(_HAVE_UNICORN, "unicorn not installed")
class TestEmulateDirectives32(regress.RegressTest):
    """Assemble 32-bit NASM directive code and execute it."""

    def _run(self, asm, regs=None):
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        ks.syntax = KS_OPT_SYNTAX_NASM
        code, _ = ks.asm(asm.encode(), CODE)
        code = bytes(code)

        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        uc.mem_map(CODE, 0x100000)
        uc.mem_map(0x300000, 0x10000)
        uc.mem_map(0x0, 0x10000)        # low scratch for segment-override stores
        uc.mem_write(CODE, code)
        uc.reg_write(UC_X86_REG_ESP, STACK)
        uc.reg_write(UC_X86_REG_EBP, STACK)
        if regs:
            for r, v in regs.items():
                uc.reg_write(r, v)
        _hlt_stops(uc)
        uc.emu_start(CODE, CODE + len(code), count=100000)
        return uc

    def runTest(self):
        # dd data reference: load a 32-bit value defined with `dd`.
        uc = self._run("mov eax, [val]\nhlt\nval: dd 0xdeadbeef")
        self.assertEqual(uc.reg_read(UC_X86_REG_EAX), 0xdeadbeef)

        # db string with an indexed load.
        uc = self._run('movzx eax, byte [msg+2]\nhlt\nmsg: db "ABCDEF"')
        self.assertEqual(uc.reg_read(UC_X86_REG_EAX), ord('C'))

        # equ constant.
        uc = self._run("LEN equ 7\nmov eax, LEN\nhlt")
        self.assertEqual(uc.reg_read(UC_X86_REG_EAX), 7)

        # `$ - label` length computation.
        uc = self._run('jmp s\nmsg: db "hello"\nlen equ $-msg\ns:\nmov eax, len\nhlt')
        self.assertEqual(uc.reg_read(UC_X86_REG_EAX), 5)

        # times-padding must be skipped by a jump over it.
        uc = self._run("jmp code\ntimes 16 db 0x90\ncode:\nmov eax, 0x1234\nhlt")
        self.assertEqual(uc.reg_read(UC_X86_REG_EAX), 0x1234)

        # dd array summed in a loop (data directive + label + indexed access).
        uc = self._run("""
            xor eax, eax
            xor esi, esi
            mov ecx, 4
        sum:
            add eax, [arr+esi*4]
            inc esi
            dec ecx
            jnz sum
            hlt
        arr: dd 10, 20, 30, 40
        """)
        self.assertEqual(uc.reg_read(UC_X86_REG_EAX), 100)

        # Segment-override stores/loads ([es:...] / [ds:...]) round-trip.
        uc = self._run("""
            mov ax, 0
            mov es, ax
            mov dword [es:0x9000], 0xCAFEB00B
            mov eax, [es:0x9000]
            mov ebx, [ds:0x9000]
            hlt
        """)
        self.assertEqual(uc.reg_read(UC_X86_REG_EAX), 0xCAFEB00B)
        self.assertEqual(uc.reg_read(UC_X86_REG_EBX), 0xCAFEB00B)


@unittest.skipUnless(_HAVE_UNICORN, "unicorn not installed")
class TestBootSector(regress.RegressTest):
    """Assemble a real 512-byte boot sector and run it in 16-bit real mode."""

    def runTest(self):
        ks = Ks(KS_ARCH_X86, KS_MODE_16)
        ks.syntax = KS_OPT_SYNTAX_NASM
        src = """
            org 0x7c00
            start:
                mov ax, 0x1234
                mov bx, msg
                add ax, [val]
                hlt
            msg: db "OK"
            val: dw 0x1111
            times 510-($-$$) db 0
            dw 0xaa55
        """
        code, _ = ks.asm(src.encode(), 0x7c00)
        code = bytes(code)

        # The hallmark of a boot sector: exactly 512 bytes, 0x55AA signature.
        self.assertEqual(len(code), 512)
        self.assertEqual(code[510:512], b"\x55\xaa")

        uc = Uc(UC_ARCH_X86, UC_MODE_16)
        uc.mem_map(0x0, 0x10000)
        uc.mem_write(0x7c00, code)
        uc.reg_write(UC_X86_REG_CS, 0)
        uc.reg_write(UC_X86_REG_SS, 0)
        uc.reg_write(UC_X86_REG_SP, 0x7000)
        _hlt_stops(uc)
        uc.emu_start(0x7c00, 0x7c00 + len(code), count=10000)

        # ax = 0x1234 + [val]=0x1111 = 0x2345 ; bx points at the org-relative msg.
        self.assertEqual(uc.reg_read(UC_X86_REG_AX), 0x2345)
        self.assertTrue(0x7c00 <= uc.reg_read(UC_X86_REG_BX) < 0x7e00)


@unittest.skipUnless(_HAVE_UNICORN, "unicorn not installed")
class TestProtectedModeBoot(regress.RegressTest):
    """Boot sector that builds a GDT from data directives and switches the CPU
    into 32-bit protected mode, then runs 32-bit code."""

    def runTest(self):
        ks = Ks(KS_ARCH_X86, KS_MODE_16)
        ks.syntax = KS_OPT_SYNTAX_NASM
        src = r"""
            [bits 16]
            org 0x7c00
            start:
                cli
                xor ax, ax
                mov ds, ax
                lgdt [gdt_desc]
                mov eax, cr0
                or eax, 1
                mov cr0, eax
                jmp 0x08:pm_entry

            [bits 32]
            pm_entry:
                mov ax, 0x10
                mov ds, ax
                mov dword [0x9000], 0x504D4F4B   ; marker only 32-bit code writes
                mov eax, 0x1000
                mov ebx, 0x0337
                add eax, ebx
                mov dword [0x9004], eax          ; 0x1337
                hlt

            align 8
            gdt_start:
                dq 0x0000000000000000            ; null
            gdt_code:
                dw 0xFFFF, 0x0000
                db 0x00, 0x9A, 0xCF, 0x00        ; base=0 limit=4G 32-bit code
            gdt_data:
                dw 0xFFFF, 0x0000
                db 0x00, 0x92, 0xCF, 0x00        ; base=0 limit=4G 32-bit data
            gdt_end:
            gdt_desc:
                dw gdt_end - gdt_start - 1        ; limit (label difference)
                dd gdt_start                      ; base  (label reference)

            times 510-($-$$) db 0
            dw 0xAA55
        """
        code, _ = ks.asm(src.encode(), 0x7c00)
        code = bytes(code)
        self.assertEqual(len(code), 512)
        self.assertEqual(code[510:512], b"\x55\xaa")

        uc = Uc(UC_ARCH_X86, UC_MODE_16)
        uc.mem_map(0x0, 0x100000)
        uc.mem_write(0x7c00, code)
        _hlt_stops(uc)
        uc.emu_start(0x7c00, 0, count=200000)

        # PE bit set, and the 32-bit markers prove PM code actually ran.
        self.assertEqual(uc.reg_read(UC_X86_REG_CR0) & 1, 1)
        self.assertEqual(int.from_bytes(uc.mem_read(0x9000, 4), "little"), 0x504D4F4B)
        self.assertEqual(int.from_bytes(uc.mem_read(0x9004, 4), "little"), 0x1337)


if __name__ == '__main__':
    regress.main()
