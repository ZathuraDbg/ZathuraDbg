#!/usr/bin/python

# Not really an issue. It works as it is supposed to, I'd like to know if there's any possibility to add a ks_option to allow such
# output

# Github issue: #267
# Author: krystalgamer

from keystone import *

import regress

class TestX86(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        # Assemble to get back insn encoding & statement count
        encoding, count = ks.asm(b"call 0")
        # 'call 0' targets absolute address 0; with the call at address 0 the
        # PC-relative displacement is 0 - 5 = -5. This matches NASM
        # ('call 0' -> e8 fb ff ff ff).
        self.assertEqual(encoding, [ 0xE8, 0xFB, 0xFF, 0xFF, 0xFF ])

if __name__ == '__main__':
    regress.main()
