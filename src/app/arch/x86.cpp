#include "x86.hpp"

std::vector<std::string> x86DefaultShownRegs = {"RIP", "RSP", "RBP", "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
    "CS", "DS", "ES", "FS", "GS", "SS"};
std::vector<std::string> x86DefaultShownRegs16 = {"IP", "SP", "BP", "AX", "BX", "CX", "DX", "SI", "DI", "CS", "DS", "ES", "FS", "GS", "SS"};
std::vector<std::string> x86DefaultShownRegs32 = {"EIP", "ESP", "EBP", "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "CS", "DS", "ES", "FS", "SS"};
std::vector<std::string> x86DefaultShownRegs64 = {"RIP", "RSP", "RBP", "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "CS", "DS", "ES", "FS", "GS", "SS"};

std::unordered_map<std::string, std::pair<size_t, int>> x86RegInfoMap = {
        {"INVALID", {0,   UC_X86_REG_INVALID}},
        {"AH",      {8,   UC_X86_REG_AH}},
        {"AL",      {8,   UC_X86_REG_AL}},
        {"AX",      {16,  UC_X86_REG_AX}},
        {"BH",      {8,   UC_X86_REG_BH}},
        {"BL",      {8,   UC_X86_REG_BL}},
        {"BP",      {16,  UC_X86_REG_BP}},
        {"BPL",     {8,   UC_X86_REG_BPL}},
        {"BX",      {16,  UC_X86_REG_BX}},
        {"CH",      {8,   UC_X86_REG_CH}},
        {"CL",      {8,   UC_X86_REG_CL}},
        {"CS",      {16,  UC_X86_REG_CS}},
        {"CX",      {16,  UC_X86_REG_CX}},
        {"DH",      {8,   UC_X86_REG_DH}},
        {"DI",      {16,  UC_X86_REG_DI}},
        {"DIL",     {8,   UC_X86_REG_DIL}},
        {"DL",      {8,   UC_X86_REG_DL}},
        {"DS",      {16,  UC_X86_REG_DS}},
        {"DX",      {16,  UC_X86_REG_DX}},
        {"EAX",     {32,  UC_X86_REG_EAX}},
        {"EBP",     {32,  UC_X86_REG_EBP}},
        {"EBX",     {32,  UC_X86_REG_EBX}},
        {"ECX",     {32,  UC_X86_REG_ECX}},
        {"EDI",     {32,  UC_X86_REG_EDI}},
        {"EDX",     {32,  UC_X86_REG_EDX}},
        {"EFLAGS",  {32,  UC_X86_REG_EFLAGS}},
        {"EIP",     {32,  UC_X86_REG_EIP}},
        {"ES",      {16,  UC_X86_REG_ES}},
        {"ESI",     {32,  UC_X86_REG_ESI}},
        {"ESP",     {32,  UC_X86_REG_ESP}},
        {"FPSW",    {16,  UC_X86_REG_FPSW}},
        {"FS",      {16,  UC_X86_REG_FS}},
        {"GS",      {16,  UC_X86_REG_GS}},
        {"IP",      {16,  UC_X86_REG_IP}},
        {"RAX",     {64,  UC_X86_REG_RAX}},
        {"RBP",     {64,  UC_X86_REG_RBP}},
        {"RBX",     {64,  UC_X86_REG_RBX}},
        {"RCX",     {64,  UC_X86_REG_RCX}},
        {"RDI",     {64,  UC_X86_REG_RDI}},
        {"RDX",     {64,  UC_X86_REG_RDX}},
        {"RIP",     {64,  UC_X86_REG_RIP}},
        {"RSI",     {64,  UC_X86_REG_RSI}},
        {"RSP",     {64,  UC_X86_REG_RSP}},
        {"SI",      {16,  UC_X86_REG_SI}},
        {"SIL",     {8,   UC_X86_REG_SIL}},
        {"SP",      {16,  UC_X86_REG_SP}},
        {"SPL",     {8,   UC_X86_REG_SPL}},
        {"SS",      {16,  UC_X86_REG_SS}},
        {"CR0",     {64,  UC_X86_REG_CR0}},
        {"CR1",     {64,  UC_X86_REG_CR1}},
        {"CR2",     {64,  UC_X86_REG_CR2}},
        {"CR3",     {64,  UC_X86_REG_CR3}},
        {"CR4",     {64,  UC_X86_REG_CR4}},
        {"CR8",     {64,  UC_X86_REG_CR8}},
        {"DR0",     {64,  UC_X86_REG_DR0}},
        {"DR1",     {64,  UC_X86_REG_DR1}},
        {"DR2",     {64,  UC_X86_REG_DR2}},
        {"DR3",     {64,  UC_X86_REG_DR3}},
        {"DR4",     {64,  UC_X86_REG_DR4}},
        {"DR5",     {64,  UC_X86_REG_DR5}},
        {"DR6",     {64,  UC_X86_REG_DR6}},
        {"DR7",     {64,  UC_X86_REG_DR7}},
        {"FP0",     {80,  UC_X86_REG_FP0}},
        {"FP1",     {80,  UC_X86_REG_FP1}},
        {"FP2",     {80,  UC_X86_REG_FP2}},
        {"FP3",     {80,  UC_X86_REG_FP3}},
        {"FP4",     {80,  UC_X86_REG_FP4}},
        {"FP5",     {80,  UC_X86_REG_FP5}},
        {"FP6",     {80,  UC_X86_REG_FP6}},
        {"FP7",     {80,  UC_X86_REG_FP7}},
        {"K0",      {64,  UC_X86_REG_K0}},
        {"K1",      {64,  UC_X86_REG_K1}},
        {"K2",      {64,  UC_X86_REG_K2}},
        {"K3",      {64,  UC_X86_REG_K3}},
        {"K4",      {64,  UC_X86_REG_K4}},
        {"K5",      {64,  UC_X86_REG_K5}},
        {"K6",      {64,  UC_X86_REG_K6}},
        {"K7",      {64,  UC_X86_REG_K7}},
        {"MM0",     {64,  UC_X86_REG_MM0}},
        {"MM1",     {64,  UC_X86_REG_MM1}},
        {"MM2",     {64,  UC_X86_REG_MM2}},
        {"MM3",     {64,  UC_X86_REG_MM3}},
        {"MM4",     {64,  UC_X86_REG_MM4}},
        {"MM5",     {64,  UC_X86_REG_MM5}},
        {"MM6",     {64,  UC_X86_REG_MM6}},
        {"MM7",     {64,  UC_X86_REG_MM7}},
        {"R8",      {64,  UC_X86_REG_R8}},
        {"R9",      {64,  UC_X86_REG_R9}},
        {"R10",     {64,  UC_X86_REG_R10}},
        {"R11",     {64,  UC_X86_REG_R11}},
        {"R12",     {64,  UC_X86_REG_R12}},
        {"R13",     {64,  UC_X86_REG_R13}},
        {"R14",     {64,  UC_X86_REG_R14}},
        {"R15",     {64,  UC_X86_REG_R15}},
        {"ST0",     {80,  UC_X86_REG_ST0}},
        {"ST1",     {80,  UC_X86_REG_ST1}},
        {"ST2",     {80,  UC_X86_REG_ST2}},
        {"ST3",     {80,  UC_X86_REG_ST3}},
        {"ST4",     {80,  UC_X86_REG_ST4}},
        {"ST5",     {80,  UC_X86_REG_ST5}},
        {"ST6",     {80,  UC_X86_REG_ST6}},
        {"ST7",     {80,  UC_X86_REG_ST7}},
        {"XMM0",    {128, UC_X86_REG_XMM0}},
        {"XMM1",    {128, UC_X86_REG_XMM1}},
        {"XMM2",    {128, UC_X86_REG_XMM2}},
        {"XMM3",    {128, UC_X86_REG_XMM3}},
        {"XMM4",    {128, UC_X86_REG_XMM4}},
        {"XMM5",    {128, UC_X86_REG_XMM5}},
        {"XMM6",    {128, UC_X86_REG_XMM6}},
        {"XMM7",    {128, UC_X86_REG_XMM7}},
        {"XMM8",    {128, UC_X86_REG_XMM8}},
        {"XMM9",    {128, UC_X86_REG_XMM9}},
        {"XMM10",   {128, UC_X86_REG_XMM10}},
        {"XMM11",   {128, UC_X86_REG_XMM11}},
        {"XMM12",   {128, UC_X86_REG_XMM12}},
        {"XMM13",   {128, UC_X86_REG_XMM13}},
        {"XMM14",   {128, UC_X86_REG_XMM14}},
        {"XMM15",   {128, UC_X86_REG_XMM15}},
        {"YMM0",    {256, UC_X86_REG_YMM0}},
        {"YMM1",    {256, UC_X86_REG_YMM1}},
        {"YMM2",    {256, UC_X86_REG_YMM2}},
        {"YMM3",    {256, UC_X86_REG_YMM3}},
        {"YMM4",    {256, UC_X86_REG_YMM4}},
        {"YMM5",    {256, UC_X86_REG_YMM5}},
        {"YMM6",    {256, UC_X86_REG_YMM6}},
        {"YMM7",    {256, UC_X86_REG_YMM7}},
        {"YMM8",    {256, UC_X86_REG_YMM8}},
        {"YMM9",    {256, UC_X86_REG_YMM9}},
        {"YMM10",   {256, UC_X86_REG_YMM10}},
        {"YMM11",   {256, UC_X86_REG_YMM11}},
        {"YMM12",   {256, UC_X86_REG_YMM12}},
        {"YMM13",   {256, UC_X86_REG_YMM13}},
        {"YMM14",   {256, UC_X86_REG_YMM14}},
        {"YMM15",   {256, UC_X86_REG_YMM15}},
        {"ZMM0",    {512, UC_X86_REG_ZMM0}},
        {"ZMM1",    {512, UC_X86_REG_ZMM1}},
        {"ZMM2",    {512, UC_X86_REG_ZMM2}},
        {"ZMM3",    {512, UC_X86_REG_ZMM3}},
        {"ZMM4",    {512, UC_X86_REG_ZMM4}},
        {"ZMM5",    {512, UC_X86_REG_ZMM5}},
        {"ZMM6",    {512, UC_X86_REG_ZMM6}},
        {"ZMM7",    {512, UC_X86_REG_ZMM7}},
        {"ZMM8",    {512, UC_X86_REG_ZMM8}},
        {"ZMM9",    {512, UC_X86_REG_ZMM9}},
        {"ZMM10",   {512, UC_X86_REG_ZMM10}},
        {"ZMM11",   {512, UC_X86_REG_ZMM11}},
        {"ZMM12",   {512, UC_X86_REG_ZMM12}},
        {"ZMM13",   {512, UC_X86_REG_ZMM13}},
        {"ZMM14",   {512, UC_X86_REG_ZMM14}},
        {"ZMM15",   {512, UC_X86_REG_ZMM15}},
        {"ZMM16",   {512, UC_X86_REG_ZMM16}},
        {"ZMM17",   {512, UC_X86_REG_ZMM17}},
        {"ZMM18",   {512, UC_X86_REG_ZMM18}},
        {"ZMM19",   {512, UC_X86_REG_ZMM19}},
        {"ZMM20",   {512, UC_X86_REG_ZMM20}},
        {"ZMM21",   {512, UC_X86_REG_ZMM21}},
        {"ZMM22",   {512, UC_X86_REG_ZMM22}},
        {"ZMM23",   {512, UC_X86_REG_ZMM23}},
        {"ZMM24",   {512, UC_X86_REG_ZMM24}},
        {"ZMM25",   {512, UC_X86_REG_ZMM25}},
        {"ZMM26",   {512, UC_X86_REG_ZMM26}},
        {"ZMM27",   {512, UC_X86_REG_ZMM27}},
        {"ZMM28",   {512, UC_X86_REG_ZMM28}},
        {"ZMM29",   {512, UC_X86_REG_ZMM29}},
        {"ZMM30",   {512, UC_X86_REG_ZMM30}},
        {"ZMM31",   {512, UC_X86_REG_ZMM31}},
        {"R8B",     {8,   UC_X86_REG_R8B}},
        {"R9B",     {8,   UC_X86_REG_R9B}},
        {"R10B",    {8,   UC_X86_REG_R10B}},
        {"R11B",    {8,   UC_X86_REG_R11B}},
        {"R12B",    {8,   UC_X86_REG_R12B}},
        {"R13B",    {8,   UC_X86_REG_R13B}},
        {"R14B",    {8,   UC_X86_REG_R14B}},
        {"R15B",    {8,   UC_X86_REG_R15B}},
        {"R8D",     {32,  UC_X86_REG_R8D}},
        {"R9D",     {32,  UC_X86_REG_R9D}},
        {"R10D",    {32,  UC_X86_REG_R10D}},
        {"R11D",    {32,  UC_X86_REG_R11D}},
        {"R12D",    {32,  UC_X86_REG_R12D}},
        {"R13D",    {32,  UC_X86_REG_R13D}},
        {"R14D",    {32,  UC_X86_REG_R14D}},
        {"R15D",    {32,  UC_X86_REG_R15D}},
        {"R8W",     {16,  UC_X86_REG_R8W}},
        {"R9W",     {16,  UC_X86_REG_R9W}},
        {"R10W",    {16,  UC_X86_REG_R10W}},
        {"R11W",    {16,  UC_X86_REG_R11W}},
        {"R12W",    {16,  UC_X86_REG_R12W}},
        {"R13W",    {16,  UC_X86_REG_R13W}},
        {"R14W",    {16,  UC_X86_REG_R14W}},
        {"R15W",    {16,  UC_X86_REG_R15W}},
        {"IDTR",    {80,  UC_X86_REG_IDTR}},
        {"GDTR",    {80,  UC_X86_REG_GDTR}},
        {"LDTR",    {16,  UC_X86_REG_LDTR}},
        {"TR",      {16,  UC_X86_REG_TR}},
        {"FPCW",    {16,  UC_X86_REG_FPCW}},
        {"FPTAG",   {16,  UC_X86_REG_FPTAG}},
        {"MSR",     {64,  UC_X86_REG_MSR}},
        {"MXCSR",   {32,  UC_X86_REG_MXCSR}},
        {"FS_BASE", {64,  UC_X86_REG_FS_BASE}},
        {"GS_BASE", {64,  UC_X86_REG_GS_BASE}},
        {"FLAGS",   {32,  UC_X86_REG_FLAGS}},
        {"RFLAGS",  {64,  UC_X86_REG_RFLAGS}},
        {"FIP",     {64,  UC_X86_REG_FIP}},
        {"FCS",     {16,  UC_X86_REG_FCS}},
        {"FDP",     {64,  UC_X86_REG_FDP}},
        {"FDS",     {16,  UC_X86_REG_FDS}},
        {"FOP",     {16,  UC_X86_REG_FOP}},
};

std::vector<std::string> x86ArchInstructions = {"AAA", "AAD", "AAM", "AAS", "FABS", "ADC", "ADCX", "ADD", "ADDPD", "ADDPS", "ADDSD", "ADDSS", "ADDSUBPD", "ADDSUBPS", "FADD", "FIADD", "ADOX", "AESDECLAST", "AESDEC", "AESENCLAST", "AESENC", "AESIMC", "AESKEYGENASSIST", "AND", "ANDN", "ANDNPD", "ANDNPS", "ANDPD", "ANDPS", "ARPL", "BEXTR", "BLCFILL", "BLCI", "BLCIC", "BLCMSK", "BLCS", "BLENDPD", "BLENDPS", "BLENDVPD", "BLENDVPS", "BLSFILL", "BLSI", "BLSIC", "BLSMSK", "BLSR", "BNDCL", "BNDCN", "BNDCU", "BNDLDX", "BNDMK", "BNDMOV", "BNDSTX", "BOUND", "BSF", "BSR", "BSWAP", "BT", "BTC", "BTR", "BTS", "BZHI", "CALL", "CBW", "CDQ", "CDQE", "FCHS", "CLAC", "CLC", "CLD", "CLDEMOTE", "CLFLUSH", "CLFLUSHOPT", "CLGI", "CLI", "CLRSSBSY", "CLTS", "CLWB", "CLZERO", "CMC", "CMOVA", "CMOVAE", "CMOVB", "CMOVBE", "FCMOVBE", "FCMOVB", "CMOVE", "FCMOVE", "CMOVG", "CMOVGE", "CMOVL", "CMOVLE", "FCMOVNBE", "FCMOVNB", "CMOVNE", "FCMOVNE", "CMOVNO", "CMOVNP", "FCMOVNU", "FCMOVNP", "CMOVNS", "CMOVO", "CMOVP", "FCMOVU", "CMOVS", "CMP", "CMPPD", "CMPPS", "CMPSB", "CMPSD", "CMPSQ", "CMPSS", "CMPSW", "CMPXCHG16B", "CMPXCHG", "CMPXCHG8B", "COMISD", "COMISS", "FCOMP", "FCOMPI", "FCOMI", "FCOM", "FCOS", "CPUID", "CQO", "CRC32", "CVTDQ2PD", "CVTDQ2PS", "CVTPD2DQ", "CVTPD2PS", "CVTPS2DQ", "CVTPS2PD", "CVTSD2SI", "CVTSD2SS", "CVTSI2SD", "CVTSI2SS", "CVTSS2SD", "CVTSS2SI", "CVTTPD2DQ", "CVTTPS2DQ", "CVTTSD2SI", "CVTTSS2SI", "CWD", "CWDE", "DAA", "DAS", "DATA16", "DEC", "DIV", "DIVPD", "DIVPS", "FDIVR", "FIDIVR", "FDIVRP", "DIVSD", "DIVSS", "FDIV", "FIDIV", "FDIVP", "DPPD", "DPPS", "ENCLS", "ENCLU", "ENCLV", "ENDBR32", "ENDBR64", "ENTER", "EXTRACTPS", "EXTRQ", "F2XM1", "LCALL", "LJMP", "JMP", "FBLD", "FBSTP", "FCOMPP", "FDECSTP", "FDISI8087_NOP", "FEMMS", "FENI8087_NOP", "FFREE", "FFREEP", "FICOM", "FICOMP", "FINCSTP", "FLDCW", "FLDENV", "FLDL2E", "FLDL2T", "FLDLG2", "FLDLN2", "FLDPI", "FNCLEX", "FNINIT", "FNOP", "FNSTCW", "FNSTSW", "FPATAN", "FSTPNCE", "FPREM", "FPREM1", "FPTAN", "FRNDINT", "FRSTOR", "FNSAVE", "FSCALE", "FSETPM", "FSINCOS", "FNSTENV", "FXAM", "FXRSTOR", "FXRSTOR64", "FXSAVE", "FXSAVE64", "FXTRACT", "FYL2X", "FYL2XP1", "GETSEC", "GF2P8AFFINEINVQB", "GF2P8AFFINEQB", "GF2P8MULB", "HADDPD", "HADDPS", "HLT", "HSUBPD", "HSUBPS", "IDIV", "FILD", "IMUL", "IN", "INC", "INCSSPD", "INCSSPQ", "INSB", "INSERTPS", "INSERTQ", "INSD", "INSW", "INT", "INT1", "INT3", "INTO", "INVD", "INVEPT", "INVLPG", "INVLPGA", "INVPCID", "INVVPID", "IRET", "IRETD", "IRETQ", "FISTTP", "FIST", "FISTP", "JAE", "JA", "JBE", "JB", "JCXZ", "JECXZ", "JE", "JGE", "JG", "JLE", "JL", "JNE", "JNO", "JNP", "JNS", "JO", "JP", "JRCXZ", "JS", "KADDB", "KADDD", "KADDQ", "KADDW", "KANDB", "KANDD", "KANDNB", "KANDND", "KANDNQ", "KANDNW", "KANDQ", "KANDW", "KMOVB", "KMOVD", "KMOVQ", "KMOVW", "KNOTB", "KNOTD", "KNOTQ", "KNOTW", "KORB", "KORD", "KORQ", "KORTESTB", "KORTESTD", "KORTESTQ", "KORTESTW", "KORW", "KSHIFTLB", "KSHIFTLD", "KSHIFTLQ", "KSHIFTLW", "KSHIFTRB", "KSHIFTRD", "KSHIFTRQ", "KSHIFTRW", "KTESTB", "KTESTD", "KTESTQ", "KTESTW", "KUNPCKBW", "KUNPCKDQ", "KUNPCKWD", "KXNORB", "KXNORD", "KXNORQ", "KXNORW", "KXORB", "KXORD", "KXORQ", "KXORW", "LAHF", "LAR", "LDDQU", "LDMXCSR", "LDS", "FLDZ", "FLD1", "FLD", "LEA", "LEAVE", "LES", "LFENCE", "LFS", "LGDT", "LGS", "LIDT", "LLDT", "LLWPCB", "LMSW", "LOCK", "LODSB", "LODSD", "LODSQ", "LODSW", "LOOP", "LOOPE", "LOOPNE", "RETF", "RETFQ", "LSL", "LSS", "LTR", "LWPINS", "LWPVAL", "LZCNT", "MASKMOVDQU", "MAXPD", "MAXPS", "MAXSD", "MAXSS", "MFENCE", "MINPD", "MINPS", "MINSD", "MINSS", "CVTPD2PI", "CVTPI2PD", "CVTPI2PS", "CVTPS2PI", "CVTTPD2PI", "CVTTPS2PI", "EMMS", "MASKMOVQ", "MOVD", "MOVQ", "MOVDQ2Q", "MOVNTQ", "MOVQ2DQ", "PABSB", "PABSD", "PABSW", "PACKSSDW", "PACKSSWB", "PACKUSWB", "PADDB", "PADDD", "PADDQ", "PADDSB", "PADDSW", "PADDUSB", "PADDUSW", "PADDW", "PALIGNR", "PANDN", "PAND", "PAVGB", "PAVGW", "PCMPEQB", "PCMPEQD", "PCMPEQW", "PCMPGTB", "PCMPGTD", "PCMPGTW", "PEXTRW", "PHADDD", "PHADDSW", "PHADDW", "PHSUBD", "PHSUBSW", "PHSUBW", "PINSRW", "PMADDUBSW", "PMADDWD", "PMAXSW", "PMAXUB", "PMINSW", "PMINUB", "PMOVMSKB", "PMULHRSW", "PMULHUW", "PMULHW", "PMULLW", "PMULUDQ", "POR", "PSADBW", "PSHUFB", "PSHUFW", "PSIGNB", "PSIGND", "PSIGNW", "PSLLD", "PSLLQ", "PSLLW", "PSRAD", "PSRAW", "PSRLD", "PSRLQ", "PSRLW", "PSUBB", "PSUBD", "PSUBQ", "PSUBSB", "PSUBSW", "PSUBUSB", "PSUBUSW", "PSUBW", "PUNPCKHBW", "PUNPCKHDQ", "PUNPCKHWD", "PUNPCKLBW", "PUNPCKLDQ", "PUNPCKLWD", "PXOR", "MONITORX", "MONITOR", "MONTMUL", "MOV", "MOVABS", "MOVAPD", "MOVAPS", "MOVBE", "MOVDDUP", "MOVDIR64B", "MOVDIRI", "MOVDQA", "MOVDQU", "MOVHLPS", "MOVHPD", "MOVHPS", "MOVLHPS", "MOVLPD", "MOVLPS", "MOVMSKPD", "MOVMSKPS", "MOVNTDQA", "MOVNTDQ", "MOVNTI", "MOVNTPD", "MOVNTPS", "MOVNTSD", "MOVNTSS", "MOVSB", "MOVSD", "MOVSHDUP", "MOVSLDUP", "MOVSQ", "MOVSS", "MOVSW", "MOVSX", "MOVSXD", "MOVUPD", "MOVUPS", "MOVZX", "MPSADBW", "MUL", "MULPD", "MULPS", "MULSD", "MULSS", "MULX", "FMUL", "FIMUL", "FMULP", "MWAITX", "MWAIT", "NEG", "NOP", "NOT", "OR", "ORPD", "ORPS", "OUT", "OUTSB", "OUTSD", "OUTSW", "PACKUSDW", "PAUSE", "PAVGUSB", "PBLENDVB", "PBLENDW", "PCLMULQDQ", "PCMPEQQ", "PCMPESTRI", "PCMPESTRM", "PCMPGTQ", "PCMPISTRI", "PCMPISTRM", "PCONFIG", "PDEP", "PEXT", "PEXTRB", "PEXTRD", "PEXTRQ", "PF2ID", "PF2IW", "PFACC", "PFADD", "PFCMPEQ", "PFCMPGE", "PFCMPGT", "PFMAX", "PFMIN", "PFMUL", "PFNACC", "PFPNACC", "PFRCPIT1", "PFRCPIT2", "PFRCP", "PFRSQIT1", "PFRSQRT", "PFSUBR", "PFSUB", "PHMINPOSUW", "PI2FD", "PI2FW", "PINSRB", "PINSRD", "PINSRQ", "PMAXSB", "PMAXSD", "PMAXUD", "PMAXUW", "PMINSB", "PMINSD", "PMINUD", "PMINUW", "PMOVSXBD", "PMOVSXBQ", "PMOVSXBW", "PMOVSXDQ", "PMOVSXWD", "PMOVSXWQ", "PMOVZXBD", "PMOVZXBQ", "PMOVZXBW", "PMOVZXDQ", "PMOVZXWD", "PMOVZXWQ", "PMULDQ", "PMULHRW", "PMULLD", "POP", "POPAW", "POPAL", "POPCNT", "POPF", "POPFD", "POPFQ", "PREFETCH", "PREFETCHNTA", "PREFETCHT0", "PREFETCHT1", "PREFETCHT2", "PREFETCHW", "PREFETCHWT1", "PSHUFD", "PSHUFHW", "PSHUFLW", "PSLLDQ", "PSRLDQ", "PSWAPD", "PTEST", "PTWRITE", "PUNPCKHQDQ", "PUNPCKLQDQ", "PUSH", "PUSHAW", "PUSHAL", "PUSHF", "PUSHFD", "PUSHFQ", "RCL", "RCPPS", "RCPSS", "RCR", "RDFSBASE", "RDGSBASE", "RDMSR", "RDPID", "RDPKRU", "RDPMC", "RDRAND", "RDSEED", "RDSSPD", "RDSSPQ", "RDTSC", "RDTSCP", "REPNE", "REP", "RET", "REX64", "ROL", "ROR", "RORX", "ROUNDPD", "ROUNDPS", "ROUNDSD", "ROUNDSS", "RSM", "RSQRTPS", "RSQRTSS", "RSTORSSP", "SAHF", "SAL", "SALC", "SAR", "SARX", "SAVEPREVSSP", "SBB", "SCASB", "SCASD", "SCASQ", "SCASW", "SETAE", "SETA", "SETBE", "SETB", "SETE", "SETGE", "SETG", "SETLE", "SETL", "SETNE", "SETNO", "SETNP", "SETNS", "SETO", "SETP", "SETSSBSY", "SETS", "SFENCE", "SGDT", "SHA1MSG1", "SHA1MSG2", "SHA1NEXTE", "SHA1RNDS4", "SHA256MSG1", "SHA256MSG2", "SHA256RNDS2", "SHL", "SHLD", "SHLX", "SHR", "SHRD", "SHRX", "SHUFPD", "SHUFPS", "SIDT", "FSIN", "SKINIT", "SLDT", "SLWPCB", "SMSW", "SQRTPD", "SQRTPS", "SQRTSD", "SQRTSS", "FSQRT", "STAC", "STC", "STD", "STGI", "STI", "STMXCSR", "STOSB", "STOSD", "STOSQ", "STOSW", "STR", "FST", "FSTP", "SUB", "SUBPD", "SUBPS", "FSUBR", "FISUBR", "FSUBRP", "SUBSD", "SUBSS", "FSUB", "FISUB", "FSUBP", "SWAPGS", "SYSCALL", "SYSENTER", "SYSEXIT", "SYSEXITQ", "SYSRET", "SYSRETQ", "T1MSKC", "TEST", "TPAUSE", "FTST", "TZCNT", "TZMSK", "UCOMISD", "UCOMISS", "FUCOMPI", "FUCOMI", "FUCOMPP", "FUCOMP", "FUCOM", "UD0", "UD1", "UD2", "UMONITOR", "UMWAIT", "UNPCKHPD", "UNPCKHPS", "UNPCKLPD", "UNPCKLPS", "V4FMADDPS", "V4FMADDSS", "V4FNMADDPS", "V4FNMADDSS", "VADDPD", "VADDPS", "VADDSD", "VADDSS", "VADDSUBPD", "VADDSUBPS", "VAESDECLAST", "VAESDEC", "VAESENCLAST", "VAESENC", "VAESIMC", "VAESKEYGENASSIST", "VALIGND", "VALIGNQ", "VANDNPD", "VANDNPS", "VANDPD", "VANDPS", "VBLENDMPD", "VBLENDMPS", "VBLENDPD", "VBLENDPS", "VBLENDVPD", "VBLENDVPS", "VBROADCASTF128", "VBROADCASTF32X2", "VBROADCASTF32X4", "VBROADCASTF32X8", "VBROADCASTF64X2", "VBROADCASTF64X4", "VBROADCASTI128", "VBROADCASTI32X2", "VBROADCASTI32X4", "VBROADCASTI32X8", "VBROADCASTI64X2", "VBROADCASTI64X4", "VBROADCASTSD", "VBROADCASTSS", "VCMP", "VCMPPD", "VCMPPS", "VCMPSD", "VCMPSS", "VCOMISD", "VCOMISS", "VCOMPRESSPD", "VCOMPRESSPS", "VCVTDQ2PD", "VCVTDQ2PS", "VCVTPD2DQ", "VCVTPD2PS", "VCVTPD2QQ", "VCVTPD2UDQ", "VCVTPD2UQQ", "VCVTPH2PS", "VCVTPS2DQ", "VCVTPS2PD", "VCVTPS2PH", "VCVTPS2QQ", "VCVTPS2UDQ", "VCVTPS2UQQ", "VCVTQQ2PD", "VCVTQQ2PS", "VCVTSD2SI", "VCVTSD2SS", "VCVTSD2USI", "VCVTSI2SD", "VCVTSI2SS", "VCVTSS2SD", "VCVTSS2SI", "VCVTSS2USI", "VCVTTPD2DQ", "VCVTTPD2QQ", "VCVTTPD2UDQ", "VCVTTPD2UQQ", "VCVTTPS2DQ", "VCVTTPS2QQ", "VCVTTPS2UDQ", "VCVTTPS2UQQ", "VCVTTSD2SI", "VCVTTSD2USI", "VCVTTSS2SI", "VCVTTSS2USI", "VCVTUDQ2PD", "VCVTUDQ2PS", "VCVTUQQ2PD", "VCVTUQQ2PS", "VCVTUSI2SD", "VCVTUSI2SS", "VDBPSADBW", "VDIVPD", "VDIVPS", "VDIVSD", "VDIVSS", "VDPPD", "VDPPS", "VERR", "VERW", "VEXP2PD", "VEXP2PS", "VEXPANDPD", "VEXPANDPS", "VEXTRACTF128", "VEXTRACTF32X4", "VEXTRACTF32X8", "VEXTRACTF64X2", "VEXTRACTF64X4", "VEXTRACTI128", "VEXTRACTI32X4", "VEXTRACTI32X8", "VEXTRACTI64X2", "VEXTRACTI64X4", "VEXTRACTPS", "VFIXUPIMMPD", "VFIXUPIMMPS", "VFIXUPIMMSD", "VFIXUPIMMSS", "VFMADD132PD", "VFMADD132PS", "VFMADD132SD", "VFMADD132SS", "VFMADD213PD", "VFMADD213PS", "VFMADD213SD", "VFMADD213SS", "VFMADD231PD", "VFMADD231PS", "VFMADD231SD", "VFMADD231SS", "VFMADDPD", "VFMADDPS", "VFMADDSD", "VFMADDSS", "VFMADDSUB132PD", "VFMADDSUB132PS", "VFMADDSUB213PD", "VFMADDSUB213PS", "VFMADDSUB231PD", "VFMADDSUB231PS", "VFMADDSUBPD", "VFMADDSUBPS", "VFMSUB132PD", "VFMSUB132PS", "VFMSUB132SD", "VFMSUB132SS", "VFMSUB213PD", "VFMSUB213PS", "VFMSUB213SD", "VFMSUB213SS", "VFMSUB231PD", "VFMSUB231PS", "VFMSUB231SD", "VFMSUB231SS", "VFMSUBADD132PD", "VFMSUBADD132PS", "VFMSUBADD213PD", "VFMSUBADD213PS", "VFMSUBADD231PD", "VFMSUBADD231PS", "VFMSUBADDPD", "VFMSUBADDPS", "VFMSUBPD", "VFMSUBPS", "VFMSUBSD", "VFMSUBSS", "VFNMADD132PD", "VFNMADD132PS", "VFNMADD132SD", "VFNMADD132SS", "VFNMADD213PD", "VFNMADD213PS", "VFNMADD213SD", "VFNMADD213SS", "VFNMADD231PD", "VFNMADD231PS", "VFNMADD231SD", "VFNMADD231SS", "VFNMADDPD", "VFNMADDPS", "VFNMADDSD", "VFNMADDSS", "VFNMSUB132PD", "VFNMSUB132PS", "VFNMSUB132SD", "VFNMSUB132SS", "VFNMSUB213PD", "VFNMSUB213PS", "VFNMSUB213SD", "VFNMSUB213SS", "VFNMSUB231PD", "VFNMSUB231PS", "VFNMSUB231SD", "VFNMSUB231SS", "VFNMSUBPD", "VFNMSUBPS", "VFNMSUBSD", "VFNMSUBSS", "VFPCLASSPD", "VFPCLASSPS", "VFPCLASSSD", "VFPCLASSSS", "VFRCZPD", "VFRCZPS", "VFRCZSD", "VFRCZSS", "VGATHERDPD", "VGATHERDPS", "VGATHERPF0DPD", "VGATHERPF0DPS", "VGATHERPF0QPD", "VGATHERPF0QPS", "VGATHERPF1DPD", "VGATHERPF1DPS", "VGATHERPF1QPD", "VGATHERPF1QPS", "VGATHERQPD", "VGATHERQPS", "VGETEXPPD", "VGETEXPPS", "VGETEXPSD", "VGETEXPSS", "VGETMANTPD", "VGETMANTPS", "VGETMANTSD", "VGETMANTSS", "VGF2P8AFFINEINVQB", "VGF2P8AFFINEQB", "VGF2P8MULB", "VHADDPD", "VHADDPS", "VHSUBPD", "VHSUBPS", "VINSERTF128", "VINSERTF32X4", "VINSERTF32X8", "VINSERTF64X2", "VINSERTF64X4", "VINSERTI128", "VINSERTI32X4", "VINSERTI32X8", "VINSERTI64X2", "VINSERTI64X4", "VINSERTPS", "VLDDQU", "VLDMXCSR", "VMASKMOVDQU", "VMASKMOVPD", "VMASKMOVPS", "VMAXPD", "VMAXPS", "VMAXSD", "VMAXSS", "VMCALL", "VMCLEAR", "VMFUNC", "VMINPD", "VMINPS", "VMINSD", "VMINSS", "VMLAUNCH", "VMLOAD", "VMMCALL", "VMOVQ", "VMOVAPD", "VMOVAPS", "VMOVDDUP", "VMOVD", "VMOVDQA32", "VMOVDQA64", "VMOVDQA", "VMOVDQU16", "VMOVDQU32", "VMOVDQU64", "VMOVDQU8", "VMOVDQU", "VMOVHLPS", "VMOVHPD", "VMOVHPS", "VMOVLHPS", "VMOVLPD", "VMOVLPS", "VMOVMSKPD", "VMOVMSKPS", "VMOVNTDQA", "VMOVNTDQ", "VMOVNTPD", "VMOVNTPS", "VMOVSD", "VMOVSHDUP", "VMOVSLDUP", "VMOVSS", "VMOVUPD", "VMOVUPS", "VMPSADBW", "VMPTRLD", "VMPTRST", "VMREAD", "VMRESUME", "VMRUN", "VMSAVE", "VMULPD", "VMULPS", "VMULSD", "VMULSS", "VMWRITE", "VMXOFF", "VMXON", "VORPD", "VORPS", "VP4DPWSSDS", "VP4DPWSSD", "VPABSB", "VPABSD", "VPABSQ", "VPABSW", "VPACKSSDW", "VPACKSSWB", "VPACKUSDW", "VPACKUSWB", "VPADDB", "VPADDD", "VPADDQ", "VPADDSB", "VPADDSW", "VPADDUSB", "VPADDUSW", "VPADDW", "VPALIGNR", "VPANDD", "VPANDND", "VPANDNQ", "VPANDN", "VPANDQ", "VPAND", "VPAVGB", "VPAVGW", "VPBLENDD", "VPBLENDMB", "VPBLENDMD", "VPBLENDMQ", "VPBLENDMW", "VPBLENDVB", "VPBLENDW", "VPBROADCASTB", "VPBROADCASTD", "VPBROADCASTMB2Q", "VPBROADCASTMW2D", "VPBROADCASTQ", "VPBROADCASTW", "VPCLMULQDQ", "VPCMOV", "VPCMP", "VPCMPB", "VPCMPD", "VPCMPEQB", "VPCMPEQD", "VPCMPEQQ", "VPCMPEQW", "VPCMPESTRI", "VPCMPESTRM", "VPCMPGTB", "VPCMPGTD", "VPCMPGTQ", "VPCMPGTW", "VPCMPISTRI", "VPCMPISTRM", "VPCMPQ", "VPCMPUB", "VPCMPUD", "VPCMPUQ", "VPCMPUW", "VPCMPW", "VPCOM", "VPCOMB", "VPCOMD", "VPCOMPRESSB", "VPCOMPRESSD", "VPCOMPRESSQ", "VPCOMPRESSW", "VPCOMQ", "VPCOMUB", "VPCOMUD", "VPCOMUQ", "VPCOMUW", "VPCOMW", "VPCONFLICTD", "VPCONFLICTQ", "VPDPBUSDS", "VPDPBUSD", "VPDPWSSDS", "VPDPWSSD", "VPERM2F128", "VPERM2I128", "VPERMB", "VPERMD", "VPERMI2B", "VPERMI2D", "VPERMI2PD", "VPERMI2PS", "VPERMI2Q", "VPERMI2W", "VPERMIL2PD", "VPERMILPD", "VPERMIL2PS", "VPERMILPS", "VPERMPD", "VPERMPS", "VPERMQ", "VPERMT2B", "VPERMT2D", "VPERMT2PD", "VPERMT2PS", "VPERMT2Q", "VPERMT2W", "VPERMW", "VPEXPANDB", "VPEXPANDD", "VPEXPANDQ", "VPEXPANDW", "VPEXTRB", "VPEXTRD", "VPEXTRQ", "VPEXTRW", "VPGATHERDD", "VPGATHERDQ", "VPGATHERQD", "VPGATHERQQ", "VPHADDBD", "VPHADDBQ", "VPHADDBW", "VPHADDDQ", "VPHADDD", "VPHADDSW", "VPHADDUBD", "VPHADDUBQ", "VPHADDUBW", "VPHADDUDQ", "VPHADDUWD", "VPHADDUWQ", "VPHADDWD", "VPHADDWQ", "VPHADDW", "VPHMINPOSUW", "VPHSUBBW", "VPHSUBDQ", "VPHSUBD", "VPHSUBSW", "VPHSUBWD", "VPHSUBW", "VPINSRB", "VPINSRD", "VPINSRQ", "VPINSRW", "VPLZCNTD", "VPLZCNTQ", "VPMACSDD", "VPMACSDQH", "VPMACSDQL", "VPMACSSDD", "VPMACSSDQH", "VPMACSSDQL", "VPMACSSWD", "VPMACSSWW", "VPMACSWD", "VPMACSWW", "VPMADCSSWD", "VPMADCSWD", "VPMADD52HUQ", "VPMADD52LUQ", "VPMADDUBSW", "VPMADDWD", "VPMASKMOVD", "VPMASKMOVQ", "VPMAXSB", "VPMAXSD", "VPMAXSQ", "VPMAXSW", "VPMAXUB", "VPMAXUD", "VPMAXUQ", "VPMAXUW", "VPMINSB", "VPMINSD", "VPMINSQ", "VPMINSW", "VPMINUB", "VPMINUD", "VPMINUQ", "VPMINUW", "VPMOVB2M", "VPMOVD2M", "VPMOVDB", "VPMOVDW", "VPMOVM2B", "VPMOVM2D", "VPMOVM2Q", "VPMOVM2W", "VPMOVMSKB", "VPMOVQ2M", "VPMOVQB", "VPMOVQD", "VPMOVQW", "VPMOVSDB", "VPMOVSDW", "VPMOVSQB", "VPMOVSQD", "VPMOVSQW", "VPMOVSWB", "VPMOVSXBD", "VPMOVSXBQ", "VPMOVSXBW", "VPMOVSXDQ", "VPMOVSXWD", "VPMOVSXWQ", "VPMOVUSDB", "VPMOVUSDW", "VPMOVUSQB", "VPMOVUSQD", "VPMOVUSQW", "VPMOVUSWB", "VPMOVW2M", "VPMOVWB", "VPMOVZXBD", "VPMOVZXBQ", "VPMOVZXBW", "VPMOVZXDQ", "VPMOVZXWD", "VPMOVZXWQ", "VPMULDQ", "VPMULHRSW", "VPMULHUW", "VPMULHW", "VPMULLD", "VPMULLQ", "VPMULLW", "VPMULTISHIFTQB", "VPMULUDQ", "VPOPCNTB", "VPOPCNTD", "VPOPCNTQ", "VPOPCNTW", "VPORD", "VPORQ", "VPOR", "VPPERM", "VPROLD", "VPROLQ", "VPROLVD", "VPROLVQ", "VPRORD", "VPRORQ", "VPRORVD", "VPRORVQ", "VPROTB", "VPROTD", "VPROTQ", "VPROTW", "VPSADBW", "VPSCATTERDD", "VPSCATTERDQ", "VPSCATTERQD", "VPSCATTERQQ", "VPSHAB", "VPSHAD", "VPSHAQ", "VPSHAW", "VPSHLB", "VPSHLDD", "VPSHLDQ", "VPSHLDVD", "VPSHLDVQ", "VPSHLDVW", "VPSHLDW", "VPSHLD", "VPSHLQ", "VPSHLW", "VPSHRDD", "VPSHRDQ", "VPSHRDVD", "VPSHRDVQ", "VPSHRDVW", "VPSHRDW", "VPSHUFBITQMB", "VPSHUFB", "VPSHUFD", "VPSHUFHW", "VPSHUFLW", "VPSIGNB", "VPSIGND", "VPSIGNW", "VPSLLDQ", "VPSLLD", "VPSLLQ", "VPSLLVD", "VPSLLVQ", "VPSLLVW", "VPSLLW", "VPSRAD", "VPSRAQ", "VPSRAVD", "VPSRAVQ", "VPSRAVW", "VPSRAW", "VPSRLDQ", "VPSRLD", "VPSRLQ", "VPSRLVD", "VPSRLVQ", "VPSRLVW", "VPSRLW", "VPSUBB", "VPSUBD", "VPSUBQ", "VPSUBSB", "VPSUBSW", "VPSUBUSB", "VPSUBUSW", "VPSUBW", "VPTERNLOGD", "VPTERNLOGQ", "VPTESTMB", "VPTESTMD", "VPTESTMQ", "VPTESTMW", "VPTESTNMB", "VPTESTNMD", "VPTESTNMQ", "VPTESTNMW", "VPTEST", "VPUNPCKHBW", "VPUNPCKHDQ", "VPUNPCKHQDQ", "VPUNPCKHWD", "VPUNPCKLBW", "VPUNPCKLDQ", "VPUNPCKLQDQ", "VPUNPCKLWD", "VPXORD", "VPXORQ", "VPXOR", "VRANGEPD", "VRANGEPS", "VRANGESD", "VRANGESS", "VRCP14PD", "VRCP14PS", "VRCP14SD", "VRCP14SS", "VRCP28PD", "VRCP28PS", "VRCP28SD", "VRCP28SS", "VRCPPS", "VRCPSS", "VREDUCEPD", "VREDUCEPS", "VREDUCESD", "VREDUCESS", "VRNDSCALEPD", "VRNDSCALEPS", "VRNDSCALESD", "VRNDSCALESS", "VROUNDPD", "VROUNDPS", "VROUNDSD", "VROUNDSS", "VRSQRT14PD", "VRSQRT14PS", "VRSQRT14SD", "VRSQRT14SS", "VRSQRT28PD", "VRSQRT28PS", "VRSQRT28SD", "VRSQRT28SS", "VRSQRTPS", "VRSQRTSS", "VSCALEFPD", "VSCALEFPS", "VSCALEFSD", "VSCALEFSS", "VSCATTERDPD", "VSCATTERDPS", "VSCATTERPF0DPD", "VSCATTERPF0DPS", "VSCATTERPF0QPD", "VSCATTERPF0QPS", "VSCATTERPF1DPD", "VSCATTERPF1DPS", "VSCATTERPF1QPD", "VSCATTERPF1QPS", "VSCATTERQPD", "VSCATTERQPS", "VSHUFF32X4", "VSHUFF64X2", "VSHUFI32X4", "VSHUFI64X2", "VSHUFPD", "VSHUFPS", "VSQRTPD", "VSQRTPS", "VSQRTSD", "VSQRTSS", "VSTMXCSR", "VSUBPD", "VSUBPS", "VSUBSD", "VSUBSS", "VTESTPD", "VTESTPS", "VUCOMISD", "VUCOMISS", "VUNPCKHPD", "VUNPCKHPS", "VUNPCKLPD", "VUNPCKLPS", "VXORPD", "VXORPS", "VZEROALL", "VZEROUPPER", "WAIT", "WBINVD", "WBNOINVD", "WRFSBASE", "WRGSBASE", "WRMSR", "WRPKRU", "WRSSD", "WRSSQ", "WRUSSD", "WRUSSQ", "XABORT", "XACQUIRE", "XADD", "XBEGIN", "XCHG", "FXCH", "XCRYPTCBC", "XCRYPTCFB", "XCRYPTCTR", "XCRYPTECB", "XCRYPTOFB", "XEND", "XGETBV", "XLATB", "XOR", "XORPD", "XORPS", "XRELEASE", "XRSTOR", "XRSTOR64", "XRSTORS", "XRSTORS64", "XSAVE", "XSAVE64", "XSAVEC", "XSAVEC64", "XSAVEOPT", "XSAVEOPT64", "XSAVES", "XSAVES64", "XSETBV", "XSHA1", "XSHA256", "XSTORE", "XTEST"};

std::string x86IPStr(const uc_mode mode){
    switch (mode) {
        case UC_MODE_16:
            return "IP";
        case UC_MODE_32:
            return "EIP";
        case UC_MODE_64:
            return "RIP";
        default:
            return "";
    }
}

std::pair<std::string, std::string> x86SBPStr(const uc_mode mode){
    switch (mode) {
        case UC_MODE_16:
            return {"SP", "BP"};
        case UC_MODE_32:
            return {"ESP", "EBP"};
        case UC_MODE_64:
            return {"RSP", "RBP"};
        default:
            return {"", ""};
    }
}

bool x86IsRegisterValid(const std::string& reg, const uc_mode mode){
    std::string registerName = reg;
    if (registerName.contains("[") && registerName.contains(":") && registerName.contains("]")){
        registerName = registerName.substr(0, registerName.find_first_of('['));
    }

    if (!x86RegInfoMap.contains(registerName)){
        return false;
    }

    switch (mode){
        case UC_MODE_16:
            if (x86RegInfoMap[registerName].first == 16){
                return true;
            }

            if (x86RegInfoMap[registerName].first > 16){
                return false;
            }

            break;
        case UC_MODE_32:
            if (!registerName.contains("ST") || (!registerName.contains("XMM"))){
                if (registerName.starts_with("XMM") && registerName.length() > 3) {
                    const int suffix = atoi(registerName.substr(3).c_str());
                    if (suffix > 7) {
                        return false;
                    }
                }

                if (x86RegInfoMap[registerName].first == 32){
                    return true;
                }
                if (x86RegInfoMap[registerName].first > 32){
                    return false;
                }
            }
            else {
                if (x86RegInfoMap.contains(registerName)){
                    return true;
                }
            }
            break;
        case UC_MODE_64:
            if (!registerName.contains("ST") || (!registerName.contains("MM") || (!registerName.contains("XMM")) ||
                (!registerName.contains("YMM")) || (!registerName.contains("ZMM")))){

                if ((registerName.starts_with("XMM") || registerName.starts_with("YMM")) && registerName.length() > 3) {
                    const int suffix = atoi(registerName.substr(3).c_str());
                    if (suffix > 15) {
                        return false;
                    }
                }
                else if (registerName.starts_with("ZMM")) {
                    const int suffix = atoi(registerName.substr(3).c_str());
                    if (suffix > 31) {
                        return false;
                    }
                }

                if (x86RegInfoMap[registerName].first == 64){
                    return true;
                }
                if (x86RegInfoMap[registerName].first == 128){
                    return true;
                }
            }
        default: ;
    }
    return true;
}

void x86ModeUpdateCallback(const uc_mode mode){
    switch (mode) {
        case UC_MODE_16:
            x86DefaultShownRegs = x86DefaultShownRegs16;
            break;
        case UC_MODE_32:
            x86DefaultShownRegs = x86DefaultShownRegs32;
            break;
        case UC_MODE_64:
            x86DefaultShownRegs = x86DefaultShownRegs64;
            break;
        default: ;
    }
}