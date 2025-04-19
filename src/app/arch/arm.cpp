#include "arm.hpp"
#include "../../utils/stringHelper.hpp"

std::vector<std::string> armDefaultShownRegs = {
    "PC", "SP", "LR", "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10", "R11", "R12", "CPSR"
};

std::vector<std::string> aarch64DefaultShownRegs = {
    "PC", "SP", "LR", "X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7", "X8", "X9", "X10", "X11", "X12", 
    "X13", "X14", "X15", "X16", "X17", "X18", "X19", "X20", "X21", "X22", "X23", "X24", "X25", "X26", 
    "X27", "X28", "X29", "X30", "NZCV"
};

// ARM register info mapping with register size in bits
std::unordered_map<std::string, size_t> armRegInfoMap = {
    {"invalid", 0},
    {"cpsr", 32},
    {"d0", 64},
    {"d1", 64},
    {"d10", 64},
    {"d11", 64},
    {"d12", 64},
    {"d13", 64},
    {"d14", 64},
    {"d15", 64},
    {"d16", 64},
    {"d17", 64},
    {"d18", 64},
    {"d19", 64},
    {"d2", 64},
    {"d20", 64},
    {"d21", 64},
    {"d22", 64},
    {"d23", 64},
    {"d24", 64},
    {"d25", 64},
    {"d26", 64},
    {"d27", 64},
    {"d28", 64},
    {"d29", 64},
    {"d3", 64},
    {"d30", 64},
    {"d31", 64},
    {"d4", 64},
    {"d5", 64},
    {"d6", 64},
    {"d7", 64},
    {"d8", 64},
    {"d9", 64},
    {"lr", 32},
    {"pc", 32},
    {"q0", 128},
    {"q1", 128},
    {"q10", 128},
    {"q11", 128},
    {"q12", 128},
    {"q13", 128},
    {"q14", 128},
    {"q15", 128},
    {"q2", 128},
    {"q3", 128},
    {"q4", 128},
    {"q5", 128},
    {"q6", 128},
    {"q7", 128},
    {"q8", 128},
    {"q9", 128},
    {"r0", 32},
    {"r1", 32},
    {"r2", 32},
    {"r3", 32},
    {"r4", 32},
    {"r5", 32},
    {"r6", 32},
    {"r7", 32},
    {"r8", 32},
    {"s0", 32},
    {"s1", 32},
    {"s10", 32},
    {"s11", 32},
    {"s12", 32},
    {"s13", 32},
    {"s14", 32},
    {"s15", 32},
    {"s16", 32},
    {"s17", 32},
    {"s18", 32},
    {"s19", 32},
    {"s2", 32},
    {"s20", 32},
    {"s21", 32},
    {"s22", 32},
    {"s23", 32},
    {"s24", 32},
    {"s25", 32},
    {"s26", 32},
    {"s27", 32},
    {"s28", 32},
    {"s29", 32},
    {"s3", 32},
    {"s30", 32},
    {"s31", 32},
    {"s4", 32},
    {"s5", 32},
    {"s6", 32},
    {"s7", 32},
    {"s8", 32},
    {"s9", 32},
    {"sp", 32},
    {"spsr", 32},
};

std::unordered_map<std::string, size_t> aarch64RegInfoMap = {
    {"invalid", 0},
    {"d0", 64},
    {"d1", 64},
    {"d10", 64},
    {"d11", 64},
    {"d12", 64},
    {"d13", 64},
    {"d14", 64},
    {"d15", 64},
    {"d16", 64},
    {"d17", 64},
    {"d18", 64},
    {"d19", 64},
    {"d2", 64},
    {"d20", 64},
    {"d21", 64},
    {"d22", 64},
    {"d23", 64},
    {"d24", 64},
    {"d25", 64},
    {"d26", 64},
    {"d27", 64},
    {"d28", 64},
    {"d29", 64},
    {"d3", 64},
    {"d30", 64},
    {"d31", 64},
    {"d4", 64},
    {"d5", 64},
    {"d6", 64},
    {"d7", 64},
    {"d8", 64},
    {"d9", 64},
    {"lr", 32},
    {"nzcv", 32},
    {"q0", 128},
    {"q1", 128},
    {"q10", 128},
    {"q11", 128},
    {"q12", 128},
    {"q13", 128},
    {"q14", 128},
    {"q15", 128},
    {"q16", 128},
    {"q17", 128},
    {"q18", 128},
    {"q19", 128},
    {"q2", 128},
    {"q20", 128},
    {"q21", 128},
    {"q22", 128},
    {"q23", 128},
    {"q24", 128},
    {"q25", 128},
    {"q26", 128},
    {"q27", 128},
    {"q28", 128},
    {"q29", 128},
    {"q3", 128},
    {"q30", 128},
    {"q31", 128},
    {"q4", 128},
    {"q5", 128},
    {"q6", 128},
    {"q7", 128},
    {"q8", 128},
    {"q9", 128},
    {"s0", 32},
    {"s1", 32},
    {"s10", 32},
    {"s11", 32},
    {"s12", 32},
    {"s13", 32},
    {"s14", 32},
    {"s15", 32},
    {"s16", 32},
    {"s17", 32},
    {"s18", 32},
    {"s19", 32},
    {"s2", 32},
    {"s20", 32},
    {"s21", 32},
    {"s22", 32},
    {"s23", 32},
    {"s24", 32},
    {"s25", 32},
    {"s26", 32},
    {"s27", 32},
    {"s28", 32},
    {"s29", 32},
    {"s3", 32},
    {"s30", 32},
    {"s31", 32},
    {"s4", 32},
    {"s5", 32},
    {"s6", 32},
    {"s7", 32},
    {"s8", 32},
    {"s9", 32},
    {"sp", 32},
    {"w0", 32},
    {"w1", 32},
    {"w10", 32},
    {"w11", 32},
    {"w12", 32},
    {"w13", 32},
    {"w14", 32},
    {"w15", 32},
    {"w16", 32},
    {"w17", 32},
    {"w18", 32},
    {"w19", 32},
    {"w2", 32},
    {"w20", 32},
    {"w21", 32},
    {"w22", 32},
    {"w23", 32},
    {"w24", 32},
    {"w25", 32},
    {"w26", 32},
    {"w27", 32},
    {"w28", 32},
    {"w29", 32},
    {"w3", 32},
    {"w30", 32},
    {"w4", 32},
    {"w5", 32},
    {"w6", 32},
    {"w7", 32},
    {"w8", 32},
    {"w9", 32},
    {"wzr", 32},
    {"x0", 64},
    {"x1", 64},
    {"x10", 64},
    {"x11", 64},
    {"x12", 64},
    {"x13", 64},
    {"x14", 64},
    {"x15", 64},
    {"x16", 64},
    {"x17", 64},
    {"x18", 64},
    {"x19", 64},
    {"x2", 64},
    {"x20", 64},
    {"x21", 64},
    {"x22", 64},
    {"x23", 64},
    {"x24", 64},
    {"x25", 64},
    {"x26", 64},
    {"x27", 64},
    {"x28", 64},
    {"x3", 64},
    {"x4", 64},
    {"x5", 64},
    {"x6", 64},
    {"x7", 64},
    {"x8", 64},
    {"x9", 64},
    {"xzr", 64},
};

// Basic ARM architecture instructions
std::vector<std::string> aarch64ArchInstructions = {
"SSUBLB", "AESIMC", "LDSMAXL", "UADDWT", "SMINV", "ADR", "REVH", "DSB", "ST2", "XPACLRI", "SQRSHL", "SQSUB", "ORNS", "PACNBIASPPC", "SXTW", "LDNT1SW", "CMN", "LD1RW", "FMOV", "LD3", "LDADDL", "UQSHRNT", "SMADDL", "CPYFEWN", "BRB", "SABDLT", "CNT", "SADALP", "AUTIBSPPCR", "USUBLT", "SQRSHRUNT", "RCWSCAS", "BF1CVT", "ST3", "SUMOPA", "DMB", "LDFF1B", "CPYMT", "SUQADD", "AUTIBZ", "FCCMP", "SQSUB", "UQADD", "SQDECB", "ST2", "F1CVTL", "PFIRST", "SXTL", "SSHL", "STGP", "CMLS", "SSUBLT", "SQDMLSLT", "FLOGB", "FRINT32X", "CPYFEWT", "RCWSSETL", "UUNPKHI", "STNT1B", "CPYERTWN", "SLI", "ZIPQ1", "SETET", "CPYFPT", "STNT1W", "LDRSW", "AUTIA1716", "FSUBR", "LDNT1D", "LDEORAL", "CPYFPWN", "LD3", "SMULL", "AUTIBSP", "LDSETALH", "RDFFRS", "UHSUBR", "RCWSWPP", "SXTL2", "RCWSSWPP", "SUBG", "FCMUO", "STADDB", "ADD", "UQRSHRN2", "AUTIZB", "LDXP", "SMIN", "SHRNT", "BFMLSLT", "TCANCEL", "CPYFMTRN", "URSQRTE", "UMLSLB", "LD2", "PEXT", "ST4", "TBX", "FCMEQ", "UQDECH", "LDCLRL", "LD3H", "LDEORAH", "GCSPOPCX", "LD1D", "UMLSL", "SRSRA", "FTMAD", "UXTL", "EORBT", "YIELD", "LDUMINL", "RCWCLRAL", "ST1", "PACNBIBSPPC", "ST2", "PMULL", "LD1", "EOR", "LDUMAXALB", "LDEORB", "FDOT", "STTRH", "RCWCASPL", "SQINCP", "UZP", "BFMMLA", "RCWSCLRAL", "SMLALT", "F1CVTL2", "BFCVTNT", "FCVTN2", "SUVDOT", "RADDHN", "LDXRH", "SQDMLALBT", "CPYFMWN", "SHADD", "SABALB", "F2CVTL2", "CPYFMRTWN", "SYS", "UVDOT", "FCMEQ", "NGC", "SHSUBR", "MRS", "CPYP", "UMADDL", "ADDHN", "FMLALLTB", "FMAXNMQV", "FCVTZU", "FRECPX", "LDRAA", "UHSUB", "LDSMINH", "CPYMRTRN", "SWPPA", "PMUL", "STILP", "SUBS", "SVC", "SUMOPS", "UQSHRN", "CASAL", "LD1R", "RCWSCASPA", "LDRH", "NOTS", "WRFFR", "CBZ", "SABA", "CRC32H", "CCMN", "ST2D", "STLLRH", "FCMLA", "LD1W", "SMINV", "CSINV", "FCMGT", "MSRR", "WHILELO", "ST3", "MOV", "AUTDA", "UQXTN", "LDARB", "CPYMWTN", "CPYFPRTRN", "LDSETAH", "ORR", "LD3R", "LIFETIME_START", "SMLALL", "RCWSETL", "ADC", "LDSMAXAL", "ST2", "MUL", "UZP1", "USHLLT", "LDXR", "FMINNMP", "FCVTX", "LDFF1SW", "UABDL2", "LDSETP", "ST1D", "LD1R", "LDUMINLB", "FRINTM", "LDEORA", "CPYETN", "SWPL", "SQDMLSLBT", "AUTIB1716", "BFM", "FNMLS", "FABS", "GCSSS1", "FCLAMP", "FRINT32Z", "FRINTP", "LD2R", "UADDLT", "STTR", "LDAPUR", "FMINP", "LD3", "FMINNMV", "LD3R", "CPYFERTRN", "LDEORAB", "LDADD", "ST1", "FCMPE", "SSUBL", "LDCLRALB", "LDNF1D", "FCMLT", "ST1", "FRINT64X", "CPYPRTN", "SWPPAL", "FMULX", "COMPACT", "LD1H", "WFE", "AUTIZA", "FADDQV", "FCVTNU", "CPYEWTN", "SRSHR", "CPYFMWTWN", "SETPTN", "MOVI", "PHINODE", "SETP", "CPYFERTN", "LUTI4", "UADDWB", "BFMLALT", "LDP", "MADPT", "SQABS", "SQINCW", "REVB", "BFMLA", "LD3", "USUBL", "FDOT", "WFET", "STSMAXL", "BF2CVTL2", "SQSHLU", "ST4", "RCWSWPPL", "FCMEQ", "LD4R", "CASP", "ROR", "ST3", "SMSUBL", "SQDMULLB", "SMOPA", "BIT", "LD4", "CMPGT", "RCWSSWPAL", "BICS", "CPYFPTRN", "SQCVTUN", "SDOT", "FCMLT", "RETAA", "CPYPWTRN", "FMAXNMV", "UXTL", "ST64B", "LD2Q", "CMLO", "FMAXNMP", "LDCLRB", "LDSMINA", "STSMINL", "CPYFE", "SETGM", "ASRV", "ST2", "PRFUM", "ADDHNB", "SQSHL", "CBNZ", "LDNT1SB", "UDIVR", "CPYFPRTN", "SADALP", "SETMT", "STG", "SBCS", "FCMLE", "LDAPR", "LD2R", "CMLO", "CPYFMN", "LD1", "SMULH", "BFDOT", "FCVTPU", "SHRNB", "CPYM", "ST4", "MSR", "LD3R", "CAS", "EORV", "SPLICE", "LDUMAXL", "PUNPKHI", "LDADDALH", "CPYEN", "FCVTMS", "SADDWB", "UZP2", "HISTCNT", "CMLA", "STP", "FMLALL", "FMLSLB", "LD1", "NOT", "LD1RQB", "RCWSCLR", "ST4Q", "STUMINLB", "BRABZ", "CADD", "RCWSWPL", "LD4", "LDSMAXB", "LD4Q", "USHR", "SETGPTN", "STSMAXLH", "WFIT", "SMLAL2", "ORR", "UQCVT", "ADDPL", "LD4R", "CSNEG", "LD2", "FRINTX", "LD1R", "LDCLRAL", "RSHRN", "FCVTZS", "SQDMLSL", "CRC32X", "SETGPT", "SRSHLR", "SQDMULL", "SSUBWB", "AUTIASPPCR", "SADDLBT", "BFMLALB", "SQXTN", "LDLARB", "RADDHN2", "CLZ", "LDNF1SB", "UXTL", "FSUB", "UXTW", "BL", "RDFFR", "UADALP", "STURB", "UMULLB", "CMPHS", "CPYFMWT", "BIC", "ADDHA", "FRINTI", "LSR", "PACM", "SXTL2", "SETGET", "CPYFPN", "SQSHLR", "BRKPBS", "FNMAD", "CINV", "CASAH", "LDTRSB", "ST1", "LDAP1", "BSL1N", "MVN", "LDSMINALH", "STCLR", "SQDMULH", "FDIV", "URSHR", "LDUMAXH", "INCH", "LDADDB", "BRKB", "DRPS", "SQRSHLR", "FMAXNMP", "LDCLRAB", "SMINP", "LSRV", "FMUL", "LDNF1SH", "UQXTN", "CMHS", "MSUBPT", "ST2", "ZERO", "SQSHRUNB", "FAMIN", "LSRR", "RCWCLRL", "SQSHRN", "UADDLP", "CPYPT", "RPRFM", "FCSEL", "FMLS", "STSETLH", "LD2", "LD3W", "SHL", "WHILELE", "TBNZ", "EOR", "UABALT", "CLREX", "BFMUL", "LDSETH", "PACIASPPC", "LDTRB", "SETETN", "MOVZ", "LDUR", "PACIA1716", "UMLSL", "CPYFEWTWN", "STSMAXLB", "LD4R", "LASTA", "LDSMINB", "LDUMAXLB", "SSHLLB", "LD3", "RCWSSETPL", "SWPPL", "AESMC", "SXTB", "LDSETPAL", "SUBHN2", "DUPM", "SMMLA", "LDSETAB", "ZIP1", "SETF16", "ST3", "PACIA", "CNTW", "LD2H", "UMAXV", "MRRS", "XPACI", "RDVL", "STR", "BEXT", "SMSTOP", "SADDV", "CINC", "SETPT", "FCMEQ", "ST4B", "FADD", "LD1R", "FRINTZ", "LD2", "SQDMLSL2", "LDUMINAB", "CMHI", "STXRB", "USUBW2", "FCMGT", "LD4", "LD3", "MOVAZ", "TRN2", "UQSHRN", "UMLAL", "BRKNS", "FCMLT", "MLS", "RDSVL", "SRSHR", "BFMMLA", "STEORL", "LD2", "MLS", "TBX", "XPACD", "SXTL", "SADDLP", "ST3", "LDCLRPA", "UQSUB", "SM3SS1", "LDSMIN", "SABD", "FRECPE", "FACGE", "NANDS", "BFCLAMP", "LDSETAL", "RSHRNB", "AESD", "MLA", "CASALH", "FCVT", "LDAPURSW", "BFCVTN", "CPYFMRT", "SETMTN", "SADDLT", "LD1R", "MOVPRFX", "DFB", "DCPS3", "UABALB", "LD1RH", "UMULL", "SYSL", "CLS", "ADDP", "CPYMTN", "SQSHRUN2", "ST3", "CRC32CH", "LDNF1SW", "LD4", "CCMP", "LD2", "LDADDH", "RADDHNT", "BRKAS", "STSMIN", "SEV", "LDUMINB", "URHADD", "UMLALL", "LDAXRB", "LDUMAXAH", "SSUBLTB", "RCWSCASAL", "SMLSL2", "LD1SH", "SABALT", "RCWSCASA", "SHLL2", "FCMP", "RCWCLRA", "PRFD", "RCWSSET", "STCLRB", "HISTSEG", "SQSHRN2", "USHLL", "CSEL", "UMMLA", "UMULL2", "MOVI", "LDR", "SQRSHRUN2", "LDEORALB", "PTRUE", "FMLALB", "FMINQV", "RCWCLRPAL", "SCLAMP", "FCVTL2", "NMATCH", "LD4R", "CNT", "LSL", "STZ2G", "STEORB", "ST3B", "STSETB", "FSCALE", "MOVI", "SQRDMLAH", "MOVI", "ST1", "STSMINB", "CMPNE", "USUBWT", "LDTRSH", "LDCLR", "SQXTUN2", "FCMGE", "FMINNM", "LDEORH", "ADDP", "SMLSLL", "FCMLE", "ADDS", "FCVTNS", "CPYFEN", "LD64B", "FRSQRTS", "UABD", "RCWSETPAL", "FCMGE", "BRKN", "UMLAL2", "UMULLT", "LDUMAXLH", "LD4R", "PMOV", "LDADDLH", "FCMNE", "CPYFMTN", "RCWCLRPA", "STRH", "SQRSHRUN", "FACLT", "CLASTB", "PACIZB", "CPYE", "FMLAL2", "TRN2", "LDFF1SH", "FMAXP", "FMLALLBB", "LD1RQD", "USHR", "MVNI", "FMAXNM", "LDCLRPL", "AUTIB171615", "LSLV", "SQSUBR", "RCWSSWPPAL", "LDSETPL", "GCSSTR", "UMLSL2", "UZP2", "LD4H", "WHILEGE", "LD4", "CPYERN", "USUBL2", "SQDMULL2", "ST3Q", "STURH", "LD3", "F1CVTL", "FCVTAU", "LD1RB", "ORN", "UMULL", "FCMGE", "SABDLB", "TBLQ", "LD1SB", "LDAXR", "SXTL2", "LDSMAXALH", "SABD", "LDNF1H", "SDIVR", "CASH", "CMEQ", "GCSPUSHX", "SQSHRN", "USUBLB", "UMINV", "STXRH", "INCB", "CPYFPWTWN", "SQDECP", "RCWCLR", "UQCVTN", "SHA1C", "CTERMNE", "SMLSL", "RCWSETA", "UABDLT", "NOR", "STZGM", "SWPAB", "ERET", "CPYMRTN", "HLT", "STEOR", "MOVI", "SADDWT", "LDUMAXB", "SADDLB", "LDNT1B", "SB", "CRC32CW", "UQSHL", "ADCLT", "MVNI", "ST3", "FDIVR", "SRI", "CPYPTWN", "STUMAXLB", "FVDOTT", "FMLALLTB", "SQRSHRN", "PACDB", "FCVTXN", "FCVTXNT", "LDCLRH", "RCWSSETPA", "USDOT", "UXTB", "CPYFEWTN", "DECB", "RETAB", "BFVDOT", "REV64", "UQRSHRN", "RMIF", "SSUBW2", "ST1", "ST3W", "UQADD", "USRA", "FCVTAS", "UDOT", "SETFFR", "FSCALE", "SWPB", "FRINT32Z", "LDUMAXAB", "BIC", "WHILEHS", "FACLT", "DECH", "USRA", "SYSP", "SDOT", "LDSMINALB", "SLI", "UQSUB", "RCWSSETAL", "CPYFERT", "UBFM", "ST3", "ST3", "STNT1H", "FNEG", "CMTST", "SEVL", "UQRSHL", "SABAL2", "STEORLH", "UMLALT", "MSUB", "SMAXP", "FMINNMV", "SQSHRUNT", "F2CVTL", "UMMLA", "LDADDALB", "EORQV", "FRINTX", "CMHS", "FMLAL", "CPYPRT", "MOVT", "STNT1D", "LDUMINALH", "URSHLR", "MLA", "SQDMLSL", "LDCLRPAL", "BRKPB", "FCVTPS", "ZIP", "UHSUB", "LD4", "SQDMLAL2", "UMINP", "FMOPS", "GCSSS2", "FCCMPE", "LDSMINAB", "CNTP", "LD1", "LDNT1SH", "RAX1", "CNEG", "BGRP", "SETGPN", "LDEORLB", "FRINTM", "LDSMAXAB", "SWPP", "FCMLT", "STEORH", "ST1", "SHSUB", "FMAXNM", "UMAX", "ADDV", "UQSHLR", "FACLE", "ZIP2", "ST1", "CPYPRTRN", "FMLALLBB", "SHA1M", "CPYFP", "BRK", "SQSHRUN", "FABD", "FMINNMP", "FCMGT", "CPYPWTN", "FAMAX", "SRSHL", "CPYFETN", "BF2CVTL", "UMIN", "UXTH", "PNEXT", "TRCIT", "UDF", "MOVN", "RCWCASP", "ZIP1", "ORQV", "FMSB", "ST4", "ST2", "FMMLA", "RCWSCLRL", "UMAXP", "F2CVTL", "LDSMINAL", "PACIASP", "UXTL2", "XAR", "F1CVT", "SQXTUN", "BFMLSLB", "ST4", "LDSETLH", "LD1", "FABS", "ADDSVL", "LDSETL", "SQNEG", "ST4", "SHA512H2", "DECD", "ORR", "CTZ", "CASPL", "FMULX", "FDIV", "CDOT", "CMTST", "LDLAR", "SQRDMLSH", "ST1", "SMAXQV", "FMINP", "PACIBZ", "LDUMAXALH", "SQXTUNT", "LD3R", "CLZ", "LDAXP", "SMMLA", "PMULL2", "WHILEWR", "SETE", "ADDHN2", "SQCVT", "SUB", "RCWSETAL", "PACGA", "LD1RQH", "SM4E", "UXTL2", "SETGE", "LD", "UABDLB", "CPYMRT", "STUMINH", "FMINNM", "STTRB", "SQRSHL", "RCWSCLRA", "FRSQRTE", "UADDL2", "LUTI2", "FCVTNS", "LDSMINLB", "FAMIN", "UUNPK", "SRHADD", "FRINTA", "FMLAL", "SQRSHR", "UMAXQV", "SXTL", "LD2R", "FMOV", "FMINNMQV", "LDEORLH", "TBL", "STXR", "LD1R", "CPYPWT", "FSUB", "LDUMINLH", "CASPA", "GCSB", "SETPN", "SQXTN2", "PRFH", "STADD", "SBCLB", "SMLSLB", "LD4W", "FMLA", "FCVTMS", "SRI", "UQRSHLR", "BF2CVTL", "BUNDLE", "RCWSCASPAL", "LD2D", "FCMEQ", "PSB", "BLR", "STSETL", "LD1RSH", "CLS", "RCWCLRP", "LD1", "FMLALLBT", "SQRDCMLAH", "BR", "PTRUES", "UHADD", "LDTR", "CPYPTN", "RCWSET", "SXTL", "DCPS2", "FCVTN", "CPYFMRTRN", "UQXTN2", "FCMEQ", "CPYEWTRN", "NEGS", "PMULLB", "SSHLLT", "STLUR", "LD4", "SMLAL", "FCVTAU", "SHA1P", "DECW", "BIC", "PMULLT", "SHA256SU1", "LDURSH", "FMUL", "UMOV", "CASB", "FCVTPS", "FNMADD", "F2CVTLT", "ST2", "FRINTA", "FMLSLT", "ST3", "FMAXP", "SUDOT", "UADDW2", "FCVTZU", "ST3", "LDNT1W", "SUB", "FNEG", "SM3TT2B", "UMSUBL", "LDSMAXH", "UQSHL", "TRN1", "LD3R", "LDNF1W", "F1CVTLT", "UADDLB", "FMLS", "RCWSSETP", "LDUMINAH", "SMLAL", "SQDMULLT", "ORR", "MVNI", "EXTR", "USQADD", "SQRSHRU", "FCADD", "TBXQ", "AESMC", "CPYFPRN", "DECP", "FCMLT", "FMLALLTT", "SUBR", "SMOV", "FACLE", "CASPAL", "CPYMTRN", "EORS", "SQXTN", "FMAXQV", "DUP", "USHLLB", "SSUBL2", "TBL", "STUMAXB", "REVD", "RBIT", "CMPLS", "LDSMAXLH", "ST2H", "LD1ROD", "SUBPT", "SCVTF", "UMINP", "STUMAX", "LDUMINA", "AUTIA", "SQDECW", "SSUBWT", "SWPLB", "STLURH", "BRKPA", "FMINV", "TSTART", "ST3D", "AUTIBSPPC", "STLXRB", "CNTH", "LD2", "FMAX", "CPYEWT", "USUBW", "PACIB171615", "ST4W", "LD1ROH", "CSDB", "LD2B", "CMGT", "UMINQV", "LDUMAX", "LD3R", "ST2", "ADDQV", "STSETLB", "UABAL", "UQRSHRNT", "CPYFPTWN", "LD4", "UDIV", "ADDVA", "BFMLALB", "LDAPRH", "SQCADD", "CPYFERN", "UQINCB", "CMLE", "MOVI", "SUBHNB", "STSMAXB", "RET", "FRINTP", "ST3", "SHA1H", "LDAR", "SABAL", "PACIA171615", "SMULLB", "TSB", "FMLSL", "ADDPT", "RCWSWPPAL", "SQSHL", "LDUMINALB", "ST2", "RCWSWPPA", "LD4R", "STCLRL", "LD1RQW", "LD2R", "FCVTL", "AUTIASPPC", "DBG_INSTR_REF", "CPYETWN", "FMIN", "CSETM", "ADD", "LDXRB", "UQRSHL", "LDCLRA", "UMLAL", "UHADD", "ADCLB", "LDUMIN", "RCWSETPL", "CPYEWN", "ADRP", "ST1", "BFADD", "STNP", "FCVTZS", "LDURH", "LDSETB", "SADDW2", "CPYMN", "FCVTMU", "UQDECW", "CMLS", "GCSPOPX", "URECPE", "DBG_VALUE_LIST", "CMLE", "SCVTF", "FCMLE", "LDSMAX", "RBIT", "LDUMINAL", "BMOPA", "SABDL", "SUQADD", "RCWSETP", "LDCLRALH", "BSL", "RCWSWPAL", "AND", "FRECPS", "LD4B", "TRN1", "SSBB", "LD4R", "SM4EKEY", "RSHRN2", "CMPLE", "MLAPT", "SUBHN", "SSHR", "FSQRT", "SDIV", "LDFF1H", "LDNT1H", "LDFF1D", "LDSMINL", "CTERMEQ", "ORR", "AESE", "FNMLA", "FMINV", "SETGEN", "CNTB", "LDAPURB", "ADCS", "FCMGT", "REV32", "SHA256SU0", "BFMAXNM", "RSUBHNB", "CNOT", "LD4", "LD2R", "SQINCH", "LD4D", "SQDECH", "CMLE", "FCVTNT", "NOT", "SMULLT", "FADDP", "ERETAB", "CPYMWTWN", "SETM", "PSEUDO_PROBE", "SADDL2", "CPYMRN", "SMULL2", "LDEORL", "RCWSSWPL", "LDLARH", "UMLSLT", "CPYPRN", "USMOPS", "FADD", "SUNPKHI", "AUTIB", "BRKPAS", "LD1R", "SQDMULH", "CLRBHB", "FRINT32X", "PACIAZ", "SETGETN", "FRINT64Z", "LDG", "FCMLE", "STGM", "LASTB", "FRINTN", "CPYFEWTRN", "SETGP", "BRKA", "USMMLA", "ST2W", "NGCS", "ADDG", "SQXTUN", "FCMGE", "SQCVTN", "SWPAL", "CMLT", "WHILERW", "BFMLALT", "URSRA", "SADDL", "ST1Q", "LD3R", "MVNI", "STUR", "ST64BV0", "UUNPKLO", "USDOT", "CASL", "STADDLH", "EXT", "FCMEQ", "ANDQV", "CPYFPRTWN", "LDADDA", "LDSET", "CPYFMRTN", "FRINTN", "BLRAB", "SMAXP", "LD3Q", "FCMGT", "LDSMAXALB", "USHL", "FCMLE", "FRINTZ", "STSMINLB", "LD2", "FMAXV", "SQRSHRNB", "SETMN", "STSMAX", "USMLALL", "CPYPWTWN", "LDADDAB", "LDAPURH", "BF1CVTL", "AUTDZB", "IRG", "FRINT64X", "INS", "CPYFET", "LD3", "RETABSPPC", "SQCVTU", "BCAX", "UABA", "LDNP", "ADDHNT", "ERETAA", "UADDW", "UXTL", "", "SHSUB", "BF1CVTL", "SQSHRNT", "FACGT", "LDAPURSB", "ORN", "FJCVTZS", "F2CVT", "SVDOT", "FADDV", "LD3", "ST4H", "STLRH", "SHA1SU1", "AUTDB", "CPYMRTWN", "RSUBHN", "UZPQ2", "LDURSB", "UMIN", "FSQRT", "CMPP", "MOVS", "", "BFCVT", "RADDHNB", "UQINCD", "ST2Q", "STCLRH", "SHA512SU0", "LDADDLB", "STUMINB", "INCW", "LDUMAXAL", "SRSHL", "FRECPE", "SBFM", "WHILEGT", "EXTQ", "MOV", "NAND", "SM3TT2A", "LDFF1W", "SQSHRUN", "FCVTNU", "LD1", "MVNI", "STUMAXL", "BSL2N", "CLASTA", "LDURSW", "CMGE", "BLRAAZ", "EXT", "RAX1", "STLXRH", "ADDVL", "SUBPS", "ADDSPL", "AND", "LD2R", "PACIB", "CPYERT", "SQRSHRNT", "BLRAA", "URHADD", "RCWCASPA", "SRSRA", "RSHRNT", "ST4", "FVDOT", "LD4R", "LDCLRAH", "AESIMC", "RCWCLRPL", "SSHLL", "LD1B", "FCVTLT", "NEG", "INDEX", "TCOMMIT", "STUMIN", "UABDL", "FCMLT", "RCWCASL", "STSMAXH", "FADDA", "LDEORALH", "FCMLE", "CPYFPTN", "FCVTNB", "WHILELT", "LD4R", "SQDMLALT", "SQRSHRUNB", "USUBWB", "RCWSCLRPA", "UQXTNB", "DBG_VALUE", "SBCLT", "LDSMINAH", "FCMGT", "STADDL", "CPYFETWN", "RCWSSETA", "SHLL", "FCPY", "MVNI", "LD1", "LDCLRP", "URECPE", "BFMAX", "ST2B", "RCWSCLRPAL", "PACDZA", "RCWCASA", "AUTIAZ", "LD1RSB", "MUL", "UQRSHRNB", "NOP", "LD1ROW", "CPYFPWTRN", "AUTIASP", "BRAB", "SABDL2", "FMAXNMV", "INSR", "LDIAPP", "UADALP", "SMAXV", "UQSUBR", "NBSL", "REV64", "SSHLL2", "STSET", "CPYET", "UQINCW", "SQXTNT", "ST1", "FDUP", "UABD", "CPYMWT", "FRECPS", "LDTRH", "UABAL2", "NORS", "LDAPURSH", "SMLSLT", "TBX", "STLLR", "BFCVTN", "XAR", "LDRSB", "USMOPA", "CPYMWN", "EOR3", "STZG", "UMAXV", "PRFW", "AXFLAG", "UXTL2", "NEG", "RCWSSWP", "LD1", "CHKFEAT", "SETGMT", "SUMLALL", "CPYFMT", "SQDMLALB", "LDSETLB", "STADDH", "SUBP", "LD1", "RETAASPPCR", "SQRDMULH", "GCSPOPM", "SMLALB", "STCLRLH", "FADDP", "FRSQRTS", "LDRSH", "SQABS", "LDRAB", "FVDOTB", "DBG_PHI", "SQADD", "UMULH", "CRC32W", "CPYFMRN", "RCWCAS", "SABA", "RCWSSWPA", "CMPLO", "SSHR", "CPYFPWTN", "STLR", "ST2", "BRAA", "UQRSHR", "LDSETA", "CPYFERTWN", "SBC", "BCAX", "ST2G", "BIC", "LDADDAL", "EON", "DUP", "SMAX", "CSINC", "LD4", "LDSETPA", "RCWSSWPPA", "AESE", "CPYEWTWN", "CPYPN", "SWPA", "FMAX", "SRHADD", "LDCLRLB", "SSUBLBT", "FCMLT", "UADDLV", "URSRA", "MADDPT", "FMAD", "SMAX", "SQXTUNB", "PFALSE", "LD2", "SMIN", "FMLSL", "LDSMAXA", "CMHI", "FNMSUB", "FCVTN2", "ST64BV", "SHADD", "UMNEGL", "RCWCASPAL", "DGH", "SWPAH", "LDUMAXA", "LDUMINH", "REV16", "LD2", "FRINTI", "FCMGE", "SQRSHRN2", "RCWSCLRPL", "USHLL2", "RETAASPPC", "CFINV", "WFI", "FCMLT", "SQRSHRN", "STSETH", "UMLALB", "CPYFMTWN", "UQINCP", "FMLALB", "RCWSSETPAL", "CPYFMWTN", "ANDS", "UMINV", "ORV", "TBZ", "UMOPS", "XTN2", "CSET", "URSHL", "SHA256H", "UDOT", "LD2W", "LD2R", "CPYMTWN", "FNMSB", "FTSMUL", "CMPLT", "CMPHI", "CPYFPRT", "BIC", "FCMGE", "FEXPA", "SM3TT1B", "CMEQ", "SM3PARTW1", "LD1RD", "SM4EKEY", "RCWSWP", "BF1CVTLT", "FMIN", "UCVTF", "EORTB", "GCSPUSHM", "LD1SW", "RCWSWPA", "SMLSL", "STLXR", "SMAXV", "ORRS", "USQADD", "FACGT", "FACGE", "LD3D", "SHRN", "LD1R", "ST1", "SADDW", "LD2R", "RCWSETPA", "GCSSTTR", "LD2R", "ZIP2", "FMSUB", "SXTL2", "PSSBB", "SWPALH", "TBL", "MATCH", "SQRDMLSH", "FMLALT", "CASLB", "DCPS1", "RCWSCASL", "BFMINNM", "STUMINLH", "PUNPKLO", "REV16", "URSHL", "LD3R", "LDEOR", "BFSUB", "RSUBHN2", "SQADD", "UMOPA", "STCLRLB", "SHA512SU1", "BFCVTN2", "FMAXV", "REVW", "UQSHRN2", "CPYETRN", "SUBHNT", "FCVTXN2", "PMUL", "UMOV", "GMI", "CRC32CB", "STEORLB", "FTSSEL", "REV", "LD1RSW", "CPYFETRN", "SHL", "FMLALLBT", "SQSHRNB", "STUMAXLH", "STUMINL", "UADDL", "RCWSCLRP", "CRC32CX", "FCADD", "PACDZB", "MADD", "DUPQ", "SSRA", "BIC", "PACIBSPPC", "TST", "URSHR", "CMLT", "SUNPK", "LD1", "FCMGT", "CPYERTRN", "SHA256H2", "SUNPKLO", "FABD", "USHL", "UQSHRNB", "CMP", "UQRSHRN", "CPYPWN", "BRAAZ", "ZIPQ2", "BFMLSL", "SQDMLAL", "PRFM", "AUTIA171615", "FCVTPU", "ABS", "INCP", "LD1ROB", "SMINQV", "BF2CVTLT", "FCMLE", "BF2CVT", "LDFF1SB", "SQRDMLAH", "UZP1", "FRSQRTE", "CASALB", "MOVK", "CPYFMWTRN", "FMLSL2", "MOVA", "SMINP", "LDSMINLH", "SM3PARTW2", "FCVTAS", "FMLALT", "SHA512H", "LDURB", "ORR", "ESB", "LD4", "CASLH", "CASAB", "SHRN2", "SETF8", "LD1", "CPY", "LDSMAXLB", "LDADDAH", "SSUBW", "FCMGE", "SMULL", "STRB", "LD1Q", "PACIZA", "SQDMLAL", "STLLRB", "PACDA", "SQDMLSLB", "LDCLRLH", "SETGMTN", "SMC", "CRC32B", "SWPH", "LD2", "SQXTNB", "CMGT", "LDTRSW", "LDPSW", "LD3B", "ASR", "CMPEQ", "ANDV", "RCWSCASP", "SM4E", "UADDV", "FCVTMU", "SMSTART", "STSMINH", "INS", "INCD", "ASRR", "SETGMN", "CASA", "TTEST", "WHILELS", "LD4", "UMAXP", "PRFB", "UQXTNT", "ST4D", "LIFETIME_END", "SQSHLU", "FAMAX", "RORV", "SQNEG", "BFMIN", "EOR3", "MAD", "BDEP", "RCWSSWPPL", "XAFLAG", "UQDECB", "STLRB", "SQDECD", "LDARH", "FCMLE", "BFMOPS", "CMPGE", "ST4", "UQDECP", "LD2", "USMMLA", "PTEST", "LDNF1B", "STLURB", "MNEG", "ST1W", "LD3", "CPYPTRN", "USVDOT", "FMOPA", "UCVTF", "SQRDMULH", "ST4", "RCWCASAL", "SM3TT1A", "UCLAMP", "ST4", "SXTH", "UMLSLL", "RETABSPPCR", "SETEN", "PACIB1716", "UXTL2", "XTN", "UQDECD", "UABA", "STADDLB", "CPYMWTRN", "WHILEHI", "FMLA", "LDRB", "LDSMAXAH", "FMLALLTT", "REV32", "CMGE", "ST2", "PACIBSP", "UMAX", "BIF", "CNTD", "BFDOT", "SQINCB", "FNMUL", "FRINT64Z", "SMOPS", "ST3H", "BSL", "PSEL", "SMOV", "SQRSHRUN", "BFMOPA", "ST4", "RCWSCASPL", "FMADD", "UQINCH", "SEL", "LSLR", "HVC", "SQINCD", "STUMAXH", "SSHL", "BRKBS", "SSRA", "B", "ASRD", "SUDOT", "ST1H", "SWP", "MVN", "SWPALB", "SQDMULL", "CPYFPWT", "LD3", "BF1CVTL2", "ISB", "SADDLV", "CPYPRTWN", "LDAXRH", "CPYERTN", "STXP", "AESD", "ABS", "SWPLH", "CMLT", "SMNEGL", "BLRABZ", "AUTDZA", "LD3", "UZPQ1", "ST1B", "URSQRTE", "SHA1SU0", "BMOPS", "FCMLA", "LDAPRB", "STLXP", "LDGM", "ST4", "CPYFM", "LD3R", "BFMLS", "BTI", "LD1", "LD1R", "HINT", "BFMLAL", "RSUBHNT", "LDSETALB", "STSMINLH", "MSB", "ST1", "STL1"
};

std::vector<std::string> armArchInstructions = {"ADDS", "VCVTA", "LDREXD", "VEXT", "VMRS", "STLEXH", "SWPB", "TTAT", "EOR", "VLD40", "LDREX", "AES", "VMULLB", "VSTRW", "VQABS", "VQMOVNT", "VRECPS", "CSINC", "VLDMDB", "VMLADAVAX", "VQDMLSDH", "SHA256SU0", "LDRSHT", "MRC2", "R12,", "VSTMIA", "VRMLSLDAVHAX", "SXTAB16", "CRC32", "VQRSHRNB", "VLSTM", "VMINV", "VABAV", "VRSUBHN", "VMLAL", "SMMLSR", "VSLI", "VQDMLADH", "VMLA", "BFX", "SMLALTT", "QSUB", "VJCVT", "VRINTA", "SADD16", "VADC", "VQMOVUN", "LDAH", "VLD43", "VST41", "MOVT", "VMOVNT", "VMAXNMA", "SQSHL", "VNMUL", "BFCSEL", "VABD", "UQSHL", "VRSHR", "VFMAS", "VST4", "CSINV", "STMDB", "SXTH", "LDRHT", "VRMLSLDAVHX", "VST21", "VSTRH", "VTBX", "ISB", "VMLSDAV", "VHCADD", "WFE", "STM", "VSELEQ", "VQMOVUNT", "UXTH", "LDMDB", "QADD16", "USAX", "SMLSD", "VMLSLDAV", "LDAEXD", "PSSBB", "BFLX", "DLS", "CLREX", "DCPS2", "SADD8", "RSC", "SHASX", "LDAB", "MCR", "UXTAB16", "VADDVA", "PUSH", "VADDL", "VFNMA", "SRSIB", "SMULTB", "FMSTAT", "BLXNS", "MOVS", "CMN", "VMLSDAVAX", "SEVL", "VMVN", "SHSAX", "DMB", "LDRD", "QADD8", "SMLABT", "SRSDA", "SMUADX", "VRINTZ", "UQSAX", "HVC", "ORR", "VCX3", "VQSHLU", "ROR", "UHASX", "AESMC", "LDAEX", "VQRDMLADHX", "SRSIA", "VQSHRN", "SBFX", "VQRDMLSH", "UMULL", "SSAT16", "SHA256SU1", "VQDMLAL", "VSUDOT", "SHA1SU1", "PLDW", "VPT", "SHA", "STC", "VCX1A", "CBZ", "CLZ", "STREXB", "SMLAWB", "VFMAB", "VCNT", "REV16", "VACGT", "VMLALDAVA", "UXTAB", "VSHRN", "VUDOT", "VREV32", "STRBT", "VADD", "PLD", "VPST", "SEV", "AESE", "VCMUL", "VRADDHN", "UXTAH", "MVN", "FMDLR", "UMAAL", "SHADD16", "FCONSTS", "CRC32CH", "AESIMC", "DLSTP", "VLDRD", "SMC", "VADDW", "MRS", "VSHR", "VDDUP", "SHA1P", "VPOP", "RFEDB", "BL", "CX1DA", "SETPAN", "SMLAL", "VCX3A", "CSNEG", "VQDMLSDHX", "SMLSLD", "VQDMLADHX", "VBIF", "VINS", "LDRB", "SMLALBT", "SHSUB16", "QSUB16", "AND", "VQRSHRUNT", "VQSHRNB", "FSUBD", "VMLALVA", "VSHLL", "VMULL", "SMULBT", "VRMULH", "SHA1M", "UADD8", "CLRBHB", "DSB", "VFMA", "UXTB", "VSCCLRM{", "SHADD8", "VNEG", "RRX", "SVC", "VMLALV", "VQDMULH", "FADDD", "VLDMIA", "SWP", "STC2", "CX3A", "LDMIB", "LSRL", "SMUSD", "VCMP", "VRINT", "SHA1C", "VHADD", "CX3", "UMLAL", "VQDMLASH", "SMUSDX", "VRSQRTS", "VQRSHRUNB", "VST1", "MCRR2", "QADD", "TBB", "VRSQRTE", "VREV16", "POP", "VDWDUP", "USUB16", "PACBTI", "VRINTX", "VRMLALDAVH", "VMAXV", "TT", "VMOV", "SMMULR", "UHADD8", "SMMLA", "BFI", "VMAXNM", "VRMLALDAVHX", "VPNOT", "VCX2", "CX3DA", "CINV", "SHA256H2", "CX2", "FCMPZS", "SBC", "CX2DA", "UADD16", "VRSRA", "RFEDA", "VPADDL", "VCLE", "VBRSR", "LDR", "UHSUB16", "VLD2", "VMINNMAV", "VMULH", "VST2", "CSEL", "STC2L", "VSHLC", "LSRS", "CX1", "VST40", "CRC32CW", "BFC", "VRMLALDAVHA", "LETP", "VPMAX", "SMMUL", "VCVTP", "MCRR", "USUB8", "ADD", "VSHL", "VQRDMLSDHX", "UDIV", "VMLADAVX", "VZIP", "TBH", "VQDMULLB", "LDRSH", "VTBL", "VMOVX", "AUT", "LDM", "VCX1", "VMLALDAVAX", "VPADAL", "VSTRD", "VSUBHN", "IT", "MOV", "CSDB", "LDREXB", "UQADD16", "ADR", "URSHR", "ADR{", "VLD42", "ERET", "MRRC", "VLDRB", "MRC", "VST3", "MCR2", "VABDL", "VRSHRNB", "VMLAS", "UQRSHL", "VNMLS", "SMLSDX", "BX", "VMAXNMV", "SXTB16", "VSTR", "SMLATT", "VMLADAVA", "VHSUB", "VRSHRNT", "LDRBT", "VQSHRNT", "UBFX", "VSELGT", "VMOVLB", "FCMPZD", "CRC32W", "TTA", "BXAUT", "VST20", "CPS", "DCPS3", "CRC32B", "VMLSLDAVAX", "FSTMIAX", "PKHBT", "VQRSHRNT", "SXTAH", "VPADD", "ORN", "LDC2L", "MUL", "HLT", "VCADD", "VTRN", "VRINTM", "VSBCI", "VSHRNT", "SHA1H", "SMULBB", "VLD20", "VMLALDAV", "SXTB", "VLD41", "CSETM", "VST42", "SMLABB", "MLS", "SMMLS", "VMINAV", "RSB", "SMMLAR", "TRAP", "VPUSH", "LCTP", "VADCI", "VCGT", "VCLT", "WLSTP", "VCVTM", "VMOVN", "VRINTR", "VLD4", "VQSHRUNT", "VMLAV", "VCTP", "TEQ", "RBIT", "VCVTT", "VRMLSLDAVHA", "VCLS", "SSUB8", "LSL", "STLB", "VMLSDAVX", "CX1A", "VABAL", "SMLAWT", "B", "FCONSTD", "QDSUB", "SHA1SU0", "VRHADD", "SETEND", "BXJ", "VLDRH", "VACGE", "RFEIB", "BTI", "QDADD", "STRB", "SUB", "VADDHN", "VRECPE", "VCGE", "LDA", "STREXH", "VSTMDB", "CX1D", "VQDMLAH", "AUTG", "ASRS", "VMSR", "STREX", "CRC32H", "VSUBL", "LDC2", "VQSHRUN", "ASRL", "FMDHR", "VSRI", "VUSDOT", "PAC", "UASX", "VLD3", "PKHTB", "VSDOT", "VCX2A", "VQMOVNB", "STLEX", "SHSUB8", "WLS", "FSTMDBX", "VST43", "VNMLA", "BIC", "STLEXB", "VADDLVA", "VCVTB", "ADDW", "QSAX", "LDREXH", "BLX", "BXNS", "STRD", "USAD8", "LDAEXH", "VUSMMLA", "SSUB16", "VEOR", "VSHLLT", "VMLS", "VSBC", "LSR", "VFMAL", "STREXD", "VSRA", "SMULWT", "VADDV", "VUMMLA", "WFI", "YIELD", "TSB", "VDIV", "VMINNMV", "VRSHRN", "MSR", "SMLATB", "STRT", "VMLALDAVX", "VABA", "MRRC2", "CSET", "TTT", "VQRDMLSDH", "VLDR", "VRMLSLDAVH", "VFMSL", "DBG", "NEG", "VQSHRUNB", "CX3D", "VMOVLT", "VRMLALVHA", "SQSHLL", "SUBW", "VQRDMULH", "VACLT", "VMMLA", "CDP", "VSMMLA", "VIWDUP", "USADA8", "VRINTN", "VSUB", "STL", "VMAXAV", "DFB", "VQRSHRN", "STCL", "STLEXD", "UXTB16", "VQRDMLAH", "VQSHL", "HINT", "VMLSDAVA", "VTST", "STMDA", "LDRSB", "SG", "SUBS", "VMINNMA", "STLH", "VQRSHRUN", "VACLE", "UHSAX", "SSAT", "UHADD16", "VCVTN", "VCVTR", "VRSHL", "LDRT", "STR", "VBSL", "PACG", "VQDMULL", "LDMDA", "VMUL", "VMLSL", "VQRDMLASH", "VMLSLDAVA", "VMAX", "UDF", "VQMOVUNB", "SMULTT", "SMUAD", "SDIV", "LDC", "VRMLALDAVHAX", "SQRSHRL", "VMIN", "VRMLALVH", "VMAXNMAV", "CBNZ", "STRH", "VIDUP", "LDRSBT", "UQRSHLL", "VQMOVN", "UQASX", "VCVT", "VSQRT", "TST", "CX2D", "SASX", "PLI", "VDUP", "UQSHLL", "VCLZ", "SRSDB", "RFEIA", "UQSUB16", "VBIC", "ASR", "VQDMULLT", "REV", "NOP", "VSHLLB", "VQADD", "CDP2", "VMLSLDAVX", "VORR", "VLD21", "FLDMIAX", "VREV64", "SMLALBB", "VLD1", "VCEQ", "VPMIN", "DCPS1", "FSUBS", "ADC", "SQRSHR", "QSUB8", "SRSHRL", "VMINA", "BKPT", "REVSH", "CINC", "ESB", "SXTAB", "LSLL", "VQNEG", "SMLALD", "UQADD8", "VLLDM", "VFMAT", "VMINNM", "VSWP", "VCMLA", "CNEG", "SEL", "SMLADX", "SSAX", "VMOVL", "VUZP", "VMAXA", "LDRH", "USAT16", "SMLAD", "VRINTP", "LDAEXB", "BFL", "SMULWB", "VQRDMLADH", "SMLALTB", "MOVW", "VQDMLSL", "VQRSHL", "VCMPE", "VFNMS", "CLRM", "SHA256H", "USAT", "UHSUB8", "SB", "URSHRL", "FLDMDBX", "LE", "VMOVNB", "VSELGE", "VQSUB", "VSTRB", "VAND", "SMLALDX", "FADDS", "UQSUB8", "VBIT", "VMLAVA", "VMLADAV", "SSBB", "CMP", "VSUBW", "STRHT", "VSELVS", "BF", "VLDRW", "LDCL", "SMLSLDX", "VFMS", "CX2A", "AESD", "STMIB", "SRSHR", "CRC32CB", "VABS", "VADDLV", "SMULL", "VORN", "VSHRNB", "MLA", "VDOT", "VPSEL", "VMULLT", "QASX", "BEQ",    "BNE",    "BHS",    "BLO",    "BMI",    "BPL",    "BVS",    "BVC",    "BHI",    "BLS",    "BGE",    "BLT",    "BGT",    "BLE",    "B", "ADC", "ADD", "ADDW", "ADR", "AESD", "AESE", "AESIMC", "AESMC", "AND", "ASR", "B", "BFC", "BFI", "BIC", "BKPT", "BL", "BLX", "BLXNS", "BX", "BXJ", "BXNS", "CBNZ", "CBZ", "CDP", "CDP2", "CLREX", "CLZ", "CMN", "CMP", "CPS", "CRC32B", "CRC32CB", "CRC32CH", "CRC32CW", "CRC32H", "CRC32W", "CSDB", "DBG", "DCPS1", "DCPS2", "DCPS3", "DFB", "DMB", "DSB", "EOR", "ERET", "ESB", "FADDD", "FADDS", "FCMPZD", "FCMPZS", "FCONSTD", "FCONSTS", "FLDMDBX", "FLDMIAX", "FMDHR", "FMDLR", "FMSTAT", "FSTMDBX", "FSTMIAX", "FSUBD", "FSUBS", "HINT", "HLT", "HVC", "ISB", "IT", "LDA", "LDAB", "LDAEX", "LDAEXB", "LDAEXD", "LDAEXH", "LDAH", "LDC", "LDC2", "LDC2L", "LDCL", "LDM", "LDMDA", "LDMDB", "LDMIB", "LDR", "LDRB", "LDRBT", "LDRD", "LDREX", "LDREXB", "LDREXD", "LDREXH", "LDRH", "LDRHT", "LDRSB", "LDRSBT", "LDRSH", "LDRSHT", "LDRT", "LSL", "LSR", "MCR", "MCR2", "MCRR", "MCRR2", "MLA", "MLS", "MOV", "MOVS", "MOVT", "MOVW", "MRC", "MRC2", "MRRC", "MRRC2", "MRS", "MSR", "MUL", "MVN", "NEG", "NOP", "ORN", "ORR", "PKHBT", "PKHTB", "PLD", "PLDW", "PLI", "POP", "PUSH", "QADD", "QADD16", "QADD8", "QASX", "QDADD", "QDSUB", "QSAX", "QSUB", "QSUB16", "QSUB8", "RBIT", "REV", "REV16", "REVSH", "RFEDA", "RFEDB", "RFEIA", "RFEIB", "ROR", "RRX", "RSB", "RSC", "SADD16", "SADD8", "SASX", "SBC", "SBFX", "SDIV", "SEL", "SETEND", "SETPAN", "SEV", "SEVL", "SG", "SHA1C", "SHA1H", "SHA1M", "SHA1P", "SHA1SU0", "SHA1SU1", "SHA256H", "SHA256H2", "SHA256SU0", "SHA256SU1", "SHADD16", "SHADD8", "SHASX", "SHSAX", "SHSUB16", "SHSUB8", "SMC", "SMLABB", "SMLABT", "SMLAD", "SMLADX", "SMLAL", "SMLALBB", "SMLALBT", "SMLALD", "SMLALDX", "SMLALTB", "SMLALTT", "SMLATB", "SMLATT", "SMLAWB", "SMLAWT", "SMLSD", "SMLSDX", "SMLSLD", "SMLSLDX", "SMMLA", "SMMLAR", "SMMLS", "SMMLSR", "SMMUL", "SMMULR", "SMUAD", "SMUADX", "SMULBB", "SMULBT", "SMULL", "SMULTB", "SMULTT", "SMULWB", "SMULWT", "SMUSD", "SMUSDX", "SRSDA", "SRSDB", "SRSIA", "SRSIB", "SSAT", "SSAT16", "SSAX", "SSUB16", "SSUB8", "STC", "STC2", "STC2L", "STCL", "STL", "STLB", "STLEX", "STLEXB", "STLEXD", "STLEXH", "STLH", "STM", "STMDA", "STMDB", "STMIB", "STR", "STRB", "STRBT", "STRD", "STREX", "STREXB", "STREXD", "STREXH", "STRH", "STRHT", "STRT", "SUB", "SUBS", "SUBW", "SVC", "SWP", "SWPB", "SXTAB", "SXTAB16", "SXTAH", "SXTB", "SXTB16", "SXTH", "TBB", "TBH", "TEQ", "TRAP", "TSB", "TST", "TT", "TTA", "TTAT", "TTT", "UADD16", "UADD8", "UASX", "UBFX", "UDF", "UDIV", "UHADD16", "UHADD8", "UHASX", "UHSAX", "UHSUB16", "UHSUB8", "UMAAL", "UMLAL", "UMULL", "UQADD16", "UQADD8", "UQASX", "UQSAX", "UQSUB16", "UQSUB8", "USAD8", "USADA8", "USAT", "USAT16", "USAX", "USUB16", "USUB8", "UXTAB", "UXTAB16", "UXTAH", "UXTB", "UXTB16", "UXTH", "VABA", "VABAL", "VABD", "VABDL", "VABS", "VACGE", "VACGT", "VACLE", "VACLT", "VADD", "VADDHN", "VADDL", "VADDW", "VAND", "VBIC", "VBIF", "VBIT", "VBSL", "VCADD", "VCEQ", "VCGE", "VCGT", "VCLE", "VCLS", "VCLT", "VCLZ", "VCMLA", "VCMP", "VCMPE", "VCNT", "VCVT", "VCVTA", "VCVTB", "VCVTM", "VCVTN", "VCVTP", "VCVTR", "VCVTT", "VDIV", "VDUP", "VEOR", "VEXT", "VFMA", "VFMS", "VFNMA", "VFNMS", "VHADD", "VHSUB", "VINS", "VJCVT", "VLD1", "VLD2", "VLD3", "VLD4", "VLDMDB", "VLDMIA", "VLDR", "VLLDM", "VLSTM", "VMAX", "VMAXNM", "VMIN", "VMINNM", "VMLA", "VMLAL", "VMLS", "VMLSL", "VMOV", "VMOVL", "VMOVN", "VMOVX", "VMRS", "VMSR", "VMUL", "VMULL", "VMVN", "VNEG", "VNMLA", "VNMLS", "VNMUL", "VORN", "VORR", "VPADAL", "VPADD", "VPADDL", "VPMAX", "VPMIN", "VPOP", "VPUSH", "VQABS", "VQADD", "VQDMLAL", "VQDMLSL", "VQDMULH", "VQDMULL", "VQMOVN", "VQMOVUN", "VQNEG", "VQRDMLAH", "VQRDMLSH", "VQRDMULH", "VQRSHL", "VQRSHRN", "VQRSHRUN", "VQSHL", "VQSHLU", "VQSHRN", "VQSHRUN", "VQSUB", "VRADDHN", "VRECPE", "VRECPS", "VREV16", "VREV32", "VREV64", "VRHADD", "VRINTA", "VRINTM", "VRINTN", "VRINTP", "VRINTR", "VRINTX", "VRINTZ", "VRSHL", "VRSHR", "VRSHRN", "VRSQRTE", "VRSQRTS", "VRSRA", "VRSUBHN", "VSDOT", "VSELEQ", "VSELGE", "VSELGT", "VSELVS", "VSHL", "VSHLL", "VSHR", "VSHRN", "VSLI", "VSQRT", "VSRA", "VSRI", "VST1", "VST2", "VST3", "VST4", "VSTMDB", "VSTMIA", "VSTR", "VSUB", "VSUBHN", "VSUBL", "VSUBW", "VSWP", "VTBL", "VTBX", "VTRN", "VTST", "VUDOT", "VUZP", "VZIP", "WFE", "WFI", "YIELD"
};

std::string armIPStr(int mode) {
    return "PC"; // For ARM 32-bit, program counter is R15 or PC
}

std::string aarch64IPStr(int mode) {
    return "PC"; // For AArch64, program counter is PC
}

std::pair<std::string, std::string> armSBPStr(int mode) {
    return {"SP", "R11"}; // Stack pointer is R13 or SP, Base pointer is R11 (FP)
}

std::pair<std::string, std::string> aarch64SBPStr(int mode) {
    return {"SP", "X29"}; // Stack pointer is SP, Base pointer is X29 (FP)
}

bool armIsRegisterValid(const std::string& reg) {
    std::string registerName = toLowerCase(reg);
    
    // Simple validation - check if register exists in map
    if (!armRegInfoMap.contains(registerName)) {
        return false;
    }
    
    // General registers R0-R15
    if (registerName[0] == 'r') {
        if (registerName.length() > 1) {
            int regNum = std::atoi(registerName.c_str() + 1);
            return regNum >= 0 && regNum <= 15;
        }
    }
    
    // Special registers
    if (registerName == "pc" || registerName == "lr" || registerName == "sp" || 
        registerName == "cpsr" || registerName == "spsr") {
        return true;
    }
    
    return false;
}

bool aarch64IsRegisterValid(const std::string& reg) {
    const std::string registerName = toLowerCase(reg);
    
    // Simple validation - check if register exists in map
    if (!aarch64RegInfoMap.contains(registerName)) {
        return false;
    }
    
    // X registers (X0-X30)
    if (registerName[0] == 'x') {
        if (registerName.length() > 1) {
            const int regNum = std::atoi(registerName.c_str() + 1);
            return regNum >= 0 && regNum <= 30;
        }
    }
    
    // W registers (W0-W30)
    if (registerName[0] == 'w') {
        if (registerName.length() > 1) {
            int regNum = std::atoi(registerName.c_str() + 1);
            return regNum >= 0 && regNum <= 30;
        }
    }
    
    // SIMD/FP registers validation
    if (registerName[0] == 'q' || registerName[0] == 'd' || registerName[0] == 's') {
        if (registerName.length() > 1) {
            const int regNum = std::atoi(registerName.c_str() + 1);
            return regNum >= 0 && regNum <= 31;
        }
    }
    
    // Special registers
    if (registerName == "pc" || registerName == "lr" || registerName == "sp" || 
        registerName == "xzr" || registerName == "wzr" || registerName == "fp" ||
        registerName == "nzcv" || registerName == "fpcr" || registerName == "fpsr") {
        return true;
    }
    
    return false;
}

void armModeUpdateCallback() {
    // Callback when ARM mode changes
    // Could update register views or other mode-specific settings
}

void aarch64ModeUpdateCallback() {
    // Callback when AArch64 mode changes
    // Could update register views or other mode-specific settings
}
