#include "TextEditor.h"
#include <vector>
#include <string>

bool isInstr = false;
bool isReg = false;

std::vector<std::string> armRegisters  = {
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30",
    "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8", "w9", "w10", "w11", "w12", "w13", "w14", "w15", "w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23", "w24", "w25", "w26", "w27", "w28", "w29", "w30",
    "sp", "zr",
    "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31",
    "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15", "d16", "d17", "d18", "d19", "d20", "d21", "d22", "d23", "d24", "d25", "d26", "d27", "d28", "d29", "d30", "d31",
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "s12", "s13", "s14", "s15", "s16", "s17", "s18", "s19", "s20", "s21", "s22", "s23", "s24", "s25", "s26", "s27", "s28", "s29", "s30", "s31",
    "h0", "h1", "h2", "h3", "h4", "h5", "h6", "h7", "h8", "h9", "h10", "h11", "h12", "h13", "h14", "h15", "h16", "h17", "h18", "h19", "h20", "h21", "h22", "h23", "h24", "h25", "h26", "h27", "h28", "h29", "h30", "h31",
    "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "b10", "b11", "b12", "b13", "b14", "b15", "b16", "b17", "b18", "b19", "b20", "b21", "b22", "b23", "b24", "b25", "b26", "b27", "b28", "b29", "b30", "b31",
    "pc", "lr", "fp",
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15", "r16", "r17", "r18", "r19",
    "r20", "r21", "r22", "r23",
    "r24", "r25", "r26", "r27",
    "r28", "r29", "r30", "r31",
    "q0", "q1", "q2", "q3", "q4", "q5",
    "q6", "q7", "q8", "q9",
    "q10", "q11", "q12", "q13", "q14", "q15",
    "q16", "q17", "q18", "q19",
    "q20", "q21", "q22", "q23",
    "q24", "q25", "q26", "q27",
    "q28", "q29", "q30", "q31",
};

static bool TokenizeCStyleString(const char* in_begin, const char* in_end, const char*& out_begin, const char*& out_end)
{
	const char* p = in_begin;

	if (*p == '"')
	{
		p++;

		while (p < in_end)
		{
			// handle end of string
			if (*p == '"')
			{
				out_begin = in_begin;
				out_end = p + 1;
				return true;
			}

			// handle escape character for "
			if (*p == '\\' && p + 1 < in_end && p[1] == '"')
				p++;

			p++;
		}
	}

	return false;
}

static bool TokenizeCStyleCharacterLiteral(const char* in_begin, const char* in_end, const char*& out_begin, const char*& out_end)
{
	const char* p = in_begin;

	if (*p == '\'')
	{
		p++;

		// handle escape characters
		if (p < in_end && *p == '\\')
			p++;

		if (p < in_end)
			p++;

		// handle end of character literal
		if (p < in_end && *p == '\'')
		{
			out_begin = in_begin;
			out_end = p + 1;
			return true;
		}
	}

	return false;
}


static bool TokenizeAsmStyleIdentifier(const char* in_begin, const char* in_end, const char*& out_begin, const char*& out_end)
{
    const char* p = in_begin;

    if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || *p == '_')
    {
        p++;

        while ((p < in_end) && ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '_'))
            p++;

        out_begin = in_begin;
        out_end = p;
        return true;
    }

    return false;
}

static bool TokenizeArmStyleIdentifier(const char* in_begin, const char* in_end, const char*& out_begin, const char*& out_end)
{

    const auto* s = in_begin;
    const auto  t = in_end;
    std::string j;

    if (in_begin[0] == '{' || in_begin[0] == '}')
    {
        return false;
    }

    while (s != t)
    {
        j += *s;
        s++;
    }

    bool decrement = false;
    if (j.ends_with('}'))
    {
        j = j.substr(0, j.size() - 1);
        decrement = true;
    }

    if (std::ranges::contains(armRegisters, j))
    {
        out_begin = in_begin;
        out_end = in_end - (decrement ? 1 : 0);
        return true;
    }

    if (j.ends_with(':'))
    {
        out_begin = in_begin;
        out_end = in_end;
        return true;
    }

    if (j.contains(' '))
    {
        j = j.substr(0, j.find_first_of(' '));
        if (!j.empty() && !j.contains(','))
        {
            if (boost::regex_search(j.begin(), j.end(), boost::regex(R"##(\b[A-Za-z]{1,12}(?:EQ|NE|CS|CC|MI|PL|VS|VC|HI|LS|GE|LT|GT|LE|AL)?(?:\.[A-Z0-9]+)?\b)##")))
            {
                out_begin = in_begin;
                out_end = in_begin + j.size() + 1;
                isInstr = true;
                return true;
            }
        }
        else if (j.contains(','))
        {
            j = j.substr(0, j.find_first_of(','));
            if (!j.empty())
            {
                if (std::ranges::contains(armRegisters, j))
                {
                    // isReg = true;
                    out_begin = in_begin;
                    out_end = in_begin + j.size();
                    return true;
                }
            }
        }
    }
    return false;
}


static bool TokenizeAssemblyStyleNumber(const char* in_begin, const char* in_end, const char*& out_begin, const char*& out_end)
{
    const char* p = in_begin;

    const bool startsWithNumber = *p >= '0' && *p <= '9' || *p == '#';

    if (*p != '+' && *p != '-' && !startsWithNumber)
        return false;

    p++;

    bool hasNumber = startsWithNumber;

    while (p < in_end && (*p >= '0' && *p <= '9'))
    {
        hasNumber = true;

        p++;
    }

    if (hasNumber == false)
        return false;

    bool isFloat = false;
    bool isHex = false;
    bool isBinary = false;

    if (p < in_end)
    {
        if (*p == '.')
        {
            isFloat = true;
            p++;

            while (p < in_end && (*p >= '0' && *p <= '9'))
                p++;
        }
        else if (*p == 'x' || *p == 'X')
        {
            // hex formatted integer of the type 0xef80

            isHex = true;

            p++;

            while (p < in_end && ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')))
                p++;
        }
    }

    out_begin = in_begin;
    out_end = p;
    return true;
}

static bool TokenizeCStylePunctuation(const char* in_begin, const char* in_end, const char*& out_begin, const char*& out_end)
{
	(void)in_end;

	switch (*in_begin)
	{
	case '[':
	case ']':
	case '{':
	case '}':
	case '!':
	case '%':
	case '^':
	case '&':
	case '*':
	case '(':
	case ')':
	case '-':
	case '+':
	case '=':
	case '~':
	case '|':
	case '<':
	case '>':
	case '?':
	case ':':
	case '/':
	case ';':
	case ',':
	case '.':
		out_begin = in_begin;
		out_end = in_begin + 1;
		return true;
	}

	return false;
}


static bool TokenizeCStyleNumber(const char* in_begin, const char* in_end, const char*& out_begin, const char*& out_end)
{
    const char* p = in_begin;

    const bool startsWithNumber = *p >= '0' && *p <= '9';

    if (*p != '+' && *p != '-' && !startsWithNumber)
        return false;

    p++;

    bool hasNumber = startsWithNumber;

    while (p < in_end && (*p >= '0' && *p <= '9'))
    {
        hasNumber = true;

        p++;
    }

    if (hasNumber == false)
        return false;

    bool isFloat = false;
    bool isHex = false;
    bool isBinary = false;

    if (p < in_end)
    {
        if (*p == '.')
        {
            isFloat = true;

            p++;

            while (p < in_end && (*p >= '0' && *p <= '9'))
                p++;
        }
        else if (*p == 'x' || *p == 'X')
        {
            // hex formatted integer of the type 0xef80

            isHex = true;

            p++;

            while (p < in_end && ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')))
                p++;
        }
        else if (*p == 'b' || *p == 'B')
        {
            // binary formatted integer of the type 0b01011101

            isBinary = true;

            p++;

            while (p < in_end && (*p >= '0' && *p <= '1'))
                p++;
        }
    }

    if (isHex == false && isBinary == false)
    {
        // floating point exponent
        if (p < in_end && (*p == 'e' || *p == 'E'))
        {
            isFloat = true;

            p++;

            if (p < in_end && (*p == '+' || *p == '-'))
                p++;

            bool hasDigits = false;

            while (p < in_end && (*p >= '0' && *p <= '9'))
            {
                hasDigits = true;

                p++;
            }

            if (hasDigits == false)
                return false;
        }

        // single precision floating point type
        if (p < in_end && *p == 'f')
            p++;
    }

    if (isFloat == false)
    {
        // integer size type
        while (p < in_end && (*p == 'u' || *p == 'U' || *p == 'l' || *p == 'L'))
            p++;
    }

    out_begin = in_begin;
    out_end = p;
    return true;
}

static bool TokenizeX86StylePunctuation(const char* in_begin, const char* in_end, const char*& out_begin, const char*& out_end)
{
    (void)in_end;

    switch (*in_begin)
    {
        case '[':
        case ']':
        case '*':
        case '(':  // at&t syntax
        case ')':
        case '-':
        case '+':
        case ':':
        case '{':
        case '}':
            out_begin = in_begin;
            out_end = in_begin + 1;
            return true;
    }

    return false;
}

const TextEditor::LanguageDefinition& TextEditor::LanguageDefinition::AsmArm()
{
    static bool inited = false;
    static LanguageDefinition langDef;
    if (!inited)
    {
        static const char* const x86Keywords[] =  {
            "MOV", "MOVS", "BL", "VMOV", "B", "POP", "BX", "SVC"
        };

        for (auto& k : x86Keywords)
            langDef.mKeywords.insert(k);

        static const char* const identifiers[] = {
            "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30",
            "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8", "w9", "w10", "w11", "w12", "w13", "w14", "w15", "w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23", "w24", "w25", "w26", "w27", "w28", "w29", "w30",
            "sp", "zr",
            "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31",
            "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15", "d16", "d17", "d18", "d19", "d20", "d21", "d22", "d23", "d24", "d25", "d26", "d27", "d28", "d29", "d30", "d31",
            "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "s12", "s13", "s14", "s15", "s16", "s17", "s18", "s19", "s20", "s21", "s22", "s23", "s24", "s25", "s26", "s27", "s28", "s29", "s30", "s31",
            "h0", "h1", "h2", "h3", "h4", "h5", "h6", "h7", "h8", "h9", "h10", "h11", "h12", "h13", "h14", "h15", "h16", "h17", "h18", "h19", "h20", "h21", "h22", "h23", "h24", "h25", "h26", "h27", "h28", "h29", "h30", "h31",
            "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "b10", "b11", "b12", "b13", "b14", "b15", "b16", "b17", "b18", "b19", "b20", "b21", "b22", "b23", "b24", "b25", "b26", "b27", "b28", "b29", "b30", "b31",
            "pc", "lr", "fp",
            "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13",
            "r14", "r15", "r16", "r17", "r18", "r19",
            "r20", "r21", "r22", "r23",
            "r24", "r25", "r26", "r27",
            "r28", "r29", "r30", "r31",
            "q0", "q1", "q2", "q3", "q4", "q5",
            "q6", "q7", "q8", "q9",
            "q10", "q11", "q12", "q13", "q14", "q15",
            "q16", "q17", "q18", "q19",
            "q20", "q21", "q22", "q23",
            "q24", "q25", "q26", "q27",
            "q28", "q29", "q30", "q31",
        };

        for (auto& k : identifiers)
        {
            Identifier id;
            id.mDeclaration = "CPU Register";
            langDef.mIdentifiers.insert(std::make_pair(std::string(k), id));
        }

        langDef.mTokenize = [](const char* in_begin, const char* in_end, const char*& out_begin, const char*& out_end, PaletteIndex& paletteIndex) -> bool
        {
            paletteIndex = PaletteIndex::Max;

            while (in_begin < in_end && isascii(*in_begin) && isblank(*in_begin))
                in_begin++;


            if (in_begin == in_end)
            {
                out_begin = in_end;
                out_end = in_end;
                paletteIndex = PaletteIndex::Default;
            }
            else if (TokenizeCStyleString(in_begin, in_end, out_begin, out_end))
                paletteIndex = PaletteIndex::String;
            else if (TokenizeCStyleCharacterLiteral(in_begin, in_end, out_begin, out_end))
                paletteIndex = PaletteIndex::CharLiteral;
            else if (TokenizeArmStyleIdentifier(in_begin, in_end, out_begin, out_end))
            {
                if (isInstr)
                {
                    paletteIndex = PaletteIndex::Keyword;
                    isInstr = false;
                }
                else if (isReg)
                {
                    paletteIndex = PaletteIndex::Breakpoint;
                    isReg = false;
                }
                else
                {
                    paletteIndex = PaletteIndex::Identifier;
                }
            }
            else if (TokenizeAssemblyStyleNumber(in_begin, in_end, out_begin, out_end))
                paletteIndex = PaletteIndex::Number;
            else if (TokenizeX86StylePunctuation(in_begin, in_end, out_begin, out_end))
                paletteIndex = PaletteIndex::Punctuation;

            return paletteIndex != PaletteIndex::Max;
        };

        langDef.mCommentStart = "%comment";
        langDef.mCommentEnd = "%endcomment";
        langDef.mSingleLineComment = ";";

        langDef.mCaseSensitive = true;

        langDef.mName = "ARM Assembly";
        inited = true;
    }
    return langDef;
}

const TextEditor::LanguageDefinition& TextEditor::LanguageDefinition::Asm()
{
    static bool inited = false;
    static LanguageDefinition langDef;
    if (!inited)
    {
        static const char* const x86Keywords[] =  {
          "aaa", "aad", "aam", "aas", "fabs", "adc", "adcx", "add", "addpd", "addps", "addsd", "addss", "addsubpd", "addsubps", "fadd", "fiadd", "adox", "aesdeclast", "aesdec", "aesenclast", "aesenc", "aesimc", "aeskeygenassist", "and", "andn", "andnpd", "andnps", "andpd", "andps", "arpl", "bextr", "blcfill", "blci", "blcic", "blcmsk", "blcs", "blendpd", "blendps", "blendvpd", "blendvps", "blsfill", "blsi", "blsic", "blsmsk", "blsr", "bndcl", "bndcn", "bndcu", "bndldx", "bndmk", "bndmov", "bndstx", "bound", "bsf", "bsr", "bswap", "bt", "btc", "btr", "bts", "bzhi", "call", "cbw", "cdq", "cdqe", "fchs", "clac", "clc", "cld", "cldemote", "clflush", "clflushopt", "clgi", "cli", "clrssbsy", "clts", "clwb", "clzero", "cmc", "cmova", "cmovae", "cmovb", "cmovbe", "fcmovbe", "fcmovb", "cmove", "fcmove", "cmovg", "cmovge", "cmovl", "cmovle", "fcmovnbe", "fcmovnb", "cmovne", "fcmovne", "cmovno", "cmovnp", "fcmovnu", "fcmovnp", "cmovns", "cmovo", "cmovp", "fcmovu", "cmovs", "cmp", "cmppd", "cmpps", "cmpsb", "cmpsd", "cmpsq", "cmpss", "cmpsw", "cmpxchg16b", "cmpxchg", "cmpxchg8b", "comisd", "comiss", "fcomp", "fcompi", "fcomi", "fcom", "fcos", "cpuid", "cqo", "crc32", "cvtdq2pd", "cvtdq2ps", "cvtpd2dq", "cvtpd2ps", "cvtps2dq", "cvtps2pd", "cvtsd2si", "cvtsd2ss", "cvtsi2sd", "cvtsi2ss", "cvtss2sd", "cvtss2si", "cvttpd2dq", "cvttps2dq", "cvttsd2si", "cvttss2si", "cwd", "cwde", "daa", "das", "data16", "dec", "div", "divpd", "divps", "fdivr", "fidivr", "fdivrp", "divsd", "divss", "fdiv", "fidiv", "fdivp", "dppd", "dpps", "encls", "enclu", "enclv", "endbr32", "endbr64", "enter", "extractps", "extrq", "f2xm1", "lcall", "ljmp", "jmp", "fbld", "fbstp", "fcompp", "fdecstp", "fdisi8087_nop", "femms", "feni8087_nop", "ffree", "ffreep", "ficom", "ficomp", "fincstp", "fldcw", "fldenv", "fldl2e", "fldl2t", "fldlg2", "fldln2", "fldpi", "fnclex", "fninit", "fnop", "fnstcw", "fnstsw", "fpatan", "fstpnce", "fprem", "fprem1", "fptan", "frndint", "frstor", "fnsave", "fscale", "fsetpm", "fsincos", "fnstenv", "fxam", "fxrstor", "fxrstor64", "fxsave", "fxsave64", "fxtract", "fyl2x", "fyl2xp1", "getsec", "gf2p8affineinvqb", "gf2p8affineqb", "gf2p8mulb", "haddpd", "haddps", "hlt", "hsubpd", "hsubps", "idiv", "fild", "imul", "in", "inc", "incsspd", "incsspq", "insb", "insertps", "insertq", "insd", "insw", "int", "int1", "int3", "into", "invd", "invept", "invlpg", "invlpga", "invpcid", "invvpid", "iret", "iretd", "iretq", "fisttp", "fist", "fistp", "jae", "ja", "jbe", "jb", "jcxz", "jecxz", "je", "jge", "jg", "jle", "jl", "jne", "jno", "jnp", "jns", "jo", "jp", "jrcxz", "js", "kaddb", "kaddd", "kaddq", "kaddw", "kandb", "kandd", "kandnb", "kandnd", "kandnq", "kandnw", "kandq", "kandw", "kmovb", "kmovd", "kmovq", "kmovw", "knotb", "knotd", "knotq", "knotw", "korb", "kord", "korq", "kortestb", "kortestd", "kortestq", "kortestw", "korw", "kshiftlb", "kshiftld", "kshiftlq", "kshiftlw", "kshiftrb", "kshiftrd", "kshiftrq", "kshiftrw", "ktestb", "ktestd", "ktestq", "ktestw", "kunpckbw", "kunpckdq", "kunpckwd", "kxnorb", "kxnord", "kxnorq", "kxnorw", "kxorb", "kxord", "kxorq", "kxorw", "lahf", "lar", "lddqu", "ldmxcsr", "lds", "fldz", "fld1", "fld", "lea", "leave", "les", "lfence", "lfs", "lgdt", "lgs", "lidt", "lldt", "llwpcb", "lmsw", "lock", "lodsb", "lodsd", "lodsq", "lodsw", "loop", "loope", "loopne", "retf", "retfq", "lsl", "lss", "ltr", "lwpins", "lwpval", "lzcnt", "maskmovdqu", "maxpd", "maxps", "maxsd", "maxss", "mfence", "minpd", "minps", "minsd", "minss", "cvtpd2pi", "cvtpi2pd", "cvtpi2ps", "cvtps2pi", "cvttpd2pi", "cvttps2pi", "emms", "maskmovq", "movd", "movq", "movdq2q", "movntq", "movq2dq", "pabsb", "pabsd", "pabsw", "packssdw", "packsswb", "packuswb", "paddb", "paddd", "paddq", "paddsb", "paddsw", "paddusb", "paddusw", "paddw", "palignr", "pandn", "pand", "pavgb", "pavgw", "pcmpeqb", "pcmpeqd", "pcmpeqw", "pcmpgtb", "pcmpgtd", "pcmpgtw", "pextrw", "phaddd", "phaddsw", "phaddw", "phsubd", "phsubsw", "phsubw", "pinsrw", "pmaddubsw", "pmaddwd", "pmaxsw", "pmaxub", "pminsw", "pminub", "pmovmskb", "pmulhrsw", "pmulhuw", "pmulhw", "pmullw", "pmuludq", "por", "psadbw", "pshufb", "pshufw", "psignb", "psignd", "psignw", "pslld", "psllq", "psllw", "psrad", "psraw", "psrld", "psrlq", "psrlw", "psubb", "psubd", "psubq", "psubsb", "psubsw", "psubusb", "psubusw", "psubw", "punpckhbw", "punpckhdq", "punpckhwd", "punpcklbw", "punpckldq", "punpcklwd", "pxor", "monitorx", "monitor", "montmul", "mov", "movabs", "movapd", "movaps", "movbe", "movddup", "movdir64b", "movdiri", "movdqa", "movdqu", "movhlps", "movhpd", "movhps", "movlhps", "movlpd", "movlps", "movmskpd", "movmskps", "movntdqa", "movntdq", "movnti", "movntpd", "movntps", "movntsd", "movntss", "movsb", "movsd", "movshdup", "movsldup", "movsq", "movss", "movsw", "movsx", "movsxd", "movupd", "movups", "movzx", "mpsadbw", "mul", "mulpd", "mulps", "mulsd", "mulss", "mulx", "fmul", "fimul", "fmulp", "mwaitx", "mwait", "neg", "nop", "not", "or", "orpd", "orps", "out", "outsb", "outsd", "outsw", "packusdw", "pause", "pavgusb", "pblendvb", "pblendw", "pclmulqdq", "pcmpeqq", "pcmpestri", "pcmpestrm", "pcmpgtq", "pcmpistri", "pcmpistrm", "pconfig", "pdep", "pext", "pextrb", "pextrd", "pextrq", "pf2id", "pf2iw", "pfacc", "pfadd", "pfcmpeq", "pfcmpge", "pfcmpgt", "pfmax", "pfmin", "pfmul", "pfnacc", "pfpnacc", "pfrcpit1", "pfrcpit2", "pfrcp", "pfrsqit1", "pfrsqrt", "pfsubr", "pfsub", "phminposuw", "pi2fd", "pi2fw", "pinsrb", "pinsrd", "pinsrq", "pmaxsb", "pmaxsd", "pmaxud", "pmaxuw", "pminsb", "pminsd", "pminud", "pminuw", "pmovsxbd", "pmovsxbq", "pmovsxbw", "pmovsxdq", "pmovsxwd", "pmovsxwq", "pmovzxbd", "pmovzxbq", "pmovzxbw", "pmovzxdq", "pmovzxwd", "pmovzxwq", "pmuldq", "pmulhrw", "pmulld", "pop", "popaw", "popal", "popcnt", "popf", "popfd", "popfq", "prefetch", "prefetchnta", "prefetcht0", "prefetcht1", "prefetcht2", "prefetchw", "prefetchwt1", "pshufd", "pshufhw", "pshuflw", "pslldq", "psrldq", "pswapd", "ptest", "ptwrite", "punpckhqdq", "punpcklqdq", "push", "pushaw", "pushal", "pushf", "pushfd", "pushfq", "rcl", "rcpps", "rcpss", "rcr", "rdfsbase", "rdgsbase", "rdmsr", "rdpid", "rdpkru", "rdpmc", "rdrand", "rdseed", "rdsspd", "rdsspq", "rdtsc", "rdtscp", "repne", "rep", "ret", "rex64", "rol", "ror", "rorx", "roundpd", "roundps", "roundsd", "roundss", "rsm", "rsqrtps", "rsqrtss", "rstorssp", "sahf", "sal", "salc", "sar", "sarx", "saveprevssp", "sbb", "scasb", "scasd", "scasq", "scasw", "setae", "seta", "setbe", "setb", "sete", "setge", "setg", "setle", "setl", "setne", "setno", "setnp", "setns", "seto", "setp", "setssbsy", "sets", "sfence", "sgdt", "sha1msg1", "sha1msg2", "sha1nexte", "sha1rnds4", "sha256msg1", "sha256msg2", "sha256rnds2", "shl", "shld", "shlx", "shr", "shrd", "shrx", "shufpd", "shufps", "sidt", "fsin", "skinit", "sldt", "slwpcb", "smsw", "sqrtpd", "sqrtps", "sqrtsd", "sqrtss", "fsqrt", "stac", "stc", "std", "stgi", "sti", "stmxcsr", "stosb", "stosd", "stosq", "stosw", "str", "fst", "fstp", "sub", "subpd", "subps", "fsubr", "fisubr", "fsubrp", "subsd", "subss", "fsub", "fisub", "fsubp", "swapgs", "syscall", "sysenter", "sysexit", "sysexitq", "sysret", "sysretq", "t1mskc", "test", "tpause", "ftst", "tzcnt", "tzmsk", "ucomisd", "ucomiss", "fucompi", "fucomi", "fucompp", "fucomp", "fucom", "ud0", "ud1", "ud2", "umonitor", "umwait", "unpckhpd", "unpckhps", "unpcklpd", "unpcklps", "v4fmaddps", "v4fmaddss", "v4fnmaddps", "v4fnmaddss", "vaddpd", "vaddps", "vaddsd", "vaddss", "vaddsubpd", "vaddsubps", "vaesdeclast", "vaesdec", "vaesenclast", "vaesenc", "vaesimc", "vaeskeygenassist", "valignd", "valignq", "vandnpd", "vandnps", "vandpd", "vandps", "vblendmpd", "vblendmps", "vblendpd", "vblendps", "vblendvpd", "vblendvps", "vbroadcastf128", "vbroadcastf32x2", "vbroadcastf32x4", "vbroadcastf32x8", "vbroadcastf64x2", "vbroadcastf64x4", "vbroadcasti128", "vbroadcasti32x2", "vbroadcasti32x4", "vbroadcasti32x8", "vbroadcasti64x2", "vbroadcasti64x4", "vbroadcastsd", "vbroadcastss", "vcmp", "vcmppd", "vcmpps", "vcmpsd", "vcmpss", "vcomisd", "vcomiss", "vcompresspd", "vcompressps", "vcvtdq2pd", "vcvtdq2ps", "vcvtpd2dq", "vcvtpd2ps", "vcvtpd2qq", "vcvtpd2udq", "vcvtpd2uqq", "vcvtph2ps", "vcvtps2dq", "vcvtps2pd", "vcvtps2ph", "vcvtps2qq", "vcvtps2udq", "vcvtps2uqq", "vcvtqq2pd", "vcvtqq2ps", "vcvtsd2si", "vcvtsd2ss", "vcvtsd2usi", "vcvtsi2sd", "vcvtsi2ss", "vcvtss2sd", "vcvtss2si", "vcvtss2usi", "vcvttpd2dq", "vcvttpd2qq", "vcvttpd2udq", "vcvttpd2uqq", "vcvttps2dq", "vcvttps2qq", "vcvttps2udq", "vcvttps2uqq", "vcvttsd2si", "vcvttsd2usi", "vcvttss2si", "vcvttss2usi", "vcvtudq2pd", "vcvtudq2ps", "vcvtuqq2pd", "vcvtuqq2ps", "vcvtusi2sd", "vcvtusi2ss", "vdbpsadbw", "vdivpd", "vdivps", "vdivsd", "vdivss", "vdppd", "vdpps", "verr", "verw", "vexp2pd", "vexp2ps", "vexpandpd", "vexpandps", "vextractf128", "vextractf32x4", "vextractf32x8", "vextractf64x2", "vextractf64x4", "vextracti128", "vextracti32x4", "vextracti32x8", "vextracti64x2", "vextracti64x4", "vextractps", "vfixupimmpd", "vfixupimmps", "vfixupimmsd", "vfixupimmss", "vfmadd132pd", "vfmadd132ps", "vfmadd132sd", "vfmadd132ss", "vfmadd213pd", "vfmadd213ps", "vfmadd213sd", "vfmadd213ss", "vfmadd231pd", "vfmadd231ps", "vfmadd231sd", "vfmadd231ss", "vfmaddpd", "vfmaddps", "vfmaddsd", "vfmaddss", "vfmaddsub132pd", "vfmaddsub132ps", "vfmaddsub213pd", "vfmaddsub213ps", "vfmaddsub231pd", "vfmaddsub231ps", "vfmaddsubpd", "vfmaddsubps", "vfmsub132pd", "vfmsub132ps", "vfmsub132sd", "vfmsub132ss", "vfmsub213pd", "vfmsub213ps", "vfmsub213sd", "vfmsub213ss", "vfmsub231pd", "vfmsub231ps", "vfmsub231sd", "vfmsub231ss", "vfmsubadd132pd", "vfmsubadd132ps", "vfmsubadd213pd", "vfmsubadd213ps", "vfmsubadd231pd", "vfmsubadd231ps", "vfmsubaddpd", "vfmsubaddps", "vfmsubpd", "vfmsubps", "vfmsubsd", "vfmsubss", "vfnmadd132pd", "vfnmadd132ps", "vfnmadd132sd", "vfnmadd132ss", "vfnmadd213pd", "vfnmadd213ps", "vfnmadd213sd", "vfnmadd213ss", "vfnmadd231pd", "vfnmadd231ps", "vfnmadd231sd", "vfnmadd231ss", "vfnmaddpd", "vfnmaddps", "vfnmaddsd", "vfnmaddss", "vfnmsub132pd", "vfnmsub132ps", "vfnmsub132sd", "vfnmsub132ss", "vfnmsub213pd", "vfnmsub213ps", "vfnmsub213sd", "vfnmsub213ss", "vfnmsub231pd", "vfnmsub231ps", "vfnmsub231sd", "vfnmsub231ss", "vfnmsubpd", "vfnmsubps", "vfnmsubsd", "vfnmsubss", "vfpclasspd", "vfpclassps", "vfpclasssd", "vfpclassss", "vfrczpd", "vfrczps", "vfrczsd", "vfrczss", "vgatherdpd", "vgatherdps", "vgatherpf0dpd", "vgatherpf0dps", "vgatherpf0qpd", "vgatherpf0qps", "vgatherpf1dpd", "vgatherpf1dps", "vgatherpf1qpd", "vgatherpf1qps", "vgatherqpd", "vgatherqps", "vgetexppd", "vgetexpps", "vgetexpsd", "vgetexpss", "vgetmantpd", "vgetmantps", "vgetmantsd", "vgetmantss", "vgf2p8affineinvqb", "vgf2p8affineqb", "vgf2p8mulb", "vhaddpd", "vhaddps", "vhsubpd", "vhsubps", "vinsertf128", "vinsertf32x4", "vinsertf32x8", "vinsertf64x2", "vinsertf64x4", "vinserti128", "vinserti32x4", "vinserti32x8", "vinserti64x2", "vinserti64x4", "vinsertps", "vlddqu", "vldmxcsr", "vmaskmovdqu", "vmaskmovpd", "vmaskmovps", "vmaxpd", "vmaxps", "vmaxsd", "vmaxss", "vmcall", "vmclear", "vmfunc", "vminpd", "vminps", "vminsd", "vminss", "vmlaunch", "vmload", "vmmcall", "vmovq", "vmovapd", "vmovaps", "vmovddup", "vmovd", "vmovdqa32", "vmovdqa64", "vmovdqa", "vmovdqu16", "vmovdqu32", "vmovdqu64", "vmovdqu8", "vmovdqu", "vmovhlps", "vmovhpd", "vmovhps", "vmovlhps", "vmovlpd", "vmovlps", "vmovmskpd", "vmovmskps", "vmovntdqa", "vmovntdq", "vmovntpd", "vmovntps", "vmovsd", "vmovshdup", "vmovsldup", "vmovss", "vmovupd", "vmovups", "vmpsadbw", "vmptrld", "vmptrst", "vmread", "vmresume", "vmrun", "vmsave", "vmulpd", "vmulps", "vmulsd", "vmulss", "vmwrite", "vmxoff", "vmxon", "vorpd", "vorps", "vp4dpwssds", "vp4dpwssd", "vpabsb", "vpabsd", "vpabsq", "vpabsw", "vpackssdw", "vpacksswb", "vpackusdw", "vpackuswb", "vpaddb", "vpaddd", "vpaddq", "vpaddsb", "vpaddsw", "vpaddusb", "vpaddusw", "vpaddw", "vpalignr", "vpandd", "vpandnd", "vpandnq", "vpandn", "vpandq", "vpand", "vpavgb", "vpavgw", "vpblendd", "vpblendmb", "vpblendmd", "vpblendmq", "vpblendmw", "vpblendvb", "vpblendw", "vpbroadcastb", "vpbroadcastd", "vpbroadcastmb2q", "vpbroadcastmw2d", "vpbroadcastq", "vpbroadcastw", "vpclmulqdq", "vpcmov", "vpcmp", "vpcmpb", "vpcmpd", "vpcmpeqb", "vpcmpeqd", "vpcmpeqq", "vpcmpeqw", "vpcmpestri", "vpcmpestrm", "vpcmpgtb", "vpcmpgtd", "vpcmpgtq", "vpcmpgtw", "vpcmpistri", "vpcmpistrm", "vpcmpq", "vpcmpub", "vpcmpud", "vpcmpuq", "vpcmpuw", "vpcmpw", "vpcom", "vpcomb", "vpcomd", "vpcompressb", "vpcompressd", "vpcompressq", "vpcompressw", "vpcomq", "vpcomub", "vpcomud", "vpcomuq", "vpcomuw", "vpcomw", "vpconflictd", "vpconflictq", "vpdpbusds", "vpdpbusd", "vpdpwssds", "vpdpwssd", "vperm2f128", "vperm2i128", "vpermb", "vpermd", "vpermi2b", "vpermi2d", "vpermi2pd", "vpermi2ps", "vpermi2q", "vpermi2w", "vpermil2pd", "vpermilpd", "vpermil2ps", "vpermilps", "vpermpd", "vpermps", "vpermq", "vpermt2b", "vpermt2d", "vpermt2pd", "vpermt2ps", "vpermt2q", "vpermt2w", "vpermw", "vpexpandb", "vpexpandd", "vpexpandq", "vpexpandw", "vpextrb", "vpextrd", "vpextrq", "vpextrw", "vpgatherdd", "vpgatherdq", "vpgatherqd", "vpgatherqq", "vphaddbd", "vphaddbq", "vphaddbw", "vphadddq", "vphaddd", "vphaddsw", "vphaddubd", "vphaddubq", "vphaddubw", "vphaddudq", "vphadduwd", "vphadduwq", "vphaddwd", "vphaddwq", "vphaddw", "vphminposuw", "vphsubbw", "vphsubdq", "vphsubd", "vphsubsw", "vphsubwd", "vphsubw", "vpinsrb", "vpinsrd", "vpinsrq", "vpinsrw", "vplzcntd", "vplzcntq", "vpmacsdd", "vpmacsdqh", "vpmacsdql", "vpmacssdd", "vpmacssdqh", "vpmacssdql", "vpmacsswd", "vpmacssww", "vpmacswd", "vpmacsww", "vpmadcsswd", "vpmadcswd", "vpmadd52huq", "vpmadd52luq", "vpmaddubsw", "vpmaddwd", "vpmaskmovd", "vpmaskmovq", "vpmaxsb", "vpmaxsd", "vpmaxsq", "vpmaxsw", "vpmaxub", "vpmaxud", "vpmaxuq", "vpmaxuw", "vpminsb", "vpminsd", "vpminsq", "vpminsw", "vpminub", "vpminud", "vpminuq", "vpminuw", "vpmovb2m", "vpmovd2m", "vpmovdb", "vpmovdw", "vpmovm2b", "vpmovm2d", "vpmovm2q", "vpmovm2w", "vpmovmskb", "vpmovq2m", "vpmovqb", "vpmovqd", "vpmovqw", "vpmovsdb", "vpmovsdw", "vpmovsqb", "vpmovsqd", "vpmovsqw", "vpmovswb", "vpmovsxbd", "vpmovsxbq", "vpmovsxbw", "vpmovsxdq", "vpmovsxwd", "vpmovsxwq", "vpmovusdb", "vpmovusdw", "vpmovusqb", "vpmovusqd", "vpmovusqw", "vpmovuswb", "vpmovw2m", "vpmovwb", "vpmovzxbd", "vpmovzxbq", "vpmovzxbw", "vpmovzxdq", "vpmovzxwd", "vpmovzxwq", "vpmuldq", "vpmulhrsw", "vpmulhuw", "vpmulhw", "vpmulld", "vpmullq", "vpmullw", "vpmultishiftqb", "vpmuludq", "vpopcntb", "vpopcntd", "vpopcntq", "vpopcntw", "vpord", "vporq", "vpor", "vpperm", "vprold", "vprolq", "vprolvd", "vprolvq", "vprord", "vprorq", "vprorvd", "vprorvq", "vprotb", "vprotd", "vprotq", "vprotw", "vpsadbw", "vpscatterdd", "vpscatterdq", "vpscatterqd", "vpscatterqq", "vpshab", "vpshad", "vpshaq", "vpshaw", "vpshlb", "vpshldd", "vpshldq", "vpshldvd", "vpshldvq", "vpshldvw", "vpshldw", "vpshld", "vpshlq", "vpshlw", "vpshrdd", "vpshrdq", "vpshrdvd", "vpshrdvq", "vpshrdvw", "vpshrdw", "vpshufbitqmb", "vpshufb", "vpshufd", "vpshufhw", "vpshuflw", "vpsignb", "vpsignd", "vpsignw", "vpslldq", "vpslld", "vpsllq", "vpsllvd", "vpsllvq", "vpsllvw", "vpsllw", "vpsrad", "vpsraq", "vpsravd", "vpsravq", "vpsravw", "vpsraw", "vpsrldq", "vpsrld", "vpsrlq", "vpsrlvd", "vpsrlvq", "vpsrlvw", "vpsrlw", "vpsubb", "vpsubd", "vpsubq", "vpsubsb", "vpsubsw", "vpsubusb", "vpsubusw", "vpsubw", "vpternlogd", "vpternlogq", "vptestmb", "vptestmd", "vptestmq", "vptestmw", "vptestnmb", "vptestnmd", "vptestnmq", "vptestnmw", "vptest", "vpunpckhbw", "vpunpckhdq", "vpunpckhqdq", "vpunpckhwd", "vpunpcklbw", "vpunpckldq", "vpunpcklqdq", "vpunpcklwd", "vpxord", "vpxorq", "vpxor", "vrangepd", "vrangeps", "vrangesd", "vrangess", "vrcp14pd", "vrcp14ps", "vrcp14sd", "vrcp14ss", "vrcp28pd", "vrcp28ps", "vrcp28sd", "vrcp28ss", "vrcpps", "vrcpss", "vreducepd", "vreduceps", "vreducesd", "vreducess", "vrndscalepd", "vrndscaleps", "vrndscalesd", "vrndscaless", "vroundpd", "vroundps", "vroundsd", "vroundss", "vrsqrt14pd", "vrsqrt14ps", "vrsqrt14sd", "vrsqrt14ss", "vrsqrt28pd", "vrsqrt28ps", "vrsqrt28sd", "vrsqrt28ss", "vrsqrtps", "vrsqrtss", "vscalefpd", "vscalefps", "vscalefsd", "vscalefss", "vscatterdpd", "vscatterdps", "vscatterpf0dpd", "vscatterpf0dps", "vscatterpf0qpd", "vscatterpf0qps", "vscatterpf1dpd", "vscatterpf1dps", "vscatterpf1qpd", "vscatterpf1qps", "vscatterqpd", "vscatterqps", "vshuff32x4", "vshuff64x2", "vshufi32x4", "vshufi64x2", "vshufpd", "vshufps", "vsqrtpd", "vsqrtps", "vsqrtsd", "vsqrtss", "vstmxcsr", "vsubpd", "vsubps", "vsubsd", "vsubss", "vtestpd", "vtestps", "vucomisd", "vucomiss", "vunpckhpd", "vunpckhps", "vunpcklpd", "vunpcklps", "vxorpd", "vxorps", "vzeroall", "vzeroupper", "wait", "wbinvd", "wbnoinvd", "wrfsbase", "wrgsbase", "wrmsr", "wrpkru", "wrssd", "wrssq", "wrussd", "wrussq", "xabort", "xacquire", "xadd", "xbegin", "xchg", "fxch", "xcryptcbc", "xcryptcfb", "xcryptctr", "xcryptecb", "xcryptofb", "xend", "xgetbv", "xlatb", "xor", "xorpd", "xorps", "xrelease", "xrstor", "xrstor64", "xrstors", "xrstors64", "xsave", "xsave64", "xsavec", "xsavec64", "xsaveopt", "xsaveopt64", "xsaves", "xsaves64", "xsetbv", "xsha1", "xsha256", "xstore", "xtestmov", "ldr", "ldrb", "ldur", "ldp", "str", "strb", "stur", "stp", "add", "sub", "neg", "mul", "udiv", "sdiv", "lsl", "lsr", "asr", "and", "orr", "eor", "mvn", "cmp", "tst", "br", "adr", "adrp", "bl", "blr", "ret", "cbz", "cbnz", "b", "b.eq", "b.ne", "b.mi", "b.pl", "b.gt", "b.ge", "b.lt", "b.le", "svc", "msub", "madd", "push", "pop"
        };

        for (auto& k : x86Keywords)
            langDef.mKeywords.insert(k);

        static const char* const identifiers[] = {
            "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "al", "ah", "bl", "bh", "cl", "ch", "dl", "dh", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "sil", "dil", "bpl", "spl", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b", "ax", "bx", "cx", "dx", "si", "di", "bp", "sp", "cs", "ds", "ss", "es", "fs", "gs", "cr0", "cr1", "cr2", "cr3", "cr4", "cr8", "cr5", "cr6", "cr7", "cr9", "cr10", "cr11", "cr12", "cr13", "cr14", "cr15", "dr0", "dr1", "dr2", "dr3", "dr6", "dr7", "dr4", "dr5", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15", "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7", "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15", "zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7", "zmm8", "zmm9", "zmm10", "zmm11", "zmm12", "zmm13", "zmm14", "zmm15", "zmm16", "zmm17", "zmm18", "zmm19", "zmm20", "zmm21", "zmm22", "zmm23", "zmm24", "zmm25", "zmm26", "zmm27", "zmm28", "zmm29", "zmm30", "zmm31", "gdtr", "ldtr", "idtr", "tr", "k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7", "MXCSR", "XCR0", "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7", "eip", "rip", "eflags", "rflags", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w", "mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7",
            "X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7", "X8", "X9", "X10", "X11", "X12", "X13", "X14", "X15", "X16", "X17", "X18", "X19", "X20", "X21", "X22", "X23", "X24", "X25", "X26", "X27", "X28", "X29", "X30",
            "W0", "W1", "W2", "W3", "W4", "W5", "W6", "W7", "W8", "W9", "W10", "W11", "W12", "W13", "W14", "W15", "W16", "W17", "W18", "W19", "W20", "W21", "W22", "W23", "W24", "W25", "W26", "W27", "W28", "W29", "W30",
            "SP", "ZR",
            "V0", "V1", "V2", "V3", "V4", "V5", "V6", "V7", "V8", "V9", "V10", "V11", "V12", "V13", "V14", "V15", "V16", "V17", "V18", "V19", "V20", "V21", "V22", "V23", "V24", "V25", "V26", "V27", "V28", "V29", "V30", "V31",
            "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "D10", "D11", "D12", "D13", "D14", "D15", "D16", "D17", "D18", "D19", "D20", "D21", "D22", "D23", "D24", "D25", "D26", "D27", "D28", "D29", "D30", "D31",
            "S0", "S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9", "S10", "S11", "S12", "S13", "S14", "S15", "S16", "S17", "S18", "S19", "S20", "S21", "S22", "S23", "S24", "S25", "S26", "S27", "S28", "S29", "S30", "S31",
            "H0", "H1", "H2", "H3", "H4", "H5", "H6", "H7", "H8", "H9", "H10", "H11", "H12", "H13", "H14", "H15", "H16", "H17", "H18", "H19", "H20", "H21", "H22", "H23", "H24", "H25", "H26", "H27", "H28", "H29", "H30", "H31",
            "B0", "B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8", "B9", "B10", "B11", "B12", "B13", "B14", "B15", "B16", "B17", "B18", "B19", "B20", "B21", "B22", "B23", "B24", "B25", "B26", "B27", "B28", "B29", "B30", "B31",
            "PC", "LR", "FP",
        };

        for (auto& k : identifiers)
        {
            Identifier id;
            id.mDeclaration = "CPU Register";
            langDef.mIdentifiers.insert(std::make_pair(std::string(k), id));
        }

        langDef.mTokenRegexStrings.push_back(std::make_pair<std::string, PaletteIndex>(R"##([a-zA-Z_]{1}[_a-zA-Z0-9]{0,}:)##", PaletteIndex::Identifier));

        langDef.mTokenize = [](const char* in_begin, const char* in_end, const char*& out_begin, const char*& out_end, PaletteIndex& paletteIndex) -> bool
        {
            paletteIndex = PaletteIndex::Max;

            while (in_begin < in_end && isascii(*in_begin) && isblank(*in_begin))
                in_begin++;

            if (in_begin == in_end)
            {
                out_begin = in_end;
                out_end = in_end;
                paletteIndex = PaletteIndex::Default;
            }
            else if (TokenizeCStyleString(in_begin, in_end, out_begin, out_end))
                paletteIndex = PaletteIndex::String;
            else if (TokenizeCStyleCharacterLiteral(in_begin, in_end, out_begin, out_end))
                paletteIndex = PaletteIndex::CharLiteral;
            else if (TokenizeAsmStyleIdentifier(in_begin, in_end, out_begin, out_end))
                paletteIndex = PaletteIndex::Identifier;
            else if (TokenizeAssemblyStyleNumber(in_begin, in_end, out_begin, out_end))
                paletteIndex = PaletteIndex::Number;
            else if (TokenizeX86StylePunctuation(in_begin, in_end, out_begin, out_end))
                paletteIndex = PaletteIndex::Punctuation;

            return paletteIndex != PaletteIndex::Max;
        };

        langDef.mCommentStart = "%comment";
        langDef.mCommentEnd = "%endcomment";
        langDef.mSingleLineComment = ";";

        langDef.mCaseSensitive = true;

        langDef.mName = "Assembly";
        inited = true;
    }
    return langDef;
}
