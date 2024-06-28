#include "interpreter.hpp"

uintptr_t ENTRY_POINT_ADDRESS = 0x1000;
uintptr_t MEMORY_ALLOCATION_SIZE = 2 * 1024 * 1024;
uintptr_t STACK_ADDRESS = 0x300000;
uint64_t CODE_BUF_SIZE = 0x3000;
uintptr_t STACK_SIZE = 5 * 1024 * 1024;

uint8_t* codeBuf = nullptr;
uc_context* context = nullptr;
uc_engine *uc = nullptr;

uint64_t codeCurrentLen = 0;
uint64_t lineNo = 1;
bool debugStopped = false;
bool continueOverBreakpoint = false;

std::unordered_map <std::string, uint64_t> labelLineNoMap = {};
// either put values in this vector with n - 1 or set lineNo = lineNo - 1
std::vector<int> breakpointLines = {};

std::string toLowerCase(const std::string& input) {
    std::string result = input; // Create a copy of the input string
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) {
        return std::tolower(c);
    });
    return result;
}

std::string toUpperCase(const std::string& input) {
    std::string result = input; // Create a copy of the input string
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) {
        return std::toupper(c);
    });
    return result;
}

int regNameToConstant(std::string name){
    if (x86RegInfoMap.find(name) == x86RegInfoMap.end()){
        LOG_ALERT("Requested register not found: " << name);
        return UC_X86_REG_INVALID;
    }

    return x86RegInfoMap[name].second;
}

void showRegs(){
    LOG_DEBUG("Showing registers");
    int rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8, r9, r10, r11, r12, r13, r14, r15, rip,
        ah, al, ax, bh, bl, bx, ch, cl, cx, dh, dl, dx, si, di, bp, sp, r8d, r9d, r10d, r11d, r12d,
        r13d, r14d, r15d, r8w, r9w, r10w, r11w, r12w, r13w, r14w, r15w, r8b, r9b, r10b, r11b, r12b, r13b, r14b,
        r15b, ds, es, fs, gs, ss, eflags, fs_base, gs_base, flags, idtr, ldtr, tr, mm0, mm1, mm2, mm3, mm4, mm5, mm6,
        mm7, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, ymm0, ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, zmm0,
        zmm1, zmm2, zmm3, zmm4,zmm5, zmm6, zmm7, cr0, cr1, cr2, cr3, cr4, cr8,
        dr0, dr1, dr2, dr3, dr4, dr5, dr6, dr7, dil, edi, sil, esi, bpl, ebp, spl, esp, cs;

    uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    uc_reg_read(uc, UC_X86_REG_RBX, &rbx);
    uc_reg_read(uc, UC_X86_REG_RCX, &rcx);
    uc_reg_read(uc, UC_X86_REG_RDX, &rdx);
    uc_reg_read(uc, UC_X86_REG_RSI, &rsi);
    uc_reg_read(uc, UC_X86_REG_RDI, &rdi);
    uc_reg_read(uc, UC_X86_REG_RBP, &rbp);
    uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
    uc_reg_read(uc, UC_X86_REG_R8, &r8);
    uc_reg_read(uc, UC_X86_REG_R9, &r9);
    uc_reg_read(uc, UC_X86_REG_R10, &r10);
    uc_reg_read(uc, UC_X86_REG_R11, &r11);
    uc_reg_read(uc, UC_X86_REG_R12, &r12);
    uc_reg_read(uc, UC_X86_REG_R13, &r13);
    uc_reg_read(uc, UC_X86_REG_R14, &r14);
    uc_reg_read(uc, UC_X86_REG_R15, &r15);
    uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);
    uc_reg_read(uc, UC_X86_REG_CS, &cs);
    uc_reg_read(uc, UC_X86_REG_DS, &ds);
    uc_reg_read(uc, UC_X86_REG_SS, &ss);
    uc_reg_read(uc, UC_X86_REG_ES, &es);
    uc_reg_read(uc, UC_X86_REG_FS, &fs);
    uc_reg_read(uc, UC_X86_REG_GS, &gs);
    uc_reg_read(uc, UC_X86_REG_FS_BASE, &fs_base);
    uc_reg_read(uc, UC_X86_REG_GS_BASE, &gs_base);

    printf("RAX = 0x%x\t\t", rax);
    printf("RBX = 0x%x\n", rbx);
    printf("RCX = 0x%x\t\t", rcx);
    printf("RDX = 0x%x\n", rdx);
    printf("RSI = 0x%x\t\t", rsi);
    printf("RDI = 0x%x\n", rdi);
    printf("RBP = 0x%x\t\t", rbp);
    printf("RSP = 0x%x\n", rsp);
    printf("R8 = 0x%x\t\t", r8);
    printf("R9 = 0x%x\n", r9);
    printf("R10 = 0x%x\t\t", r10);
    printf("R11 = 0x%x\n", r11);
    printf("R12 = 0x%x\t\t", r12);
    printf("R13 = 0x%x\n", r13);
    printf("R14 = 0x%x\t\t", r14);
    printf("R15 = 0x%x\n", r15);
    printf("RIP = 0x%x\t\t", rip);
    printf("EFLAGS = 0x%x\n", eflags);
    printf("CS = 0x%x\t\t", cs);
    printf("SS = 0x%x\n", ss);
    printf("DS = 0x%x\t\t", ds);
    printf("FS = 0x%x\n", fs);
    printf("GS = 0x%x\t\t", ds);
    printf("FS_BASE = 0x%x\n", fs_base);
    printf("GS_BASE = 0x%x\n", gs_base);
}
// TODO: Add a check while adding a new register so we don't have to add a check in the below
// two functions

uint64_t getRegisterValue(const std::string& regName){
    auto entry = x86RegInfoMap[toUpperCase(regName)];
    auto size = entry.first;
    uint64_t value{};

    if (size == 8) {
        uint8_t valTemp8;
        uc_reg_read(uc, entry.second, &valTemp8);
        value = valTemp8; // force zero extension
    }
    else if (size == 16) {
        uint16_t valTemp16;
        uc_reg_read(uc, entry.second, &valTemp16);
        value = valTemp16; // force zero extension
    }
    else if (size == 32) {
        uint32_t valTemp32;
        uc_reg_read(uc, entry.second, &valTemp32);
        value = valTemp32; // force zero extension
    }
    else if (size == 64) {
        uint64_t valTemp64;
        uc_reg_read(uc, entry.second, &valTemp64);
        value = valTemp64; // force zero extension
    }

    // 80, 128 and 512 bit unimplemented
    return value;
}

std::pair<bool, uint64_t> getRegister(const std::string& name){
    std::pair<bool, uint64_t> res = {false, 0};

    if (!codeHasRun){
        return {true, 0x00};
    }

    auto value = getRegisterValue(name);
    res = {true, value};
    return res;
}

bool ucInit(){
    LOG_DEBUG("Initializing unicorn engine");
    auto err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);

    if (err) {
        LOG_ERROR("Failed to initialise Unicorn Engine!");
        tinyfd_messageBox("ERROR!", "Could not initialize Unicorn Engine. Please check if the environment is correctly setup.", "ok", "error", 0);
        return false;
    }

    return true;
}

bool createStack(){
    LOG_DEBUG("Creating stack");

    if (!ucInit()){
        return false;
    }

    uint8_t zeroBuf[STACK_SIZE];

    memset(zeroBuf, 0, STACK_SIZE);
    if (uc_mem_map(uc, STACK_ADDRESS, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)){
        LOG_ERROR("Failed to memory map the stack!!");
        return false;
    }

    if (uc_mem_write(uc, STACK_ADDRESS, zeroBuf, STACK_SIZE)) {
        LOG_ERROR("Failed to write to the stack!!");
        return false;
    }

    uint64_t stackBase = STACK_ADDRESS + STACK_SIZE;
    if (uc_reg_write(uc, UC_X86_REG_RSP, &stackBase)){
        LOG_ERROR("Failed to write the stack pointer to base pointer, quitting!!");
        return false;
    }

    LOG_DEBUG("wrote to rsp ");
    if (uc_reg_write(uc, UC_X86_REG_RBP, &stackBase)){
        printf("Failed to write base pointer to memory, quitting!\n");
        return false;
    }

    return true;
}

void handleUCErrors(uc_err err){
    if (err == UC_ERR_INSN_INVALID){
        LOG_ERROR("Failed on uc_emu_start(): Invalid Instruction provided.");
        tinyfd_messageBox("ERROR!", "Invalid instruction found in the provided code!!", "ok", "error", 0);
    }
    else if (err < UC_ERR_VERSION){
                LOG_ERROR("Failed on uc_emu_start() with error returned " <<  err << ": " << uc_strerror(err));
        tinyfd_messageBox("INTERNAL ERROR!", "Failed to run the code because the internal configuration"
                                             " has some issues. Please report this on GitHub with your logs!", "ok", "error", 0);
    }
    else if (err > UC_ERR_VERSION && err < UC_ERR_HOOK){
                LOG_ERROR("Unmapped Memory Access Error!");

        if (err == UC_ERR_READ_UNMAPPED){
                    LOG_ERROR("Failed on uc_emu_start(): Attempt to read from memory which is not mapped.");
            tinyfd_messageBox("Memory Access Error!", "Attempt to read from memory location which is not mapped!!", "ok", "error", 0);
        }
        else if (err == UC_ERR_WRITE_UNMAPPED){
                    LOG_ERROR("Failed on uc_emu_start(): Attempt to write to memory which is not mapped.");
            tinyfd_messageBox("Memory Access Error!", "Attempt to write to memory location which is not mapped!!", "ok", "error", 0);
        }
        else if (err == UC_ERR_FETCH_UNMAPPED){
                    LOG_ERROR("Failed on uc_emu_start(): Attempt to fetch from memory which is not mapped.");
            tinyfd_messageBox("Memory Access Error!", "Attempt to fetch from memory location which is not mapped!!", "ok", "error", 0);
        }
    }
    else if (err > UC_ERR_MAP && err < UC_ERR_ARG){
        // MEMORY PROTECTION ERRORS
        LOG_ERROR("Memory Protection Error!");

        if (err == UC_ERR_WRITE_PROT){
                    LOG_ERROR("Failed on uc_emu_start(): Attempt to write to memory which does not have write permission enabled.");
            tinyfd_messageBox("Memory Protection Error!", "Attempt to write to memory location which does not have"
                                                          " write permission enabled!!", "ok", "error", 0);
        }
        else if (err == UC_ERR_READ_PROT){
                    LOG_ERROR("Failed on uc_emu_start(): Attempt to read memory which does not have read permission enabled.");
            tinyfd_messageBox("Memory Protection Error!", "Attempt to write to memory location which does not have write"
                                                          " permission enabled!!", "ok", "error", 0);
        }
        else if (err == UC_ERR_FETCH_PROT){
            LOG_ERROR("Failed on uc_emu_start(): Attempt to fetch memory which does not have fetch permission enabled.");
            tinyfd_messageBox("Memory Protection Error!", "Attempt to write to memory location which does not have fetch"
                                                          " permission enabled!!", "ok", "error", 0);
        }
    }
    else if ((err > UC_ERR_ARG) && (err < UC_ERR_HOOK_EXIST)){
        // Unaligned error
        LOG_ERROR("Unaligned Memory Access Error!");
        if (err == UC_ERR_READ_UNALIGNED){
            LOG_ERROR("Failed on uc_emu_start(): Attempt to read data from memory at an address that is not properly "
                      "aligned for the data type being accessed");
            tinyfd_messageBox("Unaligned Memory Access Error!", "Attempt to read data from memory at an address that is not properly "
                                                                "aligned for the data type being accessed", "ok", "error", 0);
        }
        else if (err == UC_ERR_WRITE_UNALIGNED){
                LOG_ERROR("Failed on uc_emu_start(): Attempt to write data to memory at an address that is not properly "
                              "aligned for the data type being accessed");
                tinyfd_messageBox("Unaligned Memory Access Error!", "Attempt to write data to memory at an address that is not properly "
                                                                "aligned for the data type being accessed", "ok", "error", 0);
        }
        else if (err == UC_ERR_FETCH_UNALIGNED){
                    LOG_ERROR("Failed on uc_emu_start(): Attempt to fetch data from memory at an address that is not properly "
                              "aligned for the data type being accessed");
                    tinyfd_messageBox("Unaligned Memory Access Error!", "Attempt to fetch data from memory at an address that is not properly "
                                                                "aligned for the data type being accessed", "ok", "error", 0);
        }
    }
    else if (err == UC_ERR_MAP){
                LOG_ERROR("Failed on uc_emu_start(): Attempt to access memory that is not mapped.");
        tinyfd_messageBox("Memory Access Error!", "Attempt to access memory that is not mapped.", "ok", "error", 0);
    }
    else if (err == UC_ERR_EXCEPTION){
        LOG_ERROR("Failed on uc_emu_start(): Exception occurred during emulation.");
        tinyfd_messageBox("Exception Error!", "Exception occurred during emulation which is not manually handled.", "ok", "error", 0);
    }
}

bool resetState(){
    codeHasRun = false;
    stepClickedOnce = false;
    continueOverBreakpoint = false;

    codeCurrentLen = 0;
    codeFinalLen = 0;
    lineNo = 0;

    assembly.clear();
    assembly.str("");
    instructionSizes.clear();
    addressLineNoMap.clear();
    editor->ClearExtraCursors();
    editor->ClearSelections();
    editor->HighlightDebugCurrentLine(-1);
    editor->HighlightBreakpoints(-1);
    breakpointLines.clear();

    if (uc != nullptr){
        uc_close(uc);
        uc = nullptr;
    }

    context = nullptr;
    for (auto& reg: registerValueMap){
        registerValueMap[reg.first] = "00";
    }

    if (!createStack()){
        LOG_DEBUG("Unable to create stack!");
        return false;
    }

    return true;
}


bool stepCode(size_t instructionCount){
    LOG_DEBUG("Stepping into code!");

    if (codeCurrentLen >= codeFinalLen){
        LOG_DEBUG("Code execution is complete!");
        uc_emu_stop(uc);
        return true;
    }

    uint64_t rip;

    uc_context_restore(uc, context);
    uc_reg_read(uc, UC_X86_REG_RIP, &rip);


    auto err = uc_emu_start(uc, rip, ENTRY_POINT_ADDRESS + CODE_BUF_SIZE, 0, instructionCount);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
               err, uc_strerror(err));
    }

    {
        char *ptr;
        int ret;

        if (codeCurrentLen >= codeFinalLen){
            uc_context_save(uc, context);
            LOG_DEBUG("Code execution is complete!");
            return true;
        }

        uc_reg_read(uc, UC_X86_REG_RIP, &rip);
        ret = std::stoi(addressLineNoMap[std::to_string(rip)]);
        editor->HighlightDebugCurrentLine(ret - 1);
        lineNo = ret;
    }

    uc_context_save(uc, context);
    codeHasRun = true;

    LOG_DEBUG("Code ran once!");
    return true;
}

void hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data){
    LOG_DEBUG("Hook called!");
    int lineNumber =(stoi(addressLineNoMap[std::to_string(address)]));

    LOG_DEBUG("At line number: " << lineNumber);
    if (std::find(breakpointLines.begin(), breakpointLines.end(), lineNumber) != breakpointLines.end()){
       editor->HighlightDebugCurrentLine(lineNumber - 1);
        if (!continueOverBreakpoint){
            LOG_DEBUG("Breakpoint hit!");
            uc_emu_stop(uc);
            uc_context_save(uc, context);
            continueOverBreakpoint = true;
            return;
        }
        else{
            continueOverBreakpoint = false;
        }
  }

    codeCurrentLen += size;
}

bool runCode(const std::string& code_in, uint64_t instructionCount)
{
    LOG_DEBUG("Running code...");

    uc_err err;
    uint8_t* code;

    if (codeBuf == nullptr){
        codeBuf = (uint8_t*)malloc(CODE_BUF_SIZE);
        memset(codeBuf, 0, CODE_BUF_SIZE);
        LOG_DEBUG("Code buffer allocated!");
    }

    code = (uint8_t*)(code_in.c_str());
    memcpy(codeBuf, code, code_in.length());

    uc_mem_map(uc, ENTRY_POINT_ADDRESS, MEMORY_ALLOCATION_SIZE, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC);
    if (uc_mem_write(uc, ENTRY_POINT_ADDRESS, codeBuf, CODE_BUF_SIZE - 1)) {
        LOG_ERROR("Failed to write emulation code to memory, quit!\n");
        return false;
    }

    uc_reg_write(uc, UC_X86_REG_RIP, &ENTRY_POINT_ADDRESS);

    if (context == nullptr){
        uc_context_alloc(uc, &context);
    }

    uc_hook trace;
    uc_hook_add(uc, &trace, UC_HOOK_CODE, (void*)hook, nullptr, 1, 0);
    if (instructionCount == 0 || (stepClickedOnce)){
        err = uc_emu_start(uc, ENTRY_POINT_ADDRESS, ENTRY_POINT_ADDRESS + CODE_BUF_SIZE, 0, instructionCount);

        if (err) {
            handleUCErrors(err);
            return false;
        }
    }

    if (instructionCount == 0){
        free(codeBuf);
        codeBuf = nullptr;
    }
    else{
        uc_context_save(uc, context);
        editor->HighlightDebugCurrentLine(0);
        stepClickedOnce = true;
    }

    LOG_DEBUG("Ran code successfully!");
    codeHasRun = true;
    return true;
}