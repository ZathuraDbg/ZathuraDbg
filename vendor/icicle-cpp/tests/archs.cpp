#include "icicle.h"
#include <vector>
#include <iostream>
#include "keystone/keystone.h"

int test()
{
    std::vector<std::string> works = {};
    std::vector<std::string> targets = {
            "aarch64", "arm", "armeb", "armebv7r", "armv4", "armv4t", "armv5tej",
            "armv6m", "armv7s", "armv8r", "i386", "m68k", "mips", "mipsel",
            "mipsisa32r6", "mipsisa32r6el", "msp430", "powerpc", "powerpc64", "powerpc64le",
            "riscv32", "riscv32gc", "riscv32i", "riscv32imc", "riscv64", "riscv64gc",
            "thumbeb", "thumbv4t", "thumbv5te", "thumbv6m", "thumbv7neon", "x86_64", "xtensa"
    };

    for (auto&i : targets)
    {
        Icicle* vm = icicle_new(i.c_str(), false, false, false, false, false, false, false, false);
        if (!vm)
        {
            printf("Failed to create %s VM\n", i.c_str());
        }
        else
        {
            works.emplace_back(i.c_str());
        }
        icicle_free(vm);
    }

    for (auto&i : works)
    {
        printf("%s\n", i.c_str());
    }

    return 0;
}

int violation_hook_callback(void* user_data, uint64_t address, uint8_t permission, int unmapped) {
    const char* perm_str = "unknown";
    // Check for specific permission value passed from Rust
    // Assumes Rust passes perm::READ (1), perm::WRITE (2), or perm::EXEC (4)
    if (permission == 1) perm_str = "read";      // Check equality
    else if (permission == 2) perm_str = "write"; // Check equality
    else if (permission == 4) perm_str = "execute"; // Check equality
    // Note: Rust code currently only passes one specific violated permission bit.

    // Keep this essential log
    printf("[VIOLATION HOOK]: address=0x%lx, permission=%s, unmapped=%s\n",
          address, perm_str,
           unmapped ? "true" : "false");
	exit(0);
    // Return 1 to resume execution. Crucially, the Rust handler only advances
    // PC for the write-to-0 case. Other violations will repeat if not handled
    // differently (e.g., by stopping execution here or advancing PC in Rust).
    return 1;
}


int test2()
{
    ks_engine* ks = nullptr;
    auto vm = icicle_new("x86_64", false, false, false, false, true, true, false, true);
    ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
    ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_INTEL);
    std::string asmStr = R"(
main:
	mov rbx, 0x400
	movabs rax, 0x4010000000000000
	movq xmm0, rax
	punpcklqdq xmm0, xmm0
	add rbx, rax
	mov rdi, rbx
	push rdi
	push rdi
	inc rdi
    call subtract_hundred
    call subtract_hundred
    cmp r11, 1000
    jne nextblock
    push rax
    push rbx
    nop

subtract_hundred:
    sub rdi, 0x100
    mov rax, rdi
    mov rbx, 0x12
    ret

nextblock:
	mov rax, rbx
	jmp nextblockagain

nextblockagain:
	mov rbx, rcx
	jmp nextblocktwice

nextblocktwice:
	mov rdx, rcx
	jmp anewblock

anewblock:
	mov r8, r9
	inc r11
	jmp main
)";
	int err = 0;
	size_t size;
	size_t count;
	unsigned char *encode;

    err = ks_asm(ks, asmStr.c_str(), 0, &encode, &size, &count);
	if (err)
	{
		printf("Failed to encode string\n");
	}
	icicle_mem_map(vm, 0x10000, 0x1000, MemoryProtection::ExecuteReadWrite);
	icicle_mem_write(vm, 0x10000, encode, size);
	icicle_mem_map(vm, 0x300000, 5 * 1024 * 1024, MemoryProtection::ReadWrite);
	// icicle_mem_map(vm, 0x20000, 0x40000, MemoryProtection::ReadWrite);
	// icicle_set_sp(vm, 0x60000);
	icicle_reg_write(vm, "rbp", 0x300000 + 5 * 1024 * 1024);
	icicle_reg_write(vm, "rsp", 0x300000 + 5 * 1024 * 1024);
	icicle_set_pc(vm, 0x10000);
	icicle_add_breakpoint(vm, 0x1003a);
	icicle_add_violation_hook(vm, violation_hook_callback, nullptr);
	// while (true)
	// {
	auto status = icicle_run(vm);
	printf("Status %d\n", (int)status);
	printf("PC: %llx\n", icicle_get_pc(vm));
	printf("SP: %llx\n", icicle_get_sp(vm));
	// }

	icicle_free(vm);
	return 0;
}

int main()
{
    test2();

    return 0;
}
