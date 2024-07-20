main:
    mov $0x400, %rbx
    add %rax, %rbx
    mov %rbx, %rdi
    call subtract_hundred
    jmp nextblock
    push %rax

subtract_hundred:
    sub $0x100, %rdi
    mov %rdi, %rax
    mov $0x12, %rbx
    ret

nextblock:
    mov %rbx, %rax
    jmp nextblockagain

nextblockagain:
    mov %rcx, %rbx
    jmp nextblocktwice

nextblocktwice:
    mov %rcx, %rdx
    jmp anewblock

anewblock:
    mov %r9, %r8
    jmp main
