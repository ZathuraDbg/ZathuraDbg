main:
    mov rax, 0x100
    mov rbx, 0x200
    add rbx, rax
    mov rdi, rbx
    call subtract_hundred 
    cmp rax, 0x100
    jne zero_regs

subtract_hundred:
    sub rdi, 0x100
    mov rax, rdi
    ret

zero_regs:
    mov rax, 0x00
    mov rbx, rax 
    mov rcx, rbx
    mov rdx, rcx
    hlt 