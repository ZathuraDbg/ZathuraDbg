main:
    mov rbx, 0x400
    add rbx, rax
    mov rdi, rbx
    call subtract_hundred
    jmp nextblock
    push rax
    
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
	jmp main