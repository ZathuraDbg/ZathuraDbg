main:
    mov rbx, 0x400
    mov rax, 0x4010000000000000
	push rax
	fild qword [rsp]
    add rsp, 8
    add rbx, rax
    mov rdi, rbx
    push rdi
    inc rdi
    call subtract_hundred
    cmp r11, 60000
    jne nextblock
    push rax
    push rbx
    
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
