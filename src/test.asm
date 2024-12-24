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
    cmp r11, 10000
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
