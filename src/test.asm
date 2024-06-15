main:
	mov rax, 0x100
	mov rbx, rax
	jmp testlabel
	push rbx
	pop r11
	mov rax, 0x12345678
	push rax
	mov rdi, 0x13
	call square
	push rax
	hlt

testlabel:
	add rbx, rbx
	push rbx

square:
	 push    rbp
     mov     rbp, rsp
     mov     [rbp-4], edi
     mov     eax, [rbp-4]
     imul    eax, eax
     pop     rbp
     ret