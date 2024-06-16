main:
	mov rax, 0x100
	mov rdi, 0x13
	call square
	push rdi
	hlt

square:
	 push    rbp
     mov     rbp, rsp
     mov     [rbp-4], edi
     mov     eax, [rbp-4]
     imul    eax, eax
     pop     rbp
     ret