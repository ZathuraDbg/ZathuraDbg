main:
    mov rax, 0x42
    push rax
    pop rdi 
    call square
    push rdi        ; rdi = 42 * 42 = 1764
    hlt

square:
	 push    rbp
     mov     rbp, rsp
     mov     [rbp-4], edi
     mov     eax, [rbp-4]
     imul    eax, eax
     pop     rbp
     ret