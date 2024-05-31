main:
	mov rax, 0x100
	mov rbx, rax
	push rbx
	pop r11
	mov rax, 0x12345678
	push rax
	mov rdi, 0x11
; 	call sq
	push rdi
	hlt
; 
; sq:
; 	 push    rbp
;      mov     rbp, rsp
;      mov     [rbp-4], edi
;      mov     eax, [rbp-4]
;      imul    eax, eax
;      pop     rbp
;      ret