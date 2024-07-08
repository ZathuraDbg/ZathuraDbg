main:
; 	mov abc
    mov rbx, 0x400
    ; mov aps
    add rbx, rax
    mov rdi, rbx
    call subtract_hundred 
    push rax

subtract_hundred:
    sub rdi, 0x100
    mov rax, rdi
    ret