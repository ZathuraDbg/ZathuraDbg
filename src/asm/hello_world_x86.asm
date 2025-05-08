_start:
    mov rax, 1              
    mov rdi, 1 
    lea rsi, [rip + msg]             
    mov rdx, 14
    syscall
    mov rax, 60
    xor rdi, rdi
    syscall

msg:
.ascii "Hello, world!\n"