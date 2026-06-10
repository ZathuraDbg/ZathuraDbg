bits 64
default rel

section .text
_start:
    mov rax, 1
    mov rdi, 1
    lea rsi, [message]
    mov rdx, message_len
    syscall

    mov rcx, 5
    xor rbx, rbx

count:
    add rbx, rcx
    loop count

    call double_result

    mov rax, 60
    xor rdi, rdi
    syscall

double_result:
    add rbx, rbx
    ret

section .data
message: db "Hello from ZathuraDbg", 10
message_len equ $ - message
