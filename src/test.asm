bits 64
default rel

section .text
_start:
    ; Write a rodata string through a computed length.
    mov rax, 1
    mov rdi, 1
    lea rsi, [message]
    mov rdx, message_len
    syscall

    ; Exercise labels, loop, call/ret, and writable data.
    mov rcx, 5
    xor rbx, rbx

count:
    add rbx, rcx
    loop count

    call double_result
    mov [result], rbx

    ; Exit is a real execution terminator in the Icicle syscall bridge.
    mov rax, 60
    xor rdi, rdi
    syscall

double_result:
    add rbx, rbx
    ret

align 16
padding: times 4 db 0x90

section .rodata
message: db "Hello from ZathuraDbg", 10
message_len equ $ - message

section .data
seed: dq 0x1122334455667788
bytes: db 0xde, 0xad, 0xbe, 0xef

section .bss
result: resq 1
scratch: resb 16
