mov rax, 0x100
mov rbx, rax
push rbx
pop r11
mov rax, 0x12345678
push rax
push 0x12345678
push 0x11
pop r15
hlt
