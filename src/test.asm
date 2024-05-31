mov rax, 0x100
mov rbx, rax
push rbx
pop r11
push 0x12345678
pop r15
hlt
