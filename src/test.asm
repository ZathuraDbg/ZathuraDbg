mov rax, 0x100
mov rbx, rax
push rbx
pop r11
push 0x1230
jmp rando
pop r15
hlt
