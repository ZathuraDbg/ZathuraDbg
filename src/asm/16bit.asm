main:
    mov ax, 0x100
    mov bx, ax
    add ax, bx
    push ax
    pop di
    call add_hundred
    push di

add_hundred:
    add di, 0x100
    ret
