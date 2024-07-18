main:
  mov eax, 0x100
  mov ebx, eax
  add eax, ebx
  push eax
  pop edi
  call add_hundred
  push edi


add_hundred:
  add edi, 0x100
  ret
