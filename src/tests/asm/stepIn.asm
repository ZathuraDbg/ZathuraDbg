main:
  mov rax, 0x1000
  call step1
  call step1
  call step2
  push rax

step1:
  inc rax
  ret

step2:
  call step3
  inc rax
  ret

step3:
  inc rax
  ret
