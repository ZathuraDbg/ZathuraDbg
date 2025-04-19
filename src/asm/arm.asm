main:
    MOVS    r0, #5
    MOVS    r1, #10
    BL      compute_sum
    CMP     r0, #20
    BHI     greater_than_twenty
    B       end
    nop

greater_than_twenty:
    MOVS    r2, #1
    B       end

compute_sum:
    PUSH    {r4, lr}
    MOV     r4, sp
    ADDS    r0, r0, r1
    CMP     r0, #15
    BLS     skip_multiply
    MUL     r0, r0, r1

skip_multiply:
    POP     {r4, lr}
    BX      lr

end:
    MOVS    r7, #1
    MOVS    r0, #0
    SVC     #0