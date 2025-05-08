main:
    MOVS    r0, #5
    MOVS    r1, #10
    BL      compute_sum
    VMOV    s0, r0
    VCVT.F32.S32 s0, s0
    VMOV.F32 s1, #20.0
    VCMP.F32 s0, s1
    VMRS    APSR_nzcv, FPSCR
    BHI     greater_than_twenty
    B       end

greater_than_twenty:
    MOVS    r2, #1
    B       end

compute_sum:
    PUSH    {r4, lr}
    VMOV    s0, r0
    VMOV    s1, r1
    VCVT.F32.S32 s0, s0
    VCVT.F32.S32 s1, s1
    VADD.F32 s2, s0, s1
    VMOV.F32 s3, #15.0
    VCMP.F32 s2, s3
    VMRS    APSR_nzcv, FPSCR
    BLS     skip_multiply
    VMUL.F32 s2, s2, s1

skip_multiply:
    VCVT.S32.F32 s2, s2
    VMOV    r0, s2
    POP     {r4, lr}
    BX      lr

end:
    MOVS    r7, #1
    MOVS    r0, #0
    SVC     #0
