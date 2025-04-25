_start:
    MOV     X0, #5
    MOV     X1, #10
    BL      compute_sum
    CMP     X0, #20
    B.GT    greater_than_twenty
    B       end
    nop

greater_than_twenty:
    MOV     X2, #1
    B       end

compute_sum:
    STP     X29, X30, [SP, #-16]!
    MOV     X29, SP
    ADD     X0, X0, X1
    CMP     X0, #15
    B.LE    skip_multiply
    MUL     X0, X0, X1

skip_multiply:
    LDP     X29, X30, [SP], #16
    RET

end:
    MOV     X8, #93
    MOV     X0, #0
    SVC     #0
