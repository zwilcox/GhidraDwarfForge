/* The conditional branch incorporates a nontrivial delay-slot value update. */
    .set noreorder
    .text
    .globl delay_context
    .ent delay_context
delay_context:
    beq $a0,$zero,1f
    addiu $v0,$a0,9
    addiu $v0,$v0,3
1:  jr $ra
    nop
    .end delay_context
    .section .note.GNU-stack,"",@progbits
