// One real function switches ARM -> Thumb -> ARM, followed by a literal pool.
// Keep the allocation separate so its complete code/data inventory is auditable.
.syntax unified
.arch armv7-a
.section .forge_mixed,"ax",%progbits
.balign 4
.arm
.global mixed_body
.type mixed_body,%function
mixed_body:
#ifdef FORGE_MIXED_SPLIT
    b mixed_code
    .word 0xfeedface
mixed_code:
#endif
    add r0, r0, #3
    adr r3, mixed_thumb
    add r3, r3, #1
    bx r3
.thumb
mixed_thumb:
    adds r0, r0, #5
    nop
    adr r3, mixed_arm_return
    bx r3
.arm
mixed_arm_return:
    add r0, r0, #7
    ldr r2, mixed_literal
    add r0, r0, r2
    bx lr
.size mixed_body, .-mixed_body
mixed_literal:
    .word 0x1234
.section .note.GNU-stack,"",%progbits
