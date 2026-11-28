.set noreorder
.section .text.low,"ax",@progbits
    nop

.section .text.high,"ax",@progbits
.globl boot_case
.type boot_case,@function
boot_case:
    jal eval_probe
    nop
1:
    b 1b
    nop
.size boot_case,.-boot_case

.globl eval_probe
.type eval_probe,@function
eval_probe:
    dla $4,eval_first
    lw $2,8($4)
    dla $5,eval_second
    addiu $2,$2,23
    sw $2,8($5)
.globl eval_transition
eval_transition:
    lw $2,8($5)
    jr $31
    nop
.size eval_probe,.-eval_probe

.data
.balign 8
.globl eval_first
eval_first:
    .dword eval_first
    .word 19,0
.globl eval_second
eval_second:
    .dword eval_first
    .word -1,0
