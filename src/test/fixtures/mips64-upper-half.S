.set noreorder
.section .text.low,"ax",@progbits
.globl low_entry
.type low_entry,@function
low_entry:
    addiu $2,$0,3
    jr $31
    nop
.size low_entry,.-low_entry

.section .text.high,"ax",@progbits
.globl high_add
.type high_add,@function
high_add:
    addu $2,$4,$5
    jr $31
    nop
.size high_add,.-high_add

.globl boot_case
.type boot_case,@function
boot_case:
    addiu $4,$0,19
    addiu $5,$0,23
    jal high_add
    nop
    dla $8,high_word
    sw $2,0($8)
.globl stop_case
stop_case:
    b stop_case
    nop
.size boot_case,.-boot_case

.data
.globl high_word
.type high_word,@object
high_word:
    .word 0
.size high_word,.-high_word
