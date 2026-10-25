#include <asm/unistd.h>
    .set noreorder
    .text
    .globl _start
    .type _start, @function
_start:
    addiu $29, $29, -32
    jal fixture_main
    nop
    move $4, $2
    li $2, __NR_exit
    syscall
    break
    .size _start, .-_start
    .section .note.GNU-stack,"",@progbits
