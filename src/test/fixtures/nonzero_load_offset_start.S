/* Linux x86-64 test entry point; no libc/startup objects are needed. */
    .section .text.start,"ax",@progbits
    .globl _start
    .type _start,@function
_start:
    call nonzero_main
    movl %eax, %edi
    movl $60, %eax
    syscall
    .size _start, .-_start
    .section .note.GNU-stack,"",@progbits
