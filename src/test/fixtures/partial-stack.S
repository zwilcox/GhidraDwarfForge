/* The argument at entry RSP+8 moves to RSP+40 after the four-byte subtraction. */
    .text
    .globl _start
    .type _start,@function
_start:
    pushq $23
    call partial_stack
    addq $8,%rsp
    xorl %edi,%edi
    movl $60,%eax
    syscall
    .size _start,.-_start

    .globl partial_stack
    .type partial_stack,@function
partial_stack:
    subq $32,%rsp
    .fill 23,1,0x90
    addq $32,%rsp
    ret
    .size partial_stack,.-partial_stack
    .data
    .globl scope_storage
scope_storage:
    .long 101, 202
    .section .note.GNU-stack,"",@progbits
