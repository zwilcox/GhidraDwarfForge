    .file "synthetic-cfi-start-aarch64.S"
    .text
    .globl _start
    .type _start,%function
_start:
    mov x29,xzr
    mov x30,xzr
    bl cfi_main
    mov x8,#93
    svc #0
    .size _start,.-_start
    .section .note.GNU-stack,"",%progbits
