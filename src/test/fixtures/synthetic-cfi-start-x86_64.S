    .file "synthetic-cfi-start-x86_64.S"
    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp,%ebp
    call cfi_main
    mov %eax,%edi
    mov $60,%eax
    syscall
    .size _start,.-_start
    .section .note.GNU-stack,"",@progbits
