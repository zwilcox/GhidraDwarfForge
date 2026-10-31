.file "arm-symbol-boundary.S"
.syntax unified
.arch armv7-a
.eabi_attribute 28, 1
.section .text.start,"ax",%progbits
.arm
.global _start
.type _start,%function
_start:
    mov r0, #7
    blx boundary
    cmp r0, #12
    movne r0, #1
    moveq r0, #0
    mov r7, #1
    svc #0
.size _start, .-_start
.section .text.tail,"ax",%progbits
.thumb
.thumb_func
.global boundary
.type boundary,%function
boundary:
    adds r0, #5
    bx lr
.size boundary, .-boundary
.section .note.GNU-stack,"",%progbits
