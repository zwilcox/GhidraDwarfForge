.syntax unified
.arm
.text
.global _start
.type _start, %function
_start:
    mov r0, #7
    bl be8_probe
    movw r1, #0x334b
    movt r1, #0x1122
    cmp r0, r1
    moveq r0, #0
    movne r0, #1
    mov r7, #1
    svc #0
.size _start, .-_start
.section .note.GNU-stack,"",%progbits
