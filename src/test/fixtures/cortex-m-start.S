/* Minimal ARMv7-M reset and exception entry, deliberately Thumb-only. */
.syntax unified
.cpu cortex-m3
.thumb

.section .vectors,"a",%progbits
.global cortex_vectors
cortex_vectors:
    .word _stack_top
    .word Reset_Handler
    .word Default_Handler
    .word Default_Handler
    .word Default_Handler
    .word Default_Handler
    .word Default_Handler
    .word 0, 0, 0, 0
    .word SVC_Handler
    .word Default_Handler
    .word 0
    .word Default_Handler
    .word Default_Handler

.section .text.Reset_Handler,"ax",%progbits
.global Reset_Handler
.type Reset_Handler,%function
.thumb_func
Reset_Handler:
    ldr r0, =_sidata
    ldr r1, =_sdata
    ldr r2, =_edata
1:
    cmp r1, r2
    bcs 2f
    ldr r3, [r0], #4
    str r3, [r1], #4
    b 1b
2:
    ldr r1, =_sbss
    ldr r2, =_ebss
    movs r3, #0
3:
    cmp r1, r2
    bcs 4f
    str r3, [r1], #4
    b 3b
4:
    bl cortex_main
    b Default_Handler
.size Reset_Handler, .-Reset_Handler

.global SVC_Handler
.type SVC_Handler,%function
.thumb_func
SVC_Handler:
    tst lr, #4
    ite eq
    mrseq r0, msp
    mrsne r0, psp
    mov r1, lr
    mrs r2, ipsr
    b cortex_svc_body
.size SVC_Handler, .-SVC_Handler

.global cortex_psp_entry
.type cortex_psp_entry,%function
.thumb_func
cortex_psp_entry:
    ldr r0, =_psp_top
    msr psp, r0
    movs r0, #2
    msr control, r0
    isb
    bl cortex_psp_main
    b Default_Handler
.size cortex_psp_entry, .-cortex_psp_entry

.global Default_Handler
.type Default_Handler,%function
.thumb_func
Default_Handler:
    b Default_Handler
.size Default_Handler, .-Default_Handler

/* Adjacent byte objects prove that odd DATA addresses must never be Thumb-normalized. */
.section .data.bytes,"aw",%progbits
.balign 4
.global cortex_byte_pad
.type cortex_byte_pad,%object
cortex_byte_pad:
    .byte 0x11
.size cortex_byte_pad,1
.global cortex_odd_byte
.type cortex_odd_byte,%object
cortex_odd_byte:
    .byte 0x7b
.size cortex_odd_byte,1

.section .note.GNU-stack,"",%progbits
