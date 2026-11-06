    .file "cfi-shrinkwrap-aarch64.S"
    .cfi_sections .debug_frame
    .text
    .macro ordinary_rules
    .cfi_def_cfa 31,0
    .cfi_same_value 30
    .cfi_register 32,30
    .cfi_val_offset 31,0
    .cfi_same_value 19
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,20,21,22,23,24,25,26,27,28,29
    .cfi_undefined \reg
    .endr
    .endm

    .globl cf_checkpoint
    .type cf_checkpoint,%function
cf_checkpoint:
    .cfi_startproc simple
    ordinary_rules
    adrp x1,cf_observation
    ldr x1,[x1,#:lo12:cf_observation]
    cset w1,ne
    nop
    ret
    .cfi_endproc
    .size cf_checkpoint,.-cf_checkpoint

    .globl cf_recurse,cf_saved,cf_restored,cf_entry_branch,cf_allocated,cf_return_saved,cf_fast_return
    .type cf_recurse,%function
cf_recurse:
    .cfi_startproc simple
    ordinary_rules
cf_entry_branch:
    cbz x0,cf_fast_return
    sub sp,sp,#32
cf_allocated:
    .cfi_def_cfa_offset 32
    str x19,[sp,#16]
cf_saved:
    .cfi_offset 19,-16
    mov x19,#0x5100
    add x19,x19,x0
    str x30,[sp,#24]
cf_return_saved:
    .cfi_offset 30,-8
    .cfi_offset 32,-8
    sub x0,x0,#1
    bl cf_recurse
    bl cf_checkpoint
    ldr x19,[sp,#16]
    .cfi_same_value 19
    ldr x30,[sp,#24]
    .cfi_same_value 30
    .cfi_register 32,30
    add sp,sp,#32
cf_restored:
    .cfi_def_cfa_offset 0
cf_fast_return:
    ret
    .cfi_endproc
    .size cf_recurse,.-cf_recurse

    .globl _start
    .type _start,%function
_start:
    .cfi_startproc simple
    ordinary_rules
    .cfi_undefined 30
    .cfi_undefined 32
    mov x29,xzr
    mov x30,xzr
    mov x19,#0x6172
    mov x0,#3
    bl cf_recurse
    mov x1,#0x6172
    cmp x19,x1
    cset x0,ne
    mov x8,#93
    svc #0
    .cfi_endproc
    .size _start,.-_start
    .section .rodata
    .balign 8
cf_observation:
    .quad 0x1234
    .section .note.GNU-stack,"",%progbits
