    .file "cfi-encoder-aarch64.S"
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
    nop
    ret
    .cfi_endproc
    .size cf_checkpoint,.-cf_checkpoint

    .globl cf_recurse,cf_saved,cf_restored
    .type cf_recurse,%function
cf_recurse:
    .cfi_startproc simple
    ordinary_rules
    stp x19,x30,[sp,#-16]!
cf_saved:
    .cfi_def_cfa_offset 16
    .cfi_offset 19,-16
    .cfi_offset 30,-8
    .cfi_offset 32,-8
    mov x19,#0x5100
    add x19,x19,x0
    cbz x0,.Lbase
    sub x0,x0,#1
    bl cf_recurse
    b .Lout
.Lbase:
    bl cf_checkpoint
.Lout:
    ldp x19,x30,[sp],#16
cf_restored:
    .cfi_def_cfa_offset 0
    .cfi_same_value 19
    .cfi_same_value 30
    .cfi_register 32,30
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
    .section .note.GNU-stack,"",%progbits
