    .file "cfi-shrinkwrap-x86_64.S"
    .cfi_sections .debug_frame
    .text
    .macro ordinary_rules
    .cfi_def_cfa 7,8
    .cfi_offset 16,-8
    .cfi_val_offset 7,0
    .cfi_same_value 12
    .irp reg,0,1,2,3,4,5,6,8,9,10,11,13,14,15
    .cfi_undefined \reg
    .endr
    .endm

    .globl cf_checkpoint
    .type cf_checkpoint,@function
cf_checkpoint:
    .cfi_startproc simple
    ordinary_rules
    endbr64
    mov cf_observation(%rip),%rax
    setnz %al
    nop
    ret
    .cfi_endproc
    .size cf_checkpoint,.-cf_checkpoint

    .globl cf_recurse,cf_saved,cf_restored,cf_entry_branch,cf_allocated,cf_fast_return
    .type cf_recurse,@function
cf_recurse:
    .cfi_startproc simple
    ordinary_rules
    test %rdi,%rdi
cf_entry_branch:
    jz cf_fast_return
    push %r12
cf_saved:
    .cfi_def_cfa_offset 16
    .cfi_offset 12,-16
    mov $0x5100,%r12
    add %rdi,%r12
    sub $16,%rsp
cf_allocated:
    .cfi_def_cfa_offset 32
    sub $1,%rdi
    call cf_recurse
    call cf_checkpoint
    add $16,%rsp
    .cfi_def_cfa_offset 16
    pop %r12
cf_restored:
    .cfi_def_cfa_offset 8
    .cfi_same_value 12
cf_fast_return:
    ret
    .cfi_endproc
    .size cf_recurse,.-cf_recurse

    .globl _start
    .type _start,@function
_start:
    .cfi_startproc simple
    ordinary_rules
    .cfi_def_cfa_offset 0
    .cfi_undefined 16
    xor %ebp,%ebp
    mov $0x6172,%r12
    mov $3,%edi
    call cf_recurse
    xor %edi,%edi
    cmp $0x6172,%r12
    setne %dil
    mov $60,%eax
    syscall
    .cfi_endproc
    .size _start,.-_start
    .section .rodata
    .balign 8
cf_observation:
    .quad 0x1234
    .section .note.GNU-stack,"",@progbits
