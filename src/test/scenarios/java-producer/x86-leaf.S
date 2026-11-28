.text
.globl eval_probe
.type eval_probe,@function
eval_probe:
    movl eval_first+8(%rip), %eax
    addl $23, %eax
    movl %eax, eval_second+8(%rip)
.globl eval_transition
eval_transition:
    movl eval_second+8(%rip), %eax
    ret
.size eval_probe,.-eval_probe

.globl eval_invoke
.type eval_invoke,@function
eval_invoke:
    subq $8, %rsp
    call eval_probe
.globl eval_returned
eval_returned:
    addq $8, %rsp
    ret
.size eval_invoke,.-eval_invoke
.section .note.GNU-stack,"",@progbits
