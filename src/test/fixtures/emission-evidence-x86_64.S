.text
.globl observed, observed_moved, observed_return, observed_end
.type observed, @function
observed:
    mov %rdi, %rax
observed_moved:
    nop
observed_return:
    ret
observed_end:
.size observed, .-observed

.globl failed, failed_end
.type failed, @function
failed:
    mov $7, %eax
    ret
failed_end:
.size failed, .-failed

.globl empty, empty_end
.type empty, @function
empty:
    ret
empty_end:
.size empty, .-empty
.section .note.GNU-stack,"",@progbits
