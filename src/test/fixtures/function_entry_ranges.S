/* x86-64 SysV fixture: both routines enter above executable body bytes.
 * The global labels are independent assembler address oracles. The split
 * routine's trap-filled gap is never executed or included in its body. */
    .text
    .globl below_start, below_end, below_entry, below_entry_end
below_start:
    movl %eax, below_sink(%rip)
    ret
below_end:
    .fill 16, 1, 0xcc
    .type below_entry, @function
below_entry:
    leal (%rdi,%rsi), %eax
    jmp below_start
below_entry_end:
    .size below_entry, below_entry_end-below_entry

    .balign 16, 0xcc
    .globl middle_start, middle_entry, middle_end
middle_start:
    movl %eax, middle_sink(%rip)
    ret
    .type middle_entry, @function
middle_entry:
    leal (%rdi,%rsi), %eax
    jmp middle_start
middle_end:
    .size middle_entry, middle_end-middle_entry
    .section .note.GNU-stack,"",@progbits
