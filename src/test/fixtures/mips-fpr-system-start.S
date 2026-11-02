/* Bare-metal O32 harness. ERL gives the low-address fixture direct RAM access.
 * The real program selects FR=1; the debugger does not repair FPR contents. */
.set noreorder
.set noat
.text
.globl _start
.ent _start
_start:
    lui $sp, 0x0020
    lui $t0, 0x2400
    ori $t0, $t0, 4
    mtc0 $t0, $12
    ehb
    jal main
    nop
.globl reference_done
reference_done:
    b reference_done
    nop
.end _start
