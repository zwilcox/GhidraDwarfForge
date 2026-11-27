ENTRY(boot_case)
PHDRS {
    low PT_LOAD FLAGS(5);
    high PT_LOAD FLAGS(5);
    data PT_LOAD FLAGS(6);
    note PT_NOTE FLAGS(4);
    abi 0x70000003 FLAGS(4); /* PT_MIPS_ABIFLAGS */
}
SECTIONS {
    . = 0x400000;
    .text.low : { *(.text.low) } :low
    .note.gnu.build-id : { *(.note.gnu.build-id) } :low :note
    .MIPS.abiflags : { *(.MIPS.abiflags) } :low :abi
    .MIPS.options : { *(.MIPS.options) } :low

    /* These KSEG0 virtual addresses refer directly to Malta RAM. */
    . = 0xffffffff80002000;
    .text.high : AT(0x2000) { *(.text.high) } :high
    . = 0xffffffff80003000;
    .data : AT(0x3000) { *(.data) *(.got) } :data
    /DISCARD/ : { *(.pdr) *(.comment) *(.gnu.attributes) }
}
