ENTRY(_start)
PHDRS {
    metadata PT_LOAD FILEHDR PHDRS FLAGS(6);
    code PT_LOAD FLAGS(5);
    dynamic PT_DYNAMIC FLAGS(4);
}
SECTIONS {
    . = SIZEOF_HEADERS;
    .hash : { *(.hash) } :metadata
    .gnu.hash : { *(.gnu.hash) } :metadata
    .dynsym : { *(.dynsym) } :metadata
    .dynstr : { *(.dynstr) } :metadata
    .dynamic : { *(.dynamic) } :metadata :dynamic
    .got : { *(.got*) } :metadata
    . = ALIGN(0x1000);
    .text : { *(.text.start) } :code
    .tail : { *(.text.tail) } :code
    .ARM.attributes 0 : { *(.ARM.attributes) }
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.ARM.exidx*) }
}
