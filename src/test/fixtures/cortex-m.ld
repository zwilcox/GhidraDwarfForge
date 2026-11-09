ENTRY(Reset_Handler)
MEMORY
{
    FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 256K
    RAM (rwx) : ORIGIN = 0x20000000, LENGTH = 64K
}
_stack_top = ORIGIN(RAM) + LENGTH(RAM);
_psp_top = _stack_top - 0x1000;
SECTIONS
{
    .vectors : { KEEP(*(.vectors)) } > FLASH
    .note.gnu.build-id : { *(.note.gnu.build-id) } > FLASH
    .text : { *(.text*) *(.rodata*) } > FLASH
    .ARM.extab : { *(.ARM.extab*) } > FLASH
    .ARM.exidx : { *(.ARM.exidx*) } > FLASH
    .data :
    {
        . = ALIGN(4);
        _sdata = .;
        *(.data*)
        . = ALIGN(4);
        _edata = .;
    } > RAM AT> FLASH
    _sidata = LOADADDR(.data);
    .bss (NOLOAD) :
    {
        . = ALIGN(4);
        _sbss = .;
        *(.bss*) *(COMMON)
        . = ALIGN(4);
        _ebss = .;
    } > RAM
    ASSERT(_ebss < _psp_top - 0x1000, "fixture overlaps reserved stacks")
}
