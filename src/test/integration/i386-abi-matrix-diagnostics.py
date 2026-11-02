"""Recognize only the proven compiler-vector FinishBreakpoint consumer failure."""
import re


def vector_finish(variant, function, text, automatic, raw, expected, eax, unreadable):
    if not text:
        return None
    match = re.fullmatch(
        r"Python Exception <class 'gdb.MemoryError'>: Cannot access memory at address (0x[0-9a-f]+)\n", text)
    assert match, ('unexpected finish diagnostic', text)
    assert variant == 'compiler' and function == 'vector_add', (variant, function)
    assert automatic is None and raw == expected == [1.5, 3.5, 5.5, 7.5]
    assert int(match[1], 16) == eax and unreadable, ('unproven EAX dereference', eax, text)
    return {'kind': 'GDB compiler-vector return dereferences EAX', 'diagnostic': text,
        'eax': eax, 'automatic': automatic, 'raw': raw, 'typedReturnValidated': False}
