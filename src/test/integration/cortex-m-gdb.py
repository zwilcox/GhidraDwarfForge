"""GDB Python oracle for the independent Cortex-M compiler reference."""
import json
import os
from pathlib import Path
import struct
import traceback
import gdb

root = Path(os.environ['FORGE_CORTEX_CASE'])
labels = json.loads((root / 'labels.json').read_text())
result = {'status': 'FAIL', 'exceptions': []}


def value(expression):
    return int(gdb.parse_and_eval(expression))


def words(address, count):
    return list(struct.unpack('<' + 'I' * count,
        bytes(gdb.selected_inferior().read_memory(address, 4 * count))))


def stop_at(location):
    breakpoint = gdb.Breakpoint(location, temporary=True)
    gdb.execute('continue')
    assert not breakpoint.is_valid(), 'expected breakpoint was not reached: ' + location


try:
    gdb.execute('set pagination off')
    gdb.execute('set confirm off')
    gdb.execute('set auto-solib-add off')
    gdb.execute('file ' + json.dumps(str(root / 'original.elf')))
    gdb.execute('symbol-file ' + json.dumps(str(root / 'reference.elf')))
    gdb.execute('target remote ' + os.environ['FORGE_CORTEX_SOCKET'])
    vectors = words(0, 16)
    reset = labels['Reset_Handler'] & ~1
    assert vectors[0] == 0x20010000 and vectors[1] == reset | 1
    assert vectors[11] == labels['SVC_Handler'] | 1
    assert value('$pc') == reset and value('$sp') == vectors[0]
    assert value('$xpsr') & (1 << 24), 'reset lost Thumb state'
    instructions = gdb.selected_frame().architecture().disassemble(reset, reset + 8)
    assert instructions and instructions[0]['length'] == 2
    assert instructions[0]['asm'].startswith('ldr')
    result['reset'] = {'pc': value('$pc'), 'sp': value('$sp'), 'xpsr': value('$xpsr'),
        'vectors': vectors, 'instructions': instructions}
    flash_initialized = labels['_sidata'] + labels['cortex_initialized'] - labels['_sdata']
    assert words(flash_initialized, 1) == [7]
    assert words(labels['cortex_initialized'], 1) == [0], 'RAM data initialized before reset copy'
    gdb.selected_inferior().write_memory(labels['cortex_bss_counter'], struct.pack('<I', 0x12345678))
    result['reset']['bssSeed'] = 0x12345678
    stop_at('cortex_main')
    assert value('cortex_initialized') == 7 and value('cortex_bss_counter') == 0
    pointer = words(labels['cortex_function_pointer'], 1)[0]
    assert pointer == labels['cortex_compute'] | 1
    pointer_type = gdb.parse_and_eval('cortex_function_pointer').type.strip_typedefs()
    assert pointer_type.code == gdb.TYPE_CODE_PTR
    function_type = pointer_type.target().strip_typedefs()
    assert function_type.code == gdb.TYPE_CODE_FUNC and function_type.target().sizeof == 4
    assert len(function_type.fields()) == 1 and function_type.fields()[0].type.sizeof == 4
    result['functionPointerType'] = gdb.execute('ptype cortex_function_pointer', to_string=True)
    result['functionPointer'] = pointer
    gdb.execute('next')
    result['steps'] = []
    for _ in range(6):
        gdb.execute('step')
        result['steps'].append({'function': gdb.selected_frame().name(),
            'pc': value('$pc'), 'line': gdb.selected_frame().find_sal().line})
        if gdb.selected_frame().name() == 'cortex_compute':
            break
    assert gdb.selected_frame().name() == 'cortex_compute'
    assert value('input') == 9
    stop_at('*' + hex(labels['cortex_compute_probe']))
    assert value('local') == 16 and value('cortex_bss_counter') == 17
    result['sourceStepping'] = {'function': gdb.selected_frame().name(), 'input': value('input'),
        'local': value('local'), 'line': gdb.selected_frame().find_sal().line}
    for index, suffix, expected_return in ((1, 'msp', 0xfffffff9), (2, 'psp', 0xfffffffd)):
        if index == 2:
            stop_at('cortex_compute')
            assert value('input') == 11
        stop_at('*' + hex(labels['cortex_exception_probe']))
        assert value('cortex_exception_count') == index
        assert value('cortex_exception_number') == 11 and value('$xpsr') & 0x1ff == 11
        assert value('cortex_exception_return') == expected_return
        address = value('cortex_stacked_address')
        frame = words(address, 8)
        msp, psp = value('$msp'), value('$psp')
        assert value('$sp') == msp, 'handler mode must use MSP'
        assert frame[6] == labels['cortex_after_svc_' + suffix]
        assert frame[7] & (1 << 24) and frame[7] & 0x1ff == 0
        assert value('cortex_stacked_pc') == frame[6] and value('cortex_stacked_xpsr') == frame[7]
        if index == 1:
            assert 0x2000f000 < address < 0x20010000
            assert msp < address and address - msp < 256
        else:
            assert 0x2000e000 < address < 0x2000f000
            assert psp == address and msp > 0x2000f000
        result['exceptions'].append({'stack': suffix, 'excReturn': expected_return,
            'msp': msp, 'psp': psp, 'frameAddress': address, 'hardwareFrame': frame,
            'backtrace': gdb.execute('bt', to_string=True),
            'registers': gdb.execute('info all-registers', to_string=True)})
    stop_at('*' + hex(labels['cortex_done']))
    assert value('cortex_result') == 21 and value('cortex_bss_counter') == 35
    assert value('$xpsr') & 0x1ff == 0
    assert value('$sp') == value('$psp') and value('$control') & 2
    result['final'] = {'result': value('cortex_result'), 'counter': value('cortex_bss_counter'),
        'pc': value('$pc'), 'sp': value('$sp')}
    result['status'] = 'PASS'
except Exception:
    result['error'] = traceback.format_exc()
finally:
    (root / 'compiler-gdb.json').write_text(json.dumps(result, indent=4) + '\n')
    print(json.dumps(result, indent=4))
    gdb.execute('quit ' + ('0' if result['status'] == 'PASS' else '1'))
