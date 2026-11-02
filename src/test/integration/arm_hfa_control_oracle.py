"""Source-owned control contracts, independent of exported DWARF locations."""
CONTROL_IDS = {'lower': 0, 'neighbor': 1, 'upper': 2, 'wide': 3, 'reuse': 4,
    'adjacent': 5, 'unknown-disjoint': 6, 'unknown-alias': 6}
# PCs before these offsets still have a complete proof. None means no gap.
GAP_START = {'lower': None, 'neighbor': None, 'upper': 48, 'wide': 48,
    'reuse': 44, 'adjacent': 48, 'unknown-disjoint': 44, 'unknown-alias': 44}


def instruction_words(control, storage="hfa"):
    words = 'e52db004 e28db000 e24dd00c eeb07a40 eef07a60 ed0b7a03 ed4b7a02 ed1b7a03 ed5b7a02 ee777a27 eeb00a67 e28bd000 e49db004 e12fff1e'.split()
    words[8] = {'reuse': 'e50b1008', 'adjacent': 'e50b1004',
        'unknown-disjoint': 'e5801000', 'unknown-alias': 'e5801000'}.get(control, words[8])
    words[10] = 'eeb00a67' if control == 'lower' else 'eeb01a67' if control == 'neighbor' else (
        'eeb00b47' if control == 'wide' else 'eef00a67')
    if storage != 'hfa':
        words[3:5] = ['ee070a10', 'ee071a90']
        words[8] = {'reuse': 'e50b3008', 'adjacent': 'e50b3004',
            'unknown-disjoint': 'e5823000', 'unknown-alias': 'e5823000'}.get(control, 'ed5b7a02')
        words[10] = 'ee170a90' if control == 'lower' else 'ee17ca90' if control == 'neighbor' else (
            'ec510b17' if control == 'wide' else 'ee171a90')
    return words
