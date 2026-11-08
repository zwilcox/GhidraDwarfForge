#!/usr/bin/env python3
"""Consumer experiment only: add known mapping records to a copied fixture sidecar.

This is not the production writer or evidence extraction. It only isolates whether
GDB can consume the proposed standard mapping records in a matched debug ELF.
"""
import importlib.util
from pathlib import Path
import struct
import sys

spec = importlib.util.spec_from_file_location("inventory", Path(__file__).with_name("arm-thumb-mode-check.py"))
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


def main(input_path, output_path):
    assert input_path.resolve() != output_path.resolve()
    original = input_path.read_bytes()
    image = inventory.elf(input_path)
    allocation = inventory.section(image, ".forge_mixed")
    assert allocation["row"][5] == 44 and allocation["row"][2] == 6
    table = inventory.section(image, ".symtab")
    strings = image["sections"][table["row"][6]]
    assert strings["name"] == ".strtab"
    assert not any(section["row"][6] == table["index"] for section in image["sections"])
    first_nonlocal = table["row"][7]
    names = bytearray(strings["data"])
    additions = bytearray()
    for mode, offset in (("a", 0), ("t", 16), ("a", 24), ("d", 40)):
        name = f"${mode}.forge_experiment_{offset}"
        assert not any(symbol["name"] == name for symbol in image["symbols"])
        additions += struct.pack("<IIIBBH", len(names), allocation["row"][3] + offset,
            0, 0, 0, allocation["index"])
        names += name.encode() + b"\0"
    records = table["data"][:first_nonlocal * 16] + additions + table["data"][first_nonlocal * 16:]
    data = bytearray(original)
    data += b"\0" * (-len(data) % 4)
    table_offset = len(data)
    data += records
    names_offset = len(data)
    data += names
    section_table_offset = image["header"][5]
    for section, offset, size in ((table, table_offset, len(records)), (strings, names_offset, len(names))):
        row = list(section["row"])
        row[4:6] = [offset, size]
        if section is table:
            row[7] += 4
        struct.pack_into("<10I", data, section_table_offset + section["index"] * 40, *row)
    with output_path.open("xb") as output_file:
        output_file.write(data)
    output = inventory.elf(output_path)
    assert input_path.read_bytes() == original
    assert output["header"] == image["header"]
    assert [s for s in output["symbols"] if ".forge_experiment_" not in s["name"]] == image["symbols"]
    for before, after in zip(image["sections"], output["sections"]):
        if before["name"] not in (".symtab", ".strtab"):
            assert before == after
    print("mixed-mapping-experiment=CREATED (not a production export)")


if __name__ == "__main__":
    main(*(Path(arg) for arg in sys.argv[1:]))
