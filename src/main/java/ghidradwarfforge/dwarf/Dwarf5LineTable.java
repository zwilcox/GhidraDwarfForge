package ghidradwarfforge.dwarf;

import java.io.ByteArrayOutputStream;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.TreeMap;

import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.source.SyntheticSourceFile.SourceLine;

/** Minimal deterministic DWARF 5 line program using evidence-backed rows. */
public final class Dwarf5LineTable {
    static record LineRow(long address, int line) {
    }

    static record LineSequence(long start, long endExclusive, List<LineRow> rows) {
        LineSequence {
            rows = List.copyOf(rows);
        }
    }

    private static final int DW_FORM_STRING = 0x08;
    private static final int DW_FORM_UDATA = 0x0f;
    private static final int DW_LNCT_PATH = 0x01;
    private static final int DW_LNCT_DIRECTORY_INDEX = 0x02;
    private static final int DW_LNS_COPY = 0x01;
    private static final int DW_LNS_ADVANCE_PC = 0x02;
    private static final int DW_LNS_ADVANCE_LINE = 0x03;
    private static final int DW_LNS_SET_FILE = 0x04;
    private static final int DW_LNE_END_SEQUENCE = 0x01;
    private static final int DW_LNE_SET_ADDRESS = 0x02;

    private Dwarf5LineTable() {
    }

    public static byte[] build(String fileName, int addressBytes, ByteOrder byteOrder,
            List<FunctionSymbol> functions, List<SourceLine> sourceLines) {
        if (fileName == null || fileName.isBlank() || fileName.indexOf('\0') >= 0) {
            throw new IllegalArgumentException("invalid line-table file name");
        }
        if (addressBytes != 4 && addressBytes != 8) {
            throw new IllegalArgumentException("unsupported address size " + addressBytes);
        }
        ByteArrayOutputStream program = new ByteArrayOutputStream();
        List<LineSequence> sequences = plan(functions, sourceLines);
        for (LineSequence sequence : sequences) {
            writeExtended(program, DW_LNE_SET_ADDRESS,
                address(sequence.start(), addressBytes, byteOrder));
            program.write(DW_LNS_SET_FILE);
            writeUleb(program, 0); // DWARF 5 file table indices are zero-based.
            long currentAddress = sequence.start();
            long currentLine = 1;
            for (LineRow row : sequence.rows()) {
                long addressDelta = Math.subtractExact(row.address(), currentAddress);
                if (addressDelta != 0) {
                    program.write(DW_LNS_ADVANCE_PC);
                    writeUleb(program, addressDelta);
                }
                long lineDelta = Math.subtractExact((long) row.line(), currentLine);
                if (lineDelta != 0) {
                    program.write(DW_LNS_ADVANCE_LINE);
                    writeSleb(program, lineDelta);
                }
                program.write(DW_LNS_COPY);
                currentAddress = row.address();
                currentLine = row.line();
            }
            long finalDelta = Math.subtractExact(sequence.endExclusive(), currentAddress);
            if (finalDelta != 0) {
                program.write(DW_LNS_ADVANCE_PC);
                writeUleb(program, finalDelta);
            }
            writeExtended(program, DW_LNE_END_SEQUENCE, new byte[0]);
        }
        if (sequences.isEmpty()) {
            return new byte[0];
        }

        ByteArrayOutputStream header = new ByteArrayOutputStream();
        header.write(1); // minimum_instruction_length
        header.write(1); // maximum_operations_per_instruction
        header.write(1); // default_is_stmt
        header.write(0xfb); // line_base = -5
        header.write(14); // line_range
        header.write(13); // opcode_base
        byte[] standardOpcodeLengths = { 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1 };
        header.writeBytes(standardOpcodeLengths);
        header.write(1); // directory_entry_format_count
        writeUleb(header, DW_LNCT_PATH);
        writeUleb(header, DW_FORM_STRING);
        writeUleb(header, 1); // directories_count
        header.write('.');
        header.write(0);
        header.write(2); // file_name_entry_format_count
        writeUleb(header, DW_LNCT_PATH);
        writeUleb(header, DW_FORM_STRING);
        writeUleb(header, DW_LNCT_DIRECTORY_INDEX);
        writeUleb(header, DW_FORM_UDATA);
        writeUleb(header, 1); // file_names_count
        header.writeBytes(fileName.getBytes(StandardCharsets.UTF_8));
        header.write(0);
        writeUleb(header, 0); // directory index

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        writeUnsigned(body, 5, 2, byteOrder);
        body.write(addressBytes);
        body.write(0); // segment selector size
        writeUnsigned(body, header.size(), 4, byteOrder);
        body.writeBytes(header.toByteArray());
        body.writeBytes(program.toByteArray());

        ByteArrayOutputStream result = new ByteArrayOutputStream();
        writeUnsigned(result, body.size(), 4, byteOrder);
        result.writeBytes(body.toByteArray());
        return result.toByteArray();
    }

    /**
     * Plans one independent line sequence per real function range. If Ghidra's
     * token evidence associates one instruction with multiple generated lines,
     * the earliest generated line wins deterministically because a line-machine
     * address can expose only one current source row.
     */
    static List<LineSequence> plan(List<FunctionSymbol> functions,
            List<SourceLine> sourceLines) {
        List<FunctionSymbol> ordered = new ArrayList<>(functions);
        ordered.sort(Comparator.comparingLong(FunctionSymbol::address)
            .thenComparing(FunctionSymbol::name));
        List<LineSequence> sequences = new ArrayList<>();
        for (FunctionSymbol function : ordered) {
            for (FunctionRange range : function.ranges()) {
                TreeMap<Long, Integer> rows = new TreeMap<>();
                for (SourceLine sourceLine : sourceLines) {
                    for (long address : sourceLine.addresses()) {
                        if (range.contains(address)) {
                            rows.merge(address, sourceLine.line(), Math::min);
                        }
                    }
                }
                if (!rows.isEmpty()) {
                    sequences.add(new LineSequence(range.address(), range.endExclusive(),
                        rows.entrySet().stream()
                            .map(row -> new LineRow(row.getKey(), row.getValue()))
                            .toList()));
                }
            }
        }
        return List.copyOf(sequences);
    }

    private static byte[] address(long value, int width, ByteOrder order) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        writeUnsigned(output, value, width, order);
        return output.toByteArray();
    }

    private static void writeExtended(ByteArrayOutputStream output, int opcode,
            byte[] operands) {
        output.write(0);
        writeUleb(output, 1L + operands.length);
        output.write(opcode);
        output.writeBytes(operands);
    }

    private static void writeUnsigned(ByteArrayOutputStream output, long value, int width,
            ByteOrder order) {
        for (int index = 0; index < width; index++) {
            int shift = order == ByteOrder.LITTLE_ENDIAN ? index * 8 : (width - index - 1) * 8;
            output.write((int) (value >>> shift) & 0xff);
        }
    }

    private static void writeUleb(ByteArrayOutputStream output, long value) {
        if (value < 0) {
            throw new IllegalArgumentException("negative ULEB128 value");
        }
        do {
            int next = (int) (value & 0x7f);
            value >>>= 7;
            output.write(value == 0 ? next : next | 0x80);
        } while (value != 0);
    }

    private static void writeSleb(ByteArrayOutputStream output, long value) {
        boolean more;
        do {
            int next = (int) (value & 0x7f);
            value >>= 7;
            more = !((value == 0 && (next & 0x40) == 0) ||
                (value == -1 && (next & 0x40) != 0));
            output.write(more ? next | 0x80 : next);
        } while (more);
    }
}
