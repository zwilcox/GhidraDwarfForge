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
import ghidradwarfforge.source.SourcePartitionPlan;

/** Minimal deterministic DWARF 5 line program using evidence-backed rows. */
public final class Dwarf5LineTable {
    public static record LineRow(long address, int line) {
    }

    public static record LineSequence(long start, long endExclusive, List<LineRow> rows) {
        public LineSequence {
            rows = List.copyOf(rows);
        }
    }

    public record FilePosition(int file, int line) {
        public FilePosition {
            if (file < 0 || line < 0) throw new IllegalArgumentException("invalid source file position");
        }
    }

    /** File table and the translation from retained logical source evidence. */
    public static final class FileLayout {
        private final List<String> names;
        private final SourcePartitionPlan partitions;

        private FileLayout(List<String> names, SourcePartitionPlan partitions) {
            this.names = List.copyOf(names);
            this.partitions = partitions;
            if (names.isEmpty() || names.stream().anyMatch(name -> name.isBlank() || name.indexOf('\0') >= 0) ||
                    names.stream().distinct().count() != names.size()) {
                throw new IllegalArgumentException("invalid or duplicate line-table file name");
            }
        }

        public static FileLayout single(String fileName) {
            if (fileName == null) throw new IllegalArgumentException("invalid line-table file name");
            return new FileLayout(List.of(fileName), null);
        }

        public static FileLayout partitioned(String indexName, List<String> partNames,
                SourcePartitionPlan partitions) {
            if (indexName == null || partitions == null || partNames == null ||
                    partNames.size() != partitions.parts().size()) {
                throw new IllegalArgumentException("partition file names differ from source plan");
            }
            var names = new ArrayList<String>();
            names.add(indexName);
            names.addAll(partNames);
            return new FileLayout(names, partitions);
        }

        public List<String> names() { return names; }

        public void requireSource(ghidradwarfforge.source.SyntheticSourceFile source) {
            if (partitions != null) partitions.requireSource(source);
        }

        public FilePosition locate(int logicalLine) {
            if (partitions == null) return new FilePosition(0, logicalLine);
            var position = partitions.locate(logicalLine);
            return new FilePosition(position.file(), position.line());
        }
    }

    /** Encoded bytes, retained logical rows, and their exact file/line translation. */
    public static final class Result {
        private final byte[] section;
        private final List<LineSequence> sequences;
        private final FileLayout files;

        private Result(byte[] section, List<LineSequence> sequences, FileLayout files) {
            // Private construction transfers the newly encoded array into this result.
            this.section = section;
            this.sequences = List.copyOf(sequences);
            this.files = files;
        }

        public byte[] section() {
            return section.clone();
        }

        public List<LineSequence> sequences() {
            return sequences;
        }

        public FileLayout files() { return files; }
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
        return build(fileName, ".", addressBytes, byteOrder, functions, sourceLines);
    }

    public static byte[] build(String fileName, String sourceDirectory, int addressBytes,
            ByteOrder byteOrder, List<FunctionSymbol> functions, List<SourceLine> sourceLines) {
        return buildWithPlan(fileName, sourceDirectory, addressBytes, byteOrder,
            functions, sourceLines).section;
    }

    public static Result buildWithPlan(String fileName, String sourceDirectory, int addressBytes,
            ByteOrder byteOrder, List<FunctionSymbol> functions, List<SourceLine> sourceLines) {
        return buildWithPlan(fileName, sourceDirectory, addressBytes, byteOrder, functions, sourceLines, false);
    }

    /** Retain a source-file table even when no instruction has defensible source evidence. */
    public static Result buildWithPlan(String fileName, String sourceDirectory, int addressBytes,
            ByteOrder byteOrder, List<FunctionSymbol> functions, List<SourceLine> sourceLines,
            boolean retainFileTable) {
        return buildWithPlan(FileLayout.single(fileName), sourceDirectory, addressBytes,
            byteOrder, functions, sourceLines, retainFileTable);
    }

    public static Result buildWithPlan(FileLayout files, String sourceDirectory, int addressBytes,
            ByteOrder byteOrder, List<FunctionSymbol> functions, List<SourceLine> sourceLines,
            boolean retainFileTable) {
        java.util.Objects.requireNonNull(files, "source files");
        if (sourceDirectory == null || sourceDirectory.isBlank() ||
                sourceDirectory.indexOf('\0') >= 0) {
            throw new IllegalArgumentException("invalid line-table source directory");
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
            int currentFile = files.locate(sequence.rows().getFirst().line()).file();
            writeUleb(program, currentFile); // DWARF 5 file table indices are zero-based.
            long currentAddress = sequence.start();
            long currentLine = 1;
            for (LineRow row : sequence.rows()) {
                FilePosition position = files.locate(row.line());
                if (position.file() != currentFile) {
                    program.write(DW_LNS_SET_FILE);
                    writeUleb(program, position.file());
                    currentFile = position.file();
                }
                long addressDelta = Math.subtractExact(row.address(), currentAddress);
                if (addressDelta != 0) {
                    program.write(DW_LNS_ADVANCE_PC);
                    writeUleb(program, addressDelta);
                }
                long lineDelta = Math.subtractExact((long) position.line(), currentLine);
                if (lineDelta != 0) {
                    program.write(DW_LNS_ADVANCE_LINE);
                    writeSleb(program, lineDelta);
                }
                program.write(DW_LNS_COPY);
                currentAddress = row.address();
                currentLine = position.line();
            }
            long finalDelta = Math.subtractExact(sequence.endExclusive(), currentAddress);
            if (finalDelta != 0) {
                program.write(DW_LNS_ADVANCE_PC);
                writeUleb(program, finalDelta);
            }
            writeExtended(program, DW_LNE_END_SEQUENCE, new byte[0]);
        }
        if (sequences.isEmpty()) {
            if (!retainFileTable) return new Result(new byte[0], sequences, files);
            // Select the DWARF 5 file without emitting a matrix row or an address.
            // Consumers can list file:line while function addresses remain unmapped.
            program.write(DW_LNS_SET_FILE);
            writeUleb(program, 0);
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
        header.writeBytes(sourceDirectory.getBytes(StandardCharsets.UTF_8));
        header.write(0);
        header.write(2); // file_name_entry_format_count
        writeUleb(header, DW_LNCT_PATH);
        writeUleb(header, DW_FORM_STRING);
        writeUleb(header, DW_LNCT_DIRECTORY_INDEX);
        writeUleb(header, DW_FORM_UDATA);
        writeUleb(header, files.names().size());
        for (String name : files.names()) {
            header.writeBytes(name.getBytes(StandardCharsets.UTF_8));
            header.write(0);
            writeUleb(header, 0); // directory index
        }

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
        return new Result(result.toByteArray(), sequences, files);
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
        TreeMap<Long, Integer> sourceRows = new TreeMap<>();
        for (SourceLine sourceLine : sourceLines) {
            for (long address : sourceLine.addresses()) {
                sourceRows.merge(address, sourceLine.line(), Math::min);
            }
        }
        List<LineSequence> sequences = new ArrayList<>();
        for (FunctionSymbol function : ordered) {
            for (FunctionRange range : function.ranges()) {
                var rows = sourceRows.subMap(range.address(), true,
                    range.endExclusive(), false);
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
