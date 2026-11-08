package ghidradwarfforge.calls;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.elf.ElfImage;

/** Original-byte, guard, table, alias-entry and cancellation rejection controls. */
public final class BoundedSwitchProofSmoke {
    private static int checks;
    private static void require(boolean condition, String reason) { if (!condition) throw new AssertionError(reason); checks++; }
    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])), new HeadlessGhidraApplicationConfiguration());
        Path output = Path.of(args[1]); Files.createDirectories(output);
        var shapes = List.of("absolute", "relative", "misleading-hint", "wrong-guard", "same-edges", "large-bound",
            "index-clobbered", "unknown-base", "unknown-target", "writable-table", "overlap-table", "zero-fill-table",
            "no-table-load", "bypass", "interior-bypass", "extra-entry", "patched-code", "opaque-effect",
            "case-constant", "case-unavailable", "loader-write");
        for (long delta : List.of(0L, 0x400000L)) for (String shape : shapes) check(shape, delta, output);
        System.out.println("bounded-switch-proof=PASS cases=" + shapes.size() * 2 + " checks=" + checks);
    }
    private static void check(String shape, long delta, Path directory) throws Exception {
        boolean relative = shape.equals("relative");
        boolean caseFlow = shape.startsWith("case-");
        byte[] code = new byte[0x51]; Arrays.fill(code, (byte) 0x90);
        byte[] dispatch = HexFormat.of().parseHex(relative ?
            "83ff01774b488d15f40f000089ff486304ba4801d0ffe0" : "83ff01774b89ffff24fd00200000");
        System.arraycopy(dispatch, 0, code, 0, dispatch.length);
        code[0x30] = code[0x40] = code[0x50] = (byte) 0xc3;
        if (shape.equals("wrong-guard")) code[3] = 0x76;
        if (shape.equals("same-edges")) code[4] = 0;
        if (shape.equals("large-bound")) code[2] = (byte) 0xff;
        if (shape.equals("index-clobbered")) code[6] = (byte) 0xf7; // MOV EDI,ESI after guard.
        if (shape.equals("unknown-base")) code[9] = (byte) 0xf8; // index RDI plus unknown RAX.
        if (shape.equals("opaque-effect")) { code[5] = 0x0f; code[6] = 0x05; }
        if (caseFlow) {
            byte[] block = HexFormat.of().parseHex(shape.equals("case-constant") ?
                "bf2a000000e806000000c3c3" : "9090909090e806000000c3c3");
            System.arraycopy(block, 0, code, 0x30, block.length);
        }
        var data = ByteBuffer.allocate(relative ? 8 : 16).order(ByteOrder.LITTLE_ENDIAN);
        if (relative) data.putInt(0x1030 - 0x2000).putInt(0x1040 - 0x2000);
        else data.putLong(shape.equals("unknown-target") ? 0x1080 : 0x1030).putLong(caseFlow ? 0x103b : 0x1040);
        byte[] original = GhidraTailStateProofSmoke.elf(false, code, data.array());
        if (shape.equals("loader-write")) original = relocatedTable(code, data.array());
        var header = ByteBuffer.wrap(original).order(ByteOrder.LITTLE_ENDIAN);
        header.putInt(124, shape.equals("writable-table") ? 6 : 4);
        if (relative) header.putShort(16, (short) 3);
        if (shape.equals("overlap-table")) header.putLong(104, 0x1010);
        if (shape.equals("zero-fill-table")) header.putLong(152, 8);
        if (shape.equals("no-table-load")) header.putInt(120, 0);
        var path = directory.resolve(shape + "-" + delta + ".elf"); Files.write(path, original);
        var image = ElfImage.read(path);
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:64:default"));
        Object consumer = new Object();
        var program = new ProgramDB("switch", language, language.getCompilerSpecByID(new CompilerSpecID("gcc")), consumer);
        try {
            int tx = program.startTransaction("switch fixture");
            try {
                var start = language.getDefaultSpace().getAddress(0x1000 + delta);
                var table = language.getDefaultSpace().getAddress(0x2000 + delta);
                program.getMemory().createInitializedBlock("code", start, code.length, (byte) 0, TaskMonitor.DUMMY, false).setExecute(true);
                if (shape.equals("patched-code")) code[2] = 0;
                program.getMemory().setBytes(start, code);
                program.getMemory().createInitializedBlock("table", table, data.capacity(), (byte) 0, TaskMonitor.DUMMY, false);
                program.getMemory().setBytes(table, data.array());
                var body = new AddressSet(start, start.add(code.length - 1));
                require(new DisassembleCommand(start, body, true).applyTo(program, TaskMonitor.DUMMY), "guard decode");
                for (int offset : List.of(0x30, 0x40)) require(new DisassembleCommand(start.add(offset), body, true)
                    .applyTo(program, TaskMonitor.DUMMY), "target decode");
                if (caseFlow) {
                    require(new DisassembleCommand(start.add(0x3b), body, true).applyTo(program, TaskMonitor.DUMMY), "second case decode");
                    body = new AddressSet(start, start.add(dispatch.length - 1));
                    body.add(start.add(0x30), start.add(0x3b));
                    body.add(start.add(0x50));
                    program.getFunctionManager().createFunction("leaf", start.add(0x40),
                        new AddressSet(start.add(0x40)), SourceType.USER_DEFINED);
                }
                var function = program.getFunctionManager().createFunction("dispatch", start, body, SourceType.USER_DEFINED);
                if (shape.equals("bypass") || shape.equals("interior-bypass")) {
                    program.getReferenceManager().addMemoryReference(start.add(0x50), start.add(shape.equals("bypass") ? 5 : 6),
                        RefType.UNCONDITIONAL_JUMP, SourceType.USER_DEFINED, 0);
                }
                if (shape.equals("extra-entry")) program.getSymbolTable().addExternalEntryPoint(start.add(5));
                if (shape.equals("misleading-hint")) program.getReferenceManager().addMemoryReference(start.add(7), start.add(0x50),
                    RefType.COMPUTED_JUMP, SourceType.USER_DEFINED, 0);
                boolean positive = List.of("absolute", "relative", "misleading-hint").contains(shape) || caseFlow;
                var compare = program.getListing().getInstructionAt(start);
                try {
                    var proof = GhidraBoundedSwitch.prove(program, compare, image, delta, TaskMonitor.DUMMY);
                    require(positive, "accepted invalid dispatch: " + shape);
                    require(proof.maximumIndex() == 1 && proof.targets().equals(List.of(start.add(0x30), start.add(caseFlow ? 0x3b : 0x40))),
                        "wrong target calculation: " + shape + " " + proof);
                    require(proof.reads().size() == 2 && proof.reads().getFirst().address() == 0x2000 &&
                        proof.reads().getFirst().bytes() == (relative ? 4 : 8), "wrong original table read");
                    require(proof.equals(GhidraBoundedSwitch.prove(program, compare, image, delta, TaskMonitor.DUMMY)), "nondeterministic proof");
                    if (caseFlow) {
                        var boundary = GhidraTailStateProof.verify(program, List.of(function), image, delta, TaskMonitor.DUMMY);
                        require(boundary.omissions().isEmpty() && boundary.switches().size() == 1 && boundary.tails().isEmpty(),
                            "bounded internal branch was lost or became a tail: " + boundary.omissions());
                        var values = GhidraCallArgumentFlow.analyze(program, boundary, image, delta, TaskMonitor.DUMMY);
                        require(values.omissions().isEmpty(), "switch value graph failed: " + values.omissions());
                        var site = values.transfers().get(start.add(0x35));
                        require(site != null, "missing ordinary case call");
                        var register = program.getRegister("RDI");
                        var value = GhidraCallArgumentFlow.read(site.values(), new ghidradwarfforge.unwind.UnwindFlow.Cell(
                            ghidradwarfforge.unwind.UnwindFlow.Bank.REGISTER, register.getAddress().getOffset(), 8));
                        require(shape.equals("case-constant") ? value instanceof CallValue.Literal literal && literal.value() == 42 : value == null,
                            "dispatch retained unproved incoming state or lost later constant");
                    }
                    if (shape.equals("absolute") && delta == 0) {
                        int[] polls = {0};
                        GhidraBoundedSwitch.prove(program, compare, image, delta, new TaskMonitorAdapter(true) {
                            @Override public void checkCancelled() { polls[0]++; }
                        });
                        for (int n = 1; n <= polls[0]; n++) {
                            int stop = n; int[] seen = {0};
                            try {
                                GhidraBoundedSwitch.prove(program, compare, image, delta, new TaskMonitorAdapter(true) {
                                    @Override public void checkCancelled() throws CancelledException {
                                        if (++seen[0] == stop) throw new CancelledException();
                                    }
                                });
                                throw new AssertionError("missed cancellation " + stop);
                            }
                            catch (CancelledException expected) { checks++; }
                        }
                    }
                }
                catch (IllegalArgumentException rejected) {
                    require(!positive, "rejected valid " + shape + ": " + rejected.getMessage());
                    if (shape.equals("loader-write")) require(rejected.getMessage().contains("runtime relocation write"),
                        "loader-write fixture rejected for an unrelated reason: " + rejected.getMessage());
                }
                require(Arrays.equals(original, Files.readAllBytes(path)), "modified original ELF");
            }
            finally { program.endTransaction(tx, false); }
        }
        finally { program.release(consumer); }
    }

    private static byte[] relocatedTable(byte[] code, byte[] table) {
        int payload = 64 + 4 * 56;
        int metadata = payload + code.length + table.length;
        var out = ByteBuffer.allocate(metadata + 120).order(ByteOrder.LITTLE_ENDIAN);
        out.put(GhidraTailStateProofSmoke.elf(false, code, table), 0, 64);
        out.putShort(16, (short) 3).putShort(56, (short) 4);
        for (int index = 0; index < 4; index++) {
            int ph = 64 + index * 56;
            int offset = index == 0 ? payload : index == 1 ? payload + code.length : metadata;
            int address = index == 0 ? 0x1000 : index == 1 ? 0x2000 : 0x3000;
            int length = index == 0 ? code.length : index == 1 ? table.length : index == 2 ? 120 : 80;
            out.putInt(ph, index == 3 ? 2 : 1).putInt(ph + 4, index == 0 ? 5 : index == 1 ? 4 : 6)
                .putLong(ph + 8, offset).putLong(ph + 16, address).putLong(ph + 32, length)
                .putLong(ph + 40, length).putLong(ph + 48, 1);
        }
        out.position(payload); out.put(code).put(table);
        out.position(metadata);
        out.putLong(7).putLong(0x3060).putLong(8).putLong(24).putLong(9).putLong(24)
            .putLong(22).putLong(0).putLong(0).putLong(0);
        out.position(metadata + 96);
        out.putLong(0x2000).putLong(8).putLong(0x1030); // R_X86_64_RELATIVE modifies the first table entry.
        return out.array();
    }
}
