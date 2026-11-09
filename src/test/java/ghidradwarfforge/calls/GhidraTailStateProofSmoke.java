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
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.elf.ElfImage;

/** Real instruction-state proofs and counterexamples; no DWARF emission claim. */
public final class GhidraTailStateProofSmoke {
    private static int checks;
    private static Path output;
    private static final StringBuilder report = new StringBuilder();

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        output = Path.of(args[1]); Files.createDirectories(output);
        for (boolean arm : List.of(false, true)) {
            for (String shape : List.of("direct", "annotated", "thunk", "balanced", "dirty-stack", "clobbered",
                    "return-lost", "unknown-store", "ordinary-call", "join-good", "join-bad", "one-bad-exit",
                    "select-argument", "select-preserved", "indirect", "callee-abi", "rebase",
                    "incoming-tail", "incoming-dirty", "incoming-annotated", "incoming-unselected",
                    "incoming-interior", "incoming-call")) {
                check(arm, shape);
            }
        }
        check(true, "hidden-pac");
        Files.writeString(output.resolve("proofs.txt"), report.toString());
        System.out.println("tail-state-proof-smoke=PASS checks=" + checks);
    }

    private static void require(boolean value, String reason) {
        if (!value) throw new AssertionError(reason);
        checks++;
    }
    private static String word(int value) {
        return HexFormat.of().formatHex(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array());
    }
    private static String jump(boolean arm, int from, int target) {
        return arm ? word(0x14000000 | ((target - from) >> 2) & 0x03ffffff) : "e9" + word(target - from - 5);
    }
    static byte[] elf(boolean arm, byte[] code, byte[] leaf) {
        var out = ByteBuffer.allocate(176 + code.length + leaf.length).order(ByteOrder.LITTLE_ENDIAN);
        out.put(new byte[] {0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0});
        out.putShort(16, (short) 2).putShort(18, (short) (arm ? 183 : 62)).putInt(20, 1);
        out.putLong(24, 0x9000).putLong(32, 64).putShort(52, (short) 64).putShort(54, (short) 56).putShort(56, (short) 2);
        int offset = 176;
        for (int index = 0; index < 2; index++) {
            byte[] bytes = index == 0 ? code : leaf;
            int position = 64 + index * 56;
            out.putInt(position, 1).putInt(position + 4, 5).putLong(position + 8, offset)
                .putLong(position + 16, index == 0 ? 0x1000 : 0x2000)
                .putLong(position + 32, bytes.length).putLong(position + 40, bytes.length).putLong(position + 48, 1);
            out.position(offset); out.put(bytes); offset += bytes.length;
        }
        return out.array();
    }

    private static void check(boolean arm, String shape) throws Exception {
        String prefix = switch (shape) {
            case "balanced" -> arm ? "f37bbfa9530580d2f37bc1a8" : "53bb2a0000005b";
            case "dirty-stack" -> arm ? "f37bbfa9" : "53";
            case "clobbered" -> arm ? "130080d2" : "bb2a000000";
            case "return-lost" -> arm ? "1e0080d2" : "48c7042400000000";
            case "unknown-store" -> arm ? "f37bbfa9000000f9f37bc1a8" : "488907";
            case "ordinary-call" -> arm ? "00040094" : "e8fb0f0000";
            case "join-good" -> arm ? "60000034f37bbfa9f37bc1a8" : "85ff7402535b";
            case "join-bad" -> arm ? "40000034f37bbfa9" : "85ff740153";
            case "one-bad-exit" -> arm ? "00800034f37bbfa9" : "85ff0f85f80f000053";
            case "select-argument" -> arm ? "2010809a" : "0f44c7";
            case "select-preserved" -> arm ? "1300939a" : "0f44d8";
            case "hidden-pac" -> "3f2303d5";
            default -> "";
        };
        String terminal = shape.equals("indirect") ? (arm ? "00001fd6" : "ffe0") :
            jump(arm, 0x1000 + prefix.length() / 2, 0x2000);
        byte[] code = HexFormat.of().parseHex(prefix + terminal);
        byte[] leaf = HexFormat.of().parseHex(arm ? "c0035fd6" : "c3");
        if (shape.startsWith("incoming-")) {
            if (shape.equals("incoming-call")) {
                leaf = HexFormat.of().parseHex(arm ? word(0x97fffc00) + "c0035fd6" : "e8" + word(-0x1005) + "c3");
            }
            else {
                String preparation = shape.equals("incoming-dirty") || shape.equals("incoming-annotated") ?
                    (arm ? "f37bbfa9" : "53") : "";
                int destination = shape.equals("incoming-interior") ? 0x1001 : 0x1000;
                // AArch64 can target only aligned instruction addresses; use a
                // second instruction inside the caller body for this control.
                if (arm && shape.equals("incoming-interior")) {
                    prefix = "1f2003d5";
                    code = HexFormat.of().parseHex(prefix + jump(true, 0x1004, 0x2000));
                    destination = 0x1004;
                }
                leaf = HexFormat.of().parseHex(preparation + jump(arm, 0x2000 + preparation.length() / 2, destination));
            }
        }
        byte[] original = elf(arm, code, leaf);
        Path path = output.resolve((arm ? "arm-" : "x86-") + shape + ".elf");
        Files.write(path, original);
        var image = ElfImage.read(path);
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
            arm ? "AARCH64:LE:64:v8A" : "x86:LE:64:default"));
        Object owner = new Object();
        var program = new ProgramDB("tail-state", language,
            language.getCompilerSpecByID(new CompilerSpecID(arm ? "default" : "gcc")), owner);
        long delta = shape.equals("rebase") ? 0x400000 : 0;
        try {
            int transaction = program.startTransaction("tail fixture");
            try {
                var entry = language.getDefaultSpace().getAddress(0x1000 + delta);
                var target = language.getDefaultSpace().getAddress(0x2000 + delta);
                program.getMemory().createInitializedBlock("caller", entry, code.length, (byte) 0, TaskMonitor.DUMMY, false).setExecute(true);
                program.getMemory().setBytes(entry, code);
                program.getMemory().createInitializedBlock("callee", target, leaf.length, (byte) 0, TaskMonitor.DUMMY, false).setExecute(true);
                program.getMemory().setBytes(target, leaf);
                var body = new AddressSet(entry, entry.add(code.length - 1));
                var calleeBody = new AddressSet(target, target.add(leaf.length - 1));
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "caller decode");
                require(new DisassembleCommand(target, calleeBody, true).applyTo(program, TaskMonitor.DUMMY), "callee decode");
                var function = program.getFunctionManager().createFunction("caller", entry, body, SourceType.USER_DEFINED);
                var callee = program.getFunctionManager().createFunction("callee", target, calleeBody, SourceType.USER_DEFINED);
                if (shape.equals("annotated")) program.getListing().getInstructionAt(entry).setFlowOverride(FlowOverride.CALL_RETURN);
                if (shape.equals("thunk")) function.setThunkedFunction(callee);
                if (shape.equals("callee-abi")) callee.setCustomVariableStorage(true);
                if (shape.equals("incoming-annotated")) {
                    program.getListing().getInstructionAt(target.add(arm ? 4 : 1)).setFlowOverride(FlowOverride.CALL_RETURN);
                }
                var selected = List.of("incoming-tail", "incoming-dirty", "incoming-annotated").contains(shape) ?
                    List.of(function, callee) : List.of(function);
                var result = GhidraTailStateProof.verify(program, selected, image, delta, TaskMonitor.DUMMY);
                boolean accepted = List.of("direct", "annotated", "thunk", "balanced", "join-good", "select-argument", "rebase",
                    "incoming-tail", "incoming-call").contains(shape);
                require(result.tails().size() == (shape.equals("incoming-tail") ? 2 : accepted ? 1 : 0), shape + " " + result);
                require(result.omissions().isEmpty() == accepted, shape + " " + result.omissions());
                if (accepted) {
                    var proof = result.tails().getFirst();
                    require(proof.caller().equals(entry) && proof.callee().equals(target) &&
                        proof.instruction().equals(entry.add(prefix.length() / 2)), "proved wrong transfer identity");
                }
                require(GhidraTailStateProof.verify(program, selected, image, delta, TaskMonitor.DUMMY).equals(result),
                    "proof retry is nondeterministic");
                if (shape.equals("direct")) {
                    int[] polls = {0};
                    var counting = new TaskMonitorAdapter(true) {
                        @Override public void checkCancelled() { polls[0]++; }
                    };
                    GhidraTailStateProof.verify(program, List.of(function), image, delta, counting);
                    for (int index = 1; index <= polls[0]; index++) {
                        int stop = index;
                        int[] count = {0};
                        var cancelled = new TaskMonitorAdapter(true) {
                            @Override public void checkCancelled() throws CancelledException {
                                if (++count[0] == stop) throw new CancelledException();
                            }
                        };
                        try {
                            GhidraTailStateProof.verify(program, List.of(function), image, delta, cancelled);
                            throw new AssertionError("missed tail proof cancellation " + stop);
                        }
                        catch (CancelledException expected) { checks++; }
                    }
                }
                require(Arrays.equals(original, Files.readAllBytes(path)), "proof changed original ELF");
                report.append(arm ? "aarch64/" : "x86-64/").append(shape).append(' ').append(result).append('\n');
            }
            finally { program.endTransaction(transaction, false); }
        }
        finally { program.release(owner); }
    }
}
