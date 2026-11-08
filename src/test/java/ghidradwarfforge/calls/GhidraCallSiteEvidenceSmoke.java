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
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.calls.GhidraCallSiteEvidence.Kind;
import ghidradwarfforge.elf.ElfImage;

/** Real Sleigh/control-flow and original-byte controls; no emitted call-site claim. */
public final class GhidraCallSiteEvidenceSmoke {
    private static int checks;
    private static Path output;
    private static final StringBuilder report = new StringBuilder();

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        output = Path.of(args[1]);
        Files.createDirectories(output);
        for (boolean arm : List.of(false, true)) {
            for (String mode : List.of("call", "tail", "annotated-tail", "thunk", "annotated-thunk",
                    "indirect-call", "indirect-tail", "annotated-indirect", "indirect-thunk", "indirect-hint", "internal",
                    "conditional-tail", "missing-callee", "interior-callee", "opaque", "call-override",
                    "return-override", "reference-conflict", "gap", "partial", "patched", "rebase", "discontiguous")) {
                check(arm, mode);
            }
        }
        check(false, "get-pc");
        check(false, "conditional-move");
        Files.writeString(output.resolve("capture.txt"), report.toString());
        System.out.println("call-site-evidence-smoke=PASS checks=" + checks);
    }

    private static void require(boolean condition, String reason) {
        if (!condition) throw new AssertionError(reason);
        checks++;
    }
    private static String word(int value) {
        return HexFormat.of().formatHex(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array());
    }
    private static String branch(boolean arm, int target) {
        return arm ? word(0x14000000 | (target - 0x1000) >> 2) : "e9" + word(target - 0x1005);
    }
    private static byte[] elf(boolean arm, byte[] code, byte[] leaf) {
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

    private static void check(boolean arm, String mode) throws Exception {
        String ret = arm ? "c0035fd6" : "c3";
        String call = arm ? "00040094" : "e8fb0f0000";
        String indirect = arm ? "00001fd6" : "ffe0";
        String code = switch (mode) {
            case "tail", "annotated-tail", "thunk", "annotated-thunk" -> branch(arm, 0x2000);
            case "interior-callee" -> branch(arm, arm ? 0x2004 : 0x2001);
            case "indirect-call" -> (arm ? "00003fd6" : "ffd0") + ret;
            case "indirect-tail", "annotated-indirect", "indirect-thunk", "indirect-hint" -> indirect;
            case "internal" -> branch(arm, arm ? 0x1004 : 0x1005) + ret;
            case "conditional-tail" -> (arm ? "01800054" : "0f85fa0f0000") + ret;
            case "opaque" -> (arm ? "010000d4" : "0f05") + ret;
            case "get-pc" -> "e80000000058c3";
            case "conditional-move" -> "0f44f8c3";
            case "gap" -> call + ret + (arm ? "1f2003d5" : "90");
            case "discontiguous" -> branch(arm, 0x1010) + "00".repeat(arm ? 12 : 11) + ret;
            default -> call + ret;
        };
        byte[] bytes = HexFormat.of().parseHex(code);
        byte[] leaf = HexFormat.of().parseHex((arm ? "1f2003d5" : "90") + ret);
        byte[] originalBytes = elf(arm, bytes, leaf);
        Path path = output.resolve((arm ? "arm-" : "x86-") + mode + ".elf");
        Files.write(path, originalBytes);
        var image = ElfImage.read(path);
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
            arm ? "AARCH64:LE:64:v8A" : "x86:LE:64:default"));
        Object owner = new Object();
        var program = new ProgramDB("call-site-evidence", language,
            arm ? language.getDefaultCompilerSpec() : language.getCompilerSpecByID(new CompilerSpecID("gcc")), owner);
        long delta = mode.equals("rebase") ? 0x400000 : 0;
        try {
            int transaction = program.startTransaction("call-site fixture");
            try {
                var entry = language.getDefaultSpace().getAddress(0x1000 + delta);
                var target = language.getDefaultSpace().getAddress(0x2000 + delta);
                program.getMemory().createInitializedBlock("caller", entry, bytes.length, (byte) 0, TaskMonitor.DUMMY, false).setExecute(true);
                program.getMemory().setBytes(entry, bytes);
                program.getMemory().createInitializedBlock("callee", target, leaf.length, (byte) 0, TaskMonitor.DUMMY, false).setExecute(true);
                program.getMemory().setBytes(target, leaf);
                var body = new AddressSet(entry, entry.add(bytes.length - 1));
                if (mode.equals("discontiguous")) body.delete(entry.add(arm ? 4 : 5), entry.add(15));
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "caller decode " + mode);
                var calleeBody = new AddressSet(target, target.add(leaf.length - 1));
                require(new DisassembleCommand(target, calleeBody, true).applyTo(program, TaskMonitor.DUMMY), "callee decode");
                var function = program.getFunctionManager().createFunction("caller", entry, body, SourceType.USER_DEFINED);
                var callee = mode.equals("missing-callee") ? null : program.getFunctionManager().createFunction(
                    "callee", target, calleeBody, SourceType.USER_DEFINED);
                var first = program.getListing().getInstructionAt(entry);
                switch (mode) {
                    case "annotated-tail", "annotated-indirect" -> first.setFlowOverride(FlowOverride.CALL_RETURN);
                    case "thunk", "indirect-thunk" -> function.setThunkedFunction(callee);
                    case "annotated-thunk" -> {
                        function.setThunkedFunction(callee);
                        first.setFlowOverride(FlowOverride.CALL_RETURN);
                    }
                    case "call-override" -> first.setFlowOverride(FlowOverride.CALL_RETURN);
                    case "return-override" -> first.setFlowOverride(FlowOverride.RETURN);
                    case "reference-conflict" -> program.getReferenceManager().addMemoryReference(entry,
                        entry.add(0x2000), RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
                    case "indirect-hint" -> program.getReferenceManager().addMemoryReference(entry,
                        target, RefType.COMPUTED_JUMP, SourceType.USER_DEFINED, 0);
                    case "partial" -> function.setBody(new AddressSet(entry, entry.add(arm ? 2 : 3)));
                    case "patched" -> {
                        program.getListing().clearCodeUnits(entry, first.getMaxAddress(), false);
                        program.getMemory().setByte(entry, (byte) (bytes[0] ^ 1));
                        require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "patched decode");
                    }
                    default -> { }
                }
                var evidence = GhidraCallSiteEvidence.capture(program, List.of(function), image, delta, TaskMonitor.DUMMY).getFirst();
                Kind expected = switch (mode) {
                    case "conditional-move" -> Kind.ORDINARY;
                    case "tail", "annotated-tail", "conditional-tail", "interior-callee" -> Kind.DIRECT_TAIL_CANDIDATE;
                    case "thunk", "annotated-thunk", "indirect-thunk" -> Kind.THUNK_TRANSFER;
                    case "indirect-call" -> Kind.INDIRECT_CALL;
                    case "indirect-tail", "annotated-indirect", "indirect-hint" -> Kind.INDIRECT_TAIL_CANDIDATE;
                    case "internal", "discontiguous", "get-pc" -> Kind.INTERNAL_BRANCH;
                    case "opaque", "call-override", "return-override", "reference-conflict", "partial", "patched" -> Kind.UNAVAILABLE;
                    default -> Kind.DIRECT_CALL;
                };
                var observed = evidence.instructions().getFirst();
                require(observed.transfer().kind() == expected, mode + " " + observed);
                require(evidence.captureComplete() == (expected != Kind.UNAVAILABLE && !mode.equals("gap")), mode + " " + evidence.omissions());
                if (expected == Kind.DIRECT_CALL || expected == Kind.INDIRECT_CALL) {
                    require(observed.transfer().returnPc().equals(entry.add(mode.equals("indirect-call") ? (arm ? 4 : 2) : (arm ? 4 : 5))), "return PC");
                }
                else require(observed.transfer().returnPc() == null, "non-call fabricated return PC");
                if (mode.contains("indirect")) {
                    require(observed.transfer().callee() == null && observed.transfer().target() == null,
                        "indirect transfer inherited a thunk target");
                }
                if (mode.equals("missing-callee") || mode.equals("interior-callee")) {
                    require(observed.transfer().callee() == null, "callee origin fabricated from a missing/interior entry");
                }
                if (mode.equals("rebase")) {
                    require(observed.address().equals(entry) && observed.original().address() == 0x1000 &&
                        observed.transfer().target().equals(target), "capture lost address-space/rebase identity");
                }
                require(GhidraCallSiteEvidence.capture(program, List.of(function), image, delta, TaskMonitor.DUMMY).getFirst()
                    .equals(evidence), "retry changed immutable evidence");
                if (mode.equals("call")) {
                    Path wrongTarget = output.resolve((arm ? "arm" : "x86") + "-wrong-target.elf");
                    Files.write(wrongTarget, elf(!arm, bytes, leaf));
                    try {
                        GhidraCallSiteEvidence.capture(program, List.of(function), ElfImage.read(wrongTarget), delta, TaskMonitor.DUMMY);
                        throw new AssertionError("accepted a conflicting ELF processor");
                    }
                    catch (IllegalStateException expectedMismatch) {
                        require(expectedMismatch.getMessage().startsWith("ELF/Ghidra target mismatch:"), "wrong processor rejection");
                    }
                    int[] polls = {0};
                    var counting = new TaskMonitorAdapter(true) {
                        @Override public void checkCancelled() { polls[0]++; }
                    };
                    GhidraCallSiteEvidence.capture(program, List.of(function), image, delta, counting);
                    for (int index = 1; index <= polls[0]; index++) {
                        int stop = index;
                        int[] count = {0};
                        var cancelled = new TaskMonitorAdapter(true) {
                            @Override public void checkCancelled() throws CancelledException {
                                if (++count[0] == stop) throw new CancelledException();
                            }
                        };
                        try {
                            GhidraCallSiteEvidence.capture(program, List.of(function), image, delta, cancelled);
                            throw new AssertionError("missed cancellation poll " + stop);
                        }
                        catch (CancelledException expectedCancellation) { checks++; }
                    }
                    String frozen = evidence.toString();
                    first.setFlowOverride(FlowOverride.RETURN);
                    callee.setName("renamed_callee", SourceType.USER_DEFINED);
                    var changed = GhidraCallSiteEvidence.capture(program, List.of(function), image, delta, TaskMonitor.DUMMY).getFirst();
                    require(changed.instructions().getFirst().transfer().kind() == Kind.UNAVAILABLE, "missed a later override");
                    require(frozen.equals(evidence.toString()) && observed.transfer().callee().name().equals("callee"),
                        "later Program changes mutated an earlier snapshot");
                }
                require(Arrays.equals(originalBytes, Files.readAllBytes(path)), "capture modified original target");
                report.append(arm ? "aarch64/" : "x86-64/").append(mode).append(' ').append(evidence).append('\n');
            }
            finally { program.endTransaction(transaction, false); }
        }
        finally { program.release(owner); }
    }
}
