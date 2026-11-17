package ghidradwarfforge.unwind;

import java.io.File;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;

/** Real saved-program admission controls, not an exported CFI support claim. */
public final class UnwindCaptureAdmissionSmoke {
    private static final GhidraUnwindInstructions.InstructionPolicy RAW =
        (instruction, monitor) -> monitor.checkCancelled();
    private static int checks;

    private UnwindCaptureAdmissionSmoke() { }

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        run();
    }

    static void run() throws Exception {
        checks = 0;
        savedOverrides();
        try (var fixture = new Fixture("x86:LE:64:default", HexFormat.of().parseHex("ffe0"))) {
            require(fixture.program.getListing().getInstructionAt(fixture.entry).getFlowType().isComputed(),
                "actual computed-jump premise");
            unchangedRefusal(fixture, "unresolved control flow");
        }
        for (String language : List.of("MIPS:BE:32:default", "MIPS:LE:32:default")) {
            delaySlots(language);
        }
        instructionBudget();
        System.out.println("unwind-capture-admission=PASS checks=" + checks);
    }

    private static void savedOverrides() throws Exception {
        try (var fixture = new Fixture("x86:LE:64:default", HexFormat.of().parseHex("b80100000090c3"))) {
            var program = fixture.program;
            var function = fixture.function;
            var original = accepted(fixture);
            require(original.graph().size() == 3, "baseline must contain three actual decoded instructions");
            for (String change : List.of("length", "fallthrough", "thunk", "external", "body-budget", "flow-target")) {
                int transaction = program.startTransaction("curated unwind admission " + change);
                try {
                    var first = program.getListing().getInstructionAt(fixture.entry);
                    String diagnostic = "incomplete, overridden or unsupported instruction";
                    switch (change) {
                        case "length" -> {
                            first.setLengthOverride(1);
                            require(first.isLengthOverridden(), "length override premise");
                        }
                        case "fallthrough" -> {
                            first.setFallThrough(fixture.entry.add(6));
                            require(first.isFallThroughOverridden(), "fallthrough override premise");
                        }
                        case "thunk" -> {
                            Function external = program.getExternalManager().addExtFunction("fixture_lib",
                                "callee", null, SourceType.USER_DEFINED).getFunction();
                            function.setThunkedFunction(external);
                            require(function.isThunk(), "thunk premise");
                            diagnostic = "unsupported or unbounded unwind function body";
                        }
                        case "external" -> {
                            fixture.function = program.getExternalManager().addExtFunction("fixture_lib",
                                "external_only", null, SourceType.USER_DEFINED).getFunction();
                            require(fixture.function.isExternal(), "external function premise");
                            diagnostic = "unsupported or unbounded unwind function body";
                        }
                        case "body-budget" -> {
                            function.setBody(new AddressSet(fixture.entry, fixture.entry.add(1_048_576)));
                            require(function.getBody().getNumAddresses() == 1_048_577, "body budget premise");
                            diagnostic = "unsupported or unbounded unwind function body";
                        }
                        case "flow-target" -> {
                            program.getReferenceManager().addMemoryReference(fixture.entry, fixture.entry.add(6),
                                RefType.UNCONDITIONAL_JUMP, SourceType.USER_DEFINED, 0);
                            require(!Arrays.equals(first.getFlows(), first.getDefaultFlows()), "flow target premise");
                            diagnostic = "flow targets differ from decode";
                        }
                        default -> throw new AssertionError(change);
                    }
                    unchangedRefusal(fixture, diagnostic);
                }
                finally {
                    program.endTransaction(transaction, false);
                    fixture.function = function;
                }
                require(accepted(fixture).equals(original), "rollback/retry changed decoded evidence after " + change);
            }

            int transaction = program.startTransaction("body changes during capture");
            try {
                var changed = new AddressSet(function.getBody());
                changed.add(fixture.entry.add(16));
                int[] edits = {0};
                try {
                    GhidraUnwindInstructions.capture(program, function, (instruction, monitor) -> {
                        monitor.checkCancelled();
                        if (edits[0]++ == 0) {
                            try { function.setBody(changed); }
                            catch (Exception failure) { throw new AssertionError("controlled body edit failed", failure); }
                        }
                    }, instruction -> null, TaskMonitor.DUMMY);
                    throw new AssertionError("capture accepted a stale function body");
                }
                catch (IllegalArgumentException expected) {
                    require(expected.getMessage().contains("function body changed during capture"),
                        "body change rejected for wrong reason: " + expected.getMessage());
                }
                require(function.getBody().equals(changed), "capture rewrote the controlled body edit");
                fixture.requireCodeUnchanged();
            }
            finally { program.endTransaction(transaction, false); }
            require(accepted(fixture).equals(original), "body change refusal poisoned retry");
        }
    }

    private static void delaySlots(String language) throws Exception {
        // jr ra; nop, encoded independently for each byte order.
        String hex = language.contains(":BE:") ? "03e0000800000000" : "0800e00300000000";
        try (var fixture = new Fixture(language, HexFormat.of().parseHex(hex))) {
            var branch = fixture.program.getListing().getInstructionAt(fixture.entry);
            var slot = fixture.program.getListing().getInstructionAt(fixture.entry.add(4));
            require(branch.getDelaySlotDepth() == 1 && slot.isInDelaySlot(), "real MIPS delay-slot premise");
            unchangedRefusal(fixture, "incomplete, overridden or unsupported instruction");
            int transaction = fixture.program.startTransaction("delay slot as function body");
            try {
                fixture.program.getFunctionManager().removeFunction(fixture.entry);
                fixture.function = fixture.program.getFunctionManager().createFunction("slot_only", fixture.entry.add(4),
                    new AddressSet(fixture.entry.add(4), fixture.entry.add(7)), SourceType.USER_DEFINED);
                unchangedRefusal(fixture, "incomplete, overridden or unsupported instruction");
            }
            finally { fixture.program.endTransaction(transaction, false); }
        }
    }

    private static void instructionBudget() throws Exception {
        byte[] bytes = new byte[65_537];
        Arrays.fill(bytes, (byte) 0x90); // one-byte x86 NOPs
        bytes[65_535] = (byte) 0xc3;
        bytes[65_536] = (byte) 0xc3;
        try (var fixture = new Fixture("x86:LE:64:default", bytes)) {
            int transaction = fixture.program.startTransaction("exact instruction budget");
            try {
                require(fixture.program.getListing().getInstructionAt(fixture.entry.add(65_536)) != null,
                    "additional return must be decoded");
                fixture.function.setBody(new AddressSet(fixture.entry, fixture.entry.add(65_535)));
            }
            finally { fixture.program.endTransaction(transaction, true); }
            long modification = fixture.program.getModificationNumber();
            var exact = accepted(fixture);
            require(exact.graph().size() == 65_536 && exact.observations().size() == 65_536,
                "exact instruction cap was not admitted completely");
            require(exact.graph().get(fixture.entry.add(65_535)).successors().isEmpty(), "last return gained an edge");
            require(fixture.program.getModificationNumber() == modification, "capture changed maximum fixture");
            fixture.requireCodeUnchanged();
            transaction = fixture.program.startTransaction("first excess instruction");
            try {
                fixture.function.setBody(new AddressSet(fixture.entry, fixture.entry.add(65_536)));
                unchangedRefusal(fixture, "unwind instruction budget exceeded");
            }
            finally { fixture.program.endTransaction(transaction, false); }
            require(fixture.function.getBody().getNumAddresses() == 65_536, "budget refusal altered prior body");
        }
    }

    private static GhidraUnwindInstructions.Captured capture(Fixture fixture) throws Exception {
        return GhidraUnwindInstructions.capture(fixture.program, fixture.function, RAW,
            instruction -> null, TaskMonitor.DUMMY);
    }

    private static GhidraUnwindInstructions.Captured accepted(Fixture fixture) throws Exception {
        try { return capture(fixture); }
        catch (IllegalArgumentException failure) {
            throw new AssertionError("valid decoded fixture was rejected", failure);
        }
    }

    private static void unchangedRefusal(Fixture fixture, String diagnostic) throws Exception {
        long modification = fixture.program.getModificationNumber();
        var body = new AddressSet(fixture.function.getBody());
        try {
            capture(fixture);
            throw new AssertionError("unwind capture accepted " + diagnostic);
        }
        catch (IllegalArgumentException expected) {
            require(expected.getMessage().contains(diagnostic), "wrong admission failure: " + expected.getMessage());
        }
        require(fixture.program.getModificationNumber() == modification && fixture.function.getBody().equals(body),
            "refusal changed saved function or program");
        fixture.requireCodeUnchanged();
    }

    private static final class Fixture implements AutoCloseable {
        private final Object owner = new Object();
        private final ProgramDB program;
        private final Address entry;
        private final byte[] bytes;
        private Function function;

        private Fixture(String id, byte[] bytes) throws Exception {
            this.bytes = bytes.clone();
            var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(id));
            program = new ProgramDB("unwind-admission", language, language.getDefaultCompilerSpec(), owner);
            entry = language.getDefaultSpace().getAddress(0x1000);
            boolean initialized = false;
            try {
                int transaction = program.startTransaction("decoded fixture");
                try {
                    var block = program.getMemory().createInitializedBlock("code", entry, bytes.length,
                        (byte) 0, TaskMonitor.DUMMY, false);
                    block.setExecute(true);
                    program.getMemory().setBytes(entry, bytes);
                    var body = new AddressSet(entry, entry.add(bytes.length - 1));
                    // The set overload explicitly decodes this bounded region;
                    // the address overload stops on long repeated-NOP runs.
                    require(new DisassembleCommand(body, body, true).applyTo(program, TaskMonitor.DUMMY), "fixture decode");
                    function = program.getFunctionManager().createFunction("capture_me", entry, body, SourceType.USER_DEFINED);
                }
                finally { program.endTransaction(transaction, true); }
                initialized = true;
            }
            finally { if (!initialized) program.release(owner); }
        }

        private void requireCodeUnchanged() throws Exception {
            byte[] actual = new byte[bytes.length];
            require(program.getMemory().getBytes(entry, actual) == actual.length && Arrays.equals(bytes, actual),
                "capture changed original code bytes");
        }

        @Override public void close() { program.release(owner); }
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
