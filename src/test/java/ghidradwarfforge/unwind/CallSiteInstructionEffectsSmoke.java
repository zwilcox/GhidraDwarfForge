package ghidradwarfforge.unwind;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.unwind.UnwindFlow.*;

/** Actual decoded call-site effects must never retain a conditionally overwritten argument. */
public final class CallSiteInstructionEffectsSmoke {
    private static int checks;

    private enum Outcome { COPY, KILL, OPAQUE, ADD, SUBTRACT }

    private record Fixture(String language, String name, String hex, String destination,
            String source, String preserved, Outcome outcome) { }

    private CallSiteInstructionEffectsSmoke() { }

    static void run() throws Exception {
        checks = 0;
        for (Fixture fixture : fixtures()) check(fixture);
        System.out.println("call-site-instruction-effects=PASS cases=" + fixtures().size() + " checks=" + checks);
    }

    private static List<Fixture> fixtures() {
        var fixtures = new ArrayList<Fixture>();
        for (boolean wide : List.of(false, true)) {
            String language = wide ? "x86:LE:64:default" : "x86:LE:32:default";
            String destination = wide ? "RAX" : "EAX", source = wide ? "RBX" : "EBX";
            String preserved = wide ? "RDI" : "EDI", rex = wide ? "48" : "";
            fixtures.add(new Fixture(language, "copy", rex + "89d8", destination, source, preserved, Outcome.COPY));
            fixtures.add(new Fixture(language, "add", rex + "01d8", destination, source, preserved, Outcome.ADD));
            fixtures.add(new Fixture(language, "subtract", rex + "29d8", destination, source, preserved, Outcome.SUBTRACT));
            fixtures.add(new Fixture(language, "conditional-copy", rex + "0f45c3", destination, source, preserved, Outcome.KILL));
            fixtures.add(new Fixture(language, "conditional-load", rex + "0f4503", destination, source, preserved, Outcome.KILL));
            fixtures.add(new Fixture(language, "population-count", "f3" + rex + "0fb8c3", destination, source, preserved, Outcome.KILL));
            fixtures.add(new Fixture(language, "leading-zero-count", "f3" + rex + "0fbdc3", destination, source, preserved, Outcome.KILL));
            fixtures.add(new Fixture(language, "direct-call", "e8fb0f0000", destination, source, preserved, Outcome.OPAQUE));
            fixtures.add(new Fixture(language, "indirect-call", "ffd3", destination, source, preserved, Outcome.OPAQUE));
            fixtures.add(new Fixture(language, "computed-jump", "ffe3", destination, source, preserved, Outcome.OPAQUE));
            fixtures.add(new Fixture(language, "repeated-store", "f3aa", destination, source, preserved, Outcome.OPAQUE));
            fixtures.add(new Fixture(language, "unmodeled-floating", "f20f58c1", destination, source, preserved, Outcome.OPAQUE));
        }
        String arm = "ARM:LE:32:v7";
        fixtures.add(new Fixture(arm, "copy", "0100a0e1", "r0", "r1", "r4", Outcome.COPY));
        fixtures.add(new Fixture(arm, "conditional-copy", "0100a001", "r0", "r1", "r4", Outcome.KILL));
        // ARM's predicated load includes address arithmetic inside the conditional
        // path. The current call-site decoder deliberately omits that whole
        // instruction; it must not retain facts as if the load never happened.
        fixtures.add(new Fixture(arm, "conditional-load", "00009105", "r0", "r1", "r4", Outcome.OPAQUE));
        fixtures.add(new Fixture(arm, "conditional-store", "00008105", "r0", "r1", "r4", Outcome.OPAQUE));
        fixtures.add(new Fixture(arm, "leading-zero-count", "110f6fe1", "r0", "r1", "r4", Outcome.KILL));
        fixtures.add(new Fixture(arm, "indirect-call", "31ff2fe1", "r0", "r1", "r4", Outcome.OPAQUE));
        String aarch64 = "AARCH64:LE:64:v8A";
        fixtures.add(new Fixture(aarch64, "copy", "e00301aa", "x0", "x1", "x19", Outcome.COPY));
        fixtures.add(new Fixture(aarch64, "conditional-copy", "2010829a", "x0", "x1", "x19", Outcome.KILL));
        fixtures.add(new Fixture(aarch64, "leading-zero-count", "2010c0da", "x0", "x1", "x19", Outcome.KILL));
        fixtures.add(new Fixture(aarch64, "indirect-call", "20003fd6", "x0", "x1", "x19", Outcome.OPAQUE));
        return List.copyOf(fixtures);
    }

    private static void check(Fixture fixture) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(fixture.language()));
        Object owner = new Object();
        var program = new ProgramDB("call-site-effects", language, language.getDefaultCompilerSpec(), owner);
        byte[] bytes = HexFormat.of().parseHex(fixture.hex());
        String label = fixture.language() + "/" + fixture.name();
        try {
            var entry = language.getDefaultSpace().getAddress(0x1000);
            int transaction = program.startTransaction("decode call-site effect fixture");
            try {
                var block = program.getMemory().createInitializedBlock("code", entry, bytes.length,
                    (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(entry, bytes);
                require(new DisassembleCommand(entry, new AddressSet(entry, entry.add(bytes.length - 1)), true)
                    .applyTo(program, TaskMonitor.DUMMY), label + " decode");
            }
            finally { program.endTransaction(transaction, true); }
            var instruction = program.getListing().getInstructionAt(entry);
            require(instruction != null && instruction.getLength() == bytes.length, label + " must decode exactly one instruction");
            long modification = program.getModificationNumber();
            var destination = cell(program, fixture.destination());
            var source = cell(program, fixture.source());
            var preserved = cell(program, fixture.preserved());
            var stack = cell(program, program.getCompilerSpec().getStackPointer().getName());
            int width = destination.bytes();
            var incoming = new Incoming(1, width);
            var unrelated = new Incoming(4, width);
            boolean arithmetic = fixture.outcome() == Outcome.ADD || fixture.outcome() == Outcome.SUBTRACT;
            var values = new LinkedHashMap<Cell, Value>();
            values.put(destination, new StackAddress(32, width));
            values.put(source, arithmetic ? new Constant(8, width) : incoming);
            values.put(preserved, unrelated);
            values.put(stack, new StackAddress(0, width));
            var memory = Map.<Slot, Value>of(new Slot(0, width), new ReturnAddress(width));
            var seed = new State(values, memory);
            int[] polls = {0};
            var counting = new TaskMonitorAdapter(true) {
                @Override public void checkCancelled() { polls[0]++; }
            };
            var effects = GhidraUnwindInstructions.callSiteEffects(program, instruction, counting);
            var graph = Map.of(0, new Node<>(effects, List.<Integer>of()));
            var after = UnwindFlow.analyze(graph, 0, seed, stack, () -> false).after().get(0);
            if (fixture.outcome() == Outcome.OPAQUE) {
                require(effects.size() == 1 && effects.getFirst() instanceof Opaque,
                    label + " unproved effects must replace the whole instruction: " + effects);
                require(after.values().isEmpty() && after.memory().isEmpty(), label + " retained facts across unproved effects");
            }
            else {
                require(effects.stream().noneMatch(Opaque.class::isInstance), label + " unexpected whole-instruction omission: " + effects +
                    " raw=" + Arrays.toString(instruction.getPcode(false)));
                Value expected = switch (fixture.outcome()) {
                    case COPY -> incoming;
                    case KILL -> null;
                    case ADD -> new StackAddress(40, width);
                    case SUBTRACT -> new StackAddress(24, width);
                    default -> throw new AssertionError();
                };
                require(java.util.Objects.equals(after.values().get(destination), expected),
                    label + " derived unsafe argument identity: " + after + " effects=" + effects);
                require(after.values().get(source).equals(values.get(source)) && after.values().get(preserved).equals(unrelated),
                    label + " destroyed unrelated register facts");
                require(after.values().get(stack).equals(values.get(stack)) && after.memory().equals(memory),
                    label + " changed unaffected stack facts");
                if (fixture.outcome() == Outcome.KILL) {
                    require(effects.stream().anyMatch(effect -> effect instanceof Kill kill &&
                        kill.output().bank() == destination.bank() && kill.output().offset() == destination.offset()),
                        label + " omitted destination kill");
                }
            }
            for (int stop = 1; stop <= polls[0]; stop++) {
                int selected = stop;
                int[] visits = {0};
                var cancelled = new TaskMonitorAdapter(true) {
                    @Override public void checkCancelled() throws CancelledException {
                        if (++visits[0] == selected) throw new CancelledException();
                    }
                };
                try {
                    GhidraUnwindInstructions.callSiteEffects(program, instruction, cancelled);
                    throw new AssertionError(label + " ignored cancellation at " + selected);
                }
                catch (CancelledException required) { require(visits[0] == selected, label + " late cancellation"); }
            }
            require(effects.equals(GhidraUnwindInstructions.callSiteEffects(program, instruction, TaskMonitor.DUMMY)),
                label + " retry changed effects");
            byte[] afterBytes = new byte[bytes.length];
            program.getMemory().getBytes(entry, afterBytes);
            require(Arrays.equals(bytes, afterBytes) && modification == program.getModificationNumber(),
                label + " changed saved program or code bytes");
        }
        finally { program.release(owner); }
    }

    private static Cell cell(ProgramDB program, String name) {
        var register = program.getRegister(name);
        return GhidraUnwindInstructions.cell(new Varnode(register.getAddress(), register.getMinimumByteSize()));
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
