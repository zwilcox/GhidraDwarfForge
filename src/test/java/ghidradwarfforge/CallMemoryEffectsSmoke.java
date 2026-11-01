package ghidradwarfforge;

import java.io.File;
import java.util.HexFormat;
import java.util.List;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.util.exception.CancelledException;

/** Actual p-code stack deltas, writes, joins and unsupported alias controls. */
public final class CallMemoryEffectsSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (boolean x86 : new boolean[] {true, false}) {
            for (String mode : List.of("return", "frame", "caller-slot", "unknown-store", "unequal-return",
                    "branch", "drift-loop", "unknown-sp", "nested", "recursive")) check(x86, mode);
        }
        System.out.println("call-memory-effects-smoke=PASS checks=" + checks);
    }

    private static void check(boolean x86, String mode) throws Exception {
        String ret = x86 ? "c3" : "c0035fd6";
        String callee = switch (mode) {
            case "frame" -> (x86 ? "4883ec20c6442408004883c420" : "ff8300d1ff230039ff830091") + ret;
            case "caller-slot" -> (x86 ? "c644241000" : "ff430039") + ret;
            case "unknown-store" -> (x86 ? "c60700" : "1f000039") + ret;
            case "unequal-return" -> x86 ? "85ff7401c34883c408c3" : "400000b4c0035fd6ff430091c0035fd6";
            case "branch" -> (x86 ? "85ff74084883ec204883c420" : "600000b4ff8300d1ff830091") + ret;
            case "drift-loop" -> (x86 ? "4883ec0885ff75f8" : "ff2300d1e0ffffb5") + ret;
            case "unknown-sp" -> (x86 ? "31e4" : "1f000091") + ret;
            case "nested" -> (x86 ? "e8fb0f0000" : "fd7bbfa9ff030094fd7bc1a8") + ret;
            case "recursive" -> (x86 ? "e8fbffffff" : "00000094") + ret;
            default -> ret;
        };
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
            x86 ? "x86:LE:64:default" : "AARCH64:LE:64:v8A"));
        Object owner = new Object();
        var program = new ProgramDB("call-memory-effects", language, language.getDefaultCompilerSpec(), owner);
        try {
            int tx = program.startTransaction("callee memory contracts");
            try {
                var entry = language.getDefaultSpace().getAddress(0x1000);
                var block = program.getMemory().createInitializedBlock("code", entry, 0x2100,
                    (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                String[] bodies = {(x86 ? "e8fb0f0000" : "00040094") + ret, callee, ret};
                for (int index = 0; index < bodies.length; index++) {
                    var address = entry.add(index * 0x1000);
                    byte[] bytes = HexFormat.of().parseHex(bodies[index]);
                    program.getMemory().setBytes(address, bytes);
                    var body = new AddressSet(address, address.add(bytes.length - 1));
                    require(new DisassembleCommand(address, body, true).applyTo(program, TaskMonitor.DUMMY), "decode");
                    var function = program.getFunctionManager().createFunction("body" + index, address, body, SourceType.USER_DEFINED);
                    function.setCallingConvention(program.getCompilerSpec().getDefaultCallingConvention().getName());
                }
                var instruction = program.getListing().getInstructionAt(entry);
                var calls = DirectLeafCalls.inspect(program, List.of(instruction), TaskMonitor.DUMMY);
                require(calls != null && calls.size() == 1, mode + " inspected register graph");
                var memory = calls.get(entry).memory();
                boolean known = !List.of("unknown-store", "unequal-return", "drift-loop", "unknown-sp", "recursive").contains(mode);
                if (known && memory == null) {
                    for (var decoded : calls.get(entry).instructions()) {
                        System.err.println(decoded.getAddress() + " " + decoded + " " + java.util.Arrays.toString(decoded.getPcode()));
                    }
                }
                require((memory != null) == known, (x86 ? "x86/" : "arm/") + mode + " " + memory);
                if (known) {
                    require(memory.stackDelta() == (x86 ? 8 : 0), mode + " raw return delta");
                    if (x86) require(memory.writes().contains(new CallMemoryEffects.Range(0, 8)), "return releases its slot");
                    if (mode.equals("caller-slot")) require(memory.writes().contains(new CallMemoryEffects.Range(16, 17)), "exact partial write");
                    if (mode.equals("frame")) require(memory.writes().contains(new CallMemoryEffects.Range(-24, -23)), "exact frame write");
                    if (mode.equals("frame") || mode.equals("branch")) {
                        require(memory.writes().contains(new CallMemoryEffects.Range(-32, 0)), "possible frame release");
                    }
                    if (mode.equals("nested")) require(memory.writes().stream().anyMatch(range -> range.start() < 0), "nested frame effects");
                }
                var cancelled = new TaskMonitorAdapter(true);
                cancelled.cancel();
                try {
                    DirectLeafCalls.inspect(program, List.of(instruction), cancelled);
                    throw new AssertionError("cancellation ignored");
                }
                catch (CancelledException expected) { checks++; }
            }
            finally { program.endTransaction(tx, false); }
        }
        finally { program.release(owner); }
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
