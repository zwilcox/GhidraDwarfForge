package ghidradwarfforge;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Instruction;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/** Real decoded arithmetic and control flow must not invent an unaffected stack range. */
public final class CallMemoryEffectsBoundarySmoke {
    private static int checks;

    private record Fixture(String profile, String name, String hex, Long write, long delta) { }

    private CallMemoryEffectsBoundarySmoke() { }

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        run();
    }

    static void run() throws Exception {
        checks = 0;
        for (Fixture fixture : fixtures()) checkFixture(fixture);
        System.out.println("call-memory-effects-boundary-smoke=PASS cases=" + fixtures().size() + " checks=" + checks);
    }

    private static void checkFixture(Fixture fixture) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(fixture.profile()));
        Object owner = new Object();
        var program = new ProgramDB("call-memory-" + fixture.name(), language, language.getDefaultCompilerSpec(), owner);
        byte[] bytes = HexFormat.of().parseHex(fixture.hex());
        var entry = language.getDefaultSpace().getAddress(0x1000);
        var body = new AddressSet(entry, entry.add(bytes.length - 1));
        String label = fixture.profile() + "/" + fixture.name();
        try {
            int transaction = program.startTransaction("decode independent memory-effect fixture");
            try {
                var block = program.getMemory().createInitializedBlock("code", entry, bytes.length,
                    (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(entry, bytes);
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), label + " decode");
            }
            finally {
                program.endTransaction(transaction, true);
            }
            long modification = program.getModificationNumber();
            List<Instruction> instructions = new ArrayList<>();
            program.getListing().getInstructions(body, true).forEach(instructions::add);
            require(instructions.stream().mapToInt(Instruction::getLength).sum() == bytes.length,
                label + " fixture must decode completely");
            CallMemoryEffects.Summary expected = null;
            if (fixture.write() != null) {
                var writes = new LinkedHashSet<CallMemoryEffects.Range>();
                writes.add(new CallMemoryEffects.Range(fixture.write(), fixture.write() + 1));
                // x86 RET releases the saved return-address slot. AArch64 RET does not move SP.
                if (fixture.delta() != 0) writes.add(new CallMemoryEffects.Range(0, fixture.delta()));
                expected = new CallMemoryEffects.Summary(fixture.delta(), writes);
            }
            int[] visits = {0};
            var counter = new TaskMonitorAdapter(true) {
                @Override public void checkCancelled() { visits[0]++; }
            };
            var actual = CallMemoryEffects.summarize(program, entry, instructions, Map.of(), Map.of(), counter);
            require(Objects.equals(actual, expected), label + " exact effects: expected=" + expected + " actual=" + actual);
            var reversed = new ArrayList<>(instructions);
            Collections.reverse(reversed);
            require(Objects.equals(expected, CallMemoryEffects.summarize(program, entry, reversed,
                Map.of(), Map.of(), TaskMonitor.DUMMY)), label + " instruction enumeration must not change the proof");
            for (int cancelAt : new LinkedHashSet<>(List.of(1, Math.max(1, visits[0] / 2), visits[0]))) {
                int[] seen = {0};
                var cancelled = new TaskMonitorAdapter(true) {
                    @Override public void checkCancelled() throws CancelledException {
                        if (++seen[0] == cancelAt) throw new CancelledException();
                    }
                };
                try {
                    CallMemoryEffects.summarize(program, entry, instructions, Map.of(), Map.of(), cancelled);
                    throw new AssertionError(label + " cancellation ignored at " + cancelAt);
                }
                catch (CancelledException required) {
                    require(seen[0] == cancelAt, label + " cancellation must stop immediately");
                }
            }
            // Summaries require a closed, uniquely decoded body with its stated entry.
            var duplicate = new ArrayList<>(instructions);
            duplicate.add(instructions.get(0));
            require(CallMemoryEffects.summarize(program, entry, duplicate, Map.of(), Map.of(), TaskMonitor.DUMMY) == null,
                label + " duplicate instruction must not establish a proof");
            require(CallMemoryEffects.summarize(program, entry.add(bytes.length), instructions,
                Map.of(), Map.of(), TaskMonitor.DUMMY) == null, label + " missing entry must not establish a proof");
            if (fixture.write() != null) {
                require(CallMemoryEffects.summarize(program, entry, instructions.subList(0, instructions.size() - 1),
                    Map.of(), Map.of(), TaskMonitor.DUMMY) == null, label + " open successor must not establish a proof");
            }
            byte[] after = new byte[bytes.length];
            program.getMemory().getBytes(entry, after);
            require(Arrays.equals(bytes, after) && modification == program.getModificationNumber(),
                label + " proof and cancellation must preserve bytes and saved program");
        }
        finally {
            program.release(owner);
        }
    }

    private static List<Fixture> fixtures() {
        return List.of(
            // mov eax, esp; add eax, 16; mov BYTE PTR [eax], 0; ret
            new Fixture("x86:LE:32:default", "copy-sp",
                "89e083c010c60000c3", 16L, 4),
            // mov eax, 16; add eax, esp; mov BYTE PTR [eax], 0; ret
            new Fixture("x86:LE:32:default", "commuted-add",
                "b81000000001e0c60000c3", 16L, 4),
            // mov eax, 8; add eax, 8; add eax, esp; mov BYTE PTR [eax], 0; ret
            new Fixture("x86:LE:32:default", "constant-add",
                "b80800000083c00801e0c60000c3", 16L, 4),
            // mov eax, 24; sub eax, 8; add eax, esp; mov BYTE PTR [eax], 0; ret
            new Fixture("x86:LE:32:default", "constant-sub",
                "b81800000083e80801e0c60000c3", 16L, 4),
            // mov eax, esp; sub eax, 16; mov BYTE PTR [eax], 0; ret
            new Fixture("x86:LE:32:default", "negative-write",
                "89e083e810c60000c3", -16L, 4),
            // mov eax, esp; sub eax, esp; add eax, esp; mov BYTE PTR [eax], 0; ret
            new Fixture("x86:LE:32:default", "stack-difference",
                "89e029e001e0c60000c3", 0L, 4),
            // mov eax, 16; sub eax, esp; mov BYTE PTR [eax], 0; ret
            new Fixture("x86:LE:32:default", "subtract-stack",
                "b81000000029e0c60000c3", null, 4),
            // mov eax, esp; add eax, esp; mov BYTE PTR [eax], 0; ret
            new Fixture("x86:LE:32:default", "two-stacks",
                "89e001e0c60000c3", null, 4),
            // mov eax, 16; mov BYTE PTR [eax], 0; ret
            new Fixture("x86:LE:32:default", "absolute-store",
                "b810000000c60000c3", null, 4),
            // mov eax, esp; add eax, edi; mov BYTE PTR [eax], 0; ret
            new Fixture("x86:LE:32:default", "unknown-offset",
                "89e001f8c60000c3", null, 4),
            // mov eax, esp; mov al, 1; mov BYTE PTR [eax], 0; ret
            new Fixture("x86:LE:32:default", "partial-clobber",
                "89e0b001c60000c3", null, 4),
            // mov eax, esp; add eax, 0x7fffffff; add eax, 1; mov BYTE PTR [eax], 0; ret
            new Fixture("x86:LE:32:default", "pointer-overflow",
                "89e005ffffff7f83c001c60000c3", null, 4),
            // test edi, edi; jz 1f; mov eax, esp; add eax, 16; jmp 2f; 1: mov eax, esp; add eax, 16; 2: mov BYTE PTR [eax], 0; ret
            new Fixture("x86:LE:32:default", "join-agrees",
                "85ff740789e083c010eb0589e083c010c60000c3", 16L, 4),
            // test edi, edi; jz 1f; mov eax, esp; add eax, 16; jmp 2f; 1: mov eax, esp; add eax, 24; 2: mov BYTE PTR [eax], 0; ret
            new Fixture("x86:LE:32:default", "join-conflicts",
                "85ff740789e083c010eb0589e083c018c60000c3", null, 4),
            // mov rax, rsp; add rax, 16; mov BYTE PTR [rax], 0; ret
            new Fixture("x86:LE:64:default", "copy-sp",
                "4889e04883c010c60000c3", 16L, 8),
            // mov rax, 16; add rax, rsp; mov BYTE PTR [rax], 0; ret
            new Fixture("x86:LE:64:default", "commuted-add",
                "48c7c0100000004801e0c60000c3", 16L, 8),
            // mov rax, 8; add rax, 8; add rax, rsp; mov BYTE PTR [rax], 0; ret
            new Fixture("x86:LE:64:default", "constant-add",
                "48c7c0080000004883c0084801e0c60000c3", 16L, 8),
            // mov rax, 24; sub rax, 8; add rax, rsp; mov BYTE PTR [rax], 0; ret
            new Fixture("x86:LE:64:default", "constant-sub",
                "48c7c0180000004883e8084801e0c60000c3", 16L, 8),
            // mov rax, rsp; sub rax, 16; mov BYTE PTR [rax], 0; ret
            new Fixture("x86:LE:64:default", "negative-write",
                "4889e04883e810c60000c3", -16L, 8),
            // mov rax, rsp; sub rax, rsp; add rax, rsp; mov BYTE PTR [rax], 0; ret
            new Fixture("x86:LE:64:default", "stack-difference",
                "4889e04829e04801e0c60000c3", 0L, 8),
            // mov rax, 16; sub rax, rsp; mov BYTE PTR [rax], 0; ret
            new Fixture("x86:LE:64:default", "subtract-stack",
                "48c7c0100000004829e0c60000c3", null, 8),
            // mov rax, rsp; add rax, rsp; mov BYTE PTR [rax], 0; ret
            new Fixture("x86:LE:64:default", "two-stacks",
                "4889e04801e0c60000c3", null, 8),
            // mov rax, 16; mov BYTE PTR [rax], 0; ret
            new Fixture("x86:LE:64:default", "absolute-store",
                "48c7c010000000c60000c3", null, 8),
            // mov rax, rsp; add rax, rdi; mov BYTE PTR [rax], 0; ret
            new Fixture("x86:LE:64:default", "unknown-offset",
                "4889e04801f8c60000c3", null, 8),
            // mov rax, rsp; mov al, 1; mov BYTE PTR [rax], 0; ret
            new Fixture("x86:LE:64:default", "partial-clobber",
                "4889e0b001c60000c3", null, 8),
            // mov rax, rsp; add rax, 0x7fffffff; add rax, 1; mov BYTE PTR [rax], 0; ret
            new Fixture("x86:LE:64:default", "pointer-overflow",
                "4889e04805ffffff7f4883c001c60000c3", 2147483648L, 8),
            // test rdi, rdi; jz 1f; mov rax, rsp; add rax, 16; jmp 2f; 1: mov rax, rsp; add rax, 16; 2: mov BYTE PTR [rax], 0; ret
            new Fixture("x86:LE:64:default", "join-agrees",
                "4885ff74094889e04883c010eb074889e04883c010c60000c3", 16L, 8),
            // test rdi, rdi; jz 1f; mov rax, rsp; add rax, 16; jmp 2f; 1: mov rax, rsp; add rax, 24; 2: mov BYTE PTR [rax], 0; ret
            new Fixture("x86:LE:64:default", "join-conflicts",
                "4885ff74094889e04883c010eb074889e04883c018c60000c3", null, 8),
            // mov x0, sp; add x0, x0, #16; strb wzr, [x0]; ret
            new Fixture("AARCH64:LE:64:v8A", "copy-sp",
                "e0030091004000911f000039c0035fd6", 16L, 0),
            // mov x0, #16; add x0, sp, x0; strb wzr, [x0]; ret
            new Fixture("AARCH64:LE:64:v8A", "commuted-add",
                "000280d2e063208b1f000039c0035fd6", 16L, 0),
            // mov x0, #8; add x0, x0, #8; add x0, sp, x0; strb wzr, [x0]; ret
            new Fixture("AARCH64:LE:64:v8A", "constant-add",
                "000180d200200091e063208b1f000039c0035fd6", 16L, 0),
            // mov x0, #24; sub x0, x0, #8; add x0, sp, x0; strb wzr, [x0]; ret
            new Fixture("AARCH64:LE:64:v8A", "constant-sub",
                "000380d2002000d1e063208b1f000039c0035fd6", 16L, 0),
            // sub x0, sp, #16; strb wzr, [x0]; ret
            new Fixture("AARCH64:LE:64:v8A", "negative-write",
                "e04300d11f000039c0035fd6", -16L, 0),
            // mov x0, sp; mov x1, sp; sub x0, x0, x1; add x0, sp, x0; strb wzr, [x0]; ret
            new Fixture("AARCH64:LE:64:v8A", "stack-difference",
                "e0030091e1030091000001cbe063208b1f000039c0035fd6", 0L, 0),
            // mov x0, #16; mov x1, sp; sub x0, x0, x1; strb wzr, [x0]; ret
            new Fixture("AARCH64:LE:64:v8A", "subtract-stack",
                "000280d2e1030091000001cb1f000039c0035fd6", null, 0),
            // mov x0, sp; mov x1, sp; add x0, x0, x1; strb wzr, [x0]; ret
            new Fixture("AARCH64:LE:64:v8A", "two-stacks",
                "e0030091e10300910000018b1f000039c0035fd6", null, 0),
            // mov x0, #16; strb wzr, [x0]; ret
            new Fixture("AARCH64:LE:64:v8A", "absolute-store",
                "000280d21f000039c0035fd6", null, 0),
            // mov x0, sp; add x0, x0, x1; strb wzr, [x0]; ret
            new Fixture("AARCH64:LE:64:v8A", "unknown-offset",
                "e00300910000018b1f000039c0035fd6", null, 0),
            // mov x0, sp; mov w0, w1; strb wzr, [x0]; ret
            new Fixture("AARCH64:LE:64:v8A", "partial-clobber",
                "e0030091e003012a1f000039c0035fd6", null, 0),
            // mov x0, #0x7fffffffffffffff; add x0, sp, x0; add x0, x0, #1; strb wzr, [x0]; ret
            new Fixture("AARCH64:LE:64:v8A", "pointer-overflow",
                "0000f092e063208b000400911f000039c0035fd6", null, 0),
            // cbz x2, 1f; add x0, sp, #16; b 2f; 1: add x0, sp, #16; 2: strb wzr, [x0]; ret
            new Fixture("AARCH64:LE:64:v8A", "join-agrees",
                "620000b4e043009102000014e04300911f000039c0035fd6", 16L, 0),
            // cbz x2, 1f; add x0, sp, #16; b 2f; 1: add x0, sp, #24; 2: strb wzr, [x0]; ret
            new Fixture("AARCH64:LE:64:v8A", "join-conflicts",
                "620000b4e043009102000014e06300911f000039c0035fd6", null, 0)
        );
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
