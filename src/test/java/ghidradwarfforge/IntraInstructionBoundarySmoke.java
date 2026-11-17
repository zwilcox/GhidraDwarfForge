package ghidradwarfforge;

import java.io.File;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/** Raw p-code admission boundaries; these synthetic operations are not new processor-support evidence. */
public final class IntraInstructionBoundarySmoke {
    private static int checks;

    private IntraInstructionBoundarySmoke() { }

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        run();
    }

    static void run() throws Exception {
        checks = 0;
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("ARM:LE:32:v8"));
        Object owner = new Object();
        var program = new ProgramDB("raw-instruction-boundaries", language, language.getDefaultCompilerSpec(), owner);
        try {
            long modification = program.getModificationNumber();
            var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
            var constants = program.getAddressFactory().getConstantSpace();
            var register = new Varnode(program.getRegister("r0").getAddress(), 4);
            var condition = new Varnode(program.getRegister("ZR").getAddress(), 1);
            reject(null);
            reject(new PcodeOp[0]);
            reject(new PcodeOp[] {null});
            for (int length : new int[] {1, 2, 3, 7, 127, 4096, 4097}) {
                var operations = new PcodeOp[length];
                for (int index = 0; index < length; index++) {
                    operations[index] = new PcodeOp(address, index, PcodeOp.COPY, new Varnode[] {register}, register);
                }
                reject(operations); // No branch means there is no internal-flow proof.
                for (int index : new LinkedHashSet<>(List.of(0, length / 2, length - 1))) {
                    for (int distance : new LinkedHashSet<>(List.of(1, length - index))) {
                        for (int opcode : new int[] {PcodeOp.BRANCH, PcodeOp.CBRANCH}) {
                            var candidate = operations.clone();
                            var target = new Varnode(constants.getAddress(distance), 4);
                            candidate[index] = new PcodeOp(address, index, opcode, opcode == PcodeOp.BRANCH ?
                                new Varnode[] {target} : new Varnode[] {target, condition}, null);
                            if (length > 4096) reject(candidate);
                            else {
                                int[] expected = new int[length];
                                Arrays.fill(expected, -1);
                                expected[index] = index + distance;
                                var before = Arrays.stream(candidate).map(Object::toString).toList();
                                require(Arrays.equals(IntraInstructionFlow.targets(candidate, TaskMonitor.DUMMY), expected),
                                    "wrong relative target or exact operation-cap refusal");
                                require(before.equals(Arrays.stream(candidate).map(Object::toString).toList()),
                                    "target classification modified raw operations");
                            }
                        }
                    }
                }
            }
            var target = new Varnode(constants.getAddress(1), 4);
            for (int opcode : new int[] {PcodeOp.BRANCH, PcodeOp.CBRANCH}) {
                for (Varnode[] inputs : List.of(new Varnode[0], new Varnode[] {null},
                        new Varnode[] {null, condition}, new Varnode[] {target, null},
                        new Varnode[] {target, condition, condition})) {
                    reject(new PcodeOp[] {new PcodeOp(address, 0, opcode, inputs, null)});
                }
            }
            reject(new PcodeOp[] {new PcodeOp(address, 0, PcodeOp.CBRANCH, new Varnode[] {target}, null)});
            reject(new PcodeOp[] {new PcodeOp(address, 0, PcodeOp.BRANCH, new Varnode[] {target, condition}, null)});
            for (int width : new int[] {2, 4, 8}) {
                reject(new PcodeOp[] {new PcodeOp(address, 0, PcodeOp.CBRANCH,
                    new Varnode[] {target, new Varnode(condition.getAddress(), width)}, null)});
            }
            for (long distance : new long[] {0, -1, 2, Long.MAX_VALUE}) {
                reject(new PcodeOp[] {new PcodeOp(address, 0, PcodeOp.BRANCH,
                    new Varnode[] {new Varnode(constants.getAddress(distance), 8)}, null)});
            }
            var branch = new PcodeOp(address, 0, PcodeOp.BRANCH, new Varnode[] {target}, null);
            reject(new PcodeOp[] {branch, null});
            for (int stop = 1; stop <= 2; stop++) {
                int selected = stop;
                var monitor = new TaskMonitorAdapter(true) {
                    private int polls;
                    @Override
                    public void checkCancelled() throws CancelledException {
                        if (++polls == selected) cancel();
                        super.checkCancelled();
                    }
                };
                try {
                    IntraInstructionFlow.targets(new PcodeOp[] {branch}, monitor);
                    throw new AssertionError("internal-flow classification ignored cancellation");
                }
                catch (CancelledException expected) { checks++; }
            }
            require(Arrays.equals(IntraInstructionFlow.targets(new PcodeOp[] {branch}, TaskMonitor.DUMMY), new int[] {1}),
                "cancelled classification poisoned retry");
            require(program.getModificationNumber() == modification, "raw-flow checks modified the saved program");
        }
        finally { program.release(owner); }
        System.out.println("intra-instruction-boundaries=PASS checks=" + checks);
    }

    private static void reject(PcodeOp[] operations) throws Exception {
        try { require(IntraInstructionFlow.targets(operations, TaskMonitor.DUMMY) == null, "unsafe raw p-code admitted"); }
        catch (RuntimeException invalid) { throw new AssertionError("malformed raw p-code must be refused without crashing", invalid); }
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }
}
