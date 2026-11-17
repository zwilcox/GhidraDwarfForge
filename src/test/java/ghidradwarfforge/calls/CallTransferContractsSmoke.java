package ghidradwarfforge.calls;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.elf.ElfCodeBytes;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.elf.ElfRelocationEffects;

/** Raw transfer consistency around real decode/ELF bytes; no call-site emission claim. */
final class CallTransferContractsSmoke {
    private CallTransferContractsSmoke() { }

    static void check(Program program, Instruction instruction, ElfImage image, long delta) throws Exception {
        byte[] bytes = instruction.getParsedBytes();
        long modification = program.getModificationNumber();
        PcodeOp[] original = instruction.getPcode(false);
        var transfers = Arrays.stream(original).filter(op -> switch (op.getOpcode()) {
            case PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.BRANCH, PcodeOp.CBRANCH, PcodeOp.BRANCHIND -> true;
            default -> false;
        }).toList();
        require(transfers.size() == 1, "fixture must have one real transfer");
        PcodeOp transfer = transfers.getFirst();
        Varnode target = transfer.getInput(0);
        var register = program.getRegister(program.getLanguage().getProcessor().toString().equals("AARCH64") ? "x19" : "R12");
        var cell = new Varnode(register.getAddress(), register.getMinimumByteSize());
        var copy = new PcodeOp(instruction.getAddress(), 0, PcodeOp.COPY, new Varnode[] { cell }, cell);
        var effects = ElfRelocationEffects.inspect(image, () -> false);
        try (var elf = ElfCodeBytes.open(image, () -> false)) {
            var baseline = GhidraCallSiteEvidence.incomingTransfer(program, instruction, elf, effects,
                delta, TaskMonitor.DUMMY, () -> false);
            require(baseline.kind() != GhidraCallSiteEvidence.Kind.UNAVAILABLE, "valid incoming transfer refused");
            var cases = new ArrayList<Case>();
            cases.add(new Case("null p-code", null, "missing or unbounded raw p-code"));
            cases.add(new Case("empty p-code", new PcodeOp[0], "no unique raw machine transfer"));
            cases.add(new Case("duplicate transfer", new PcodeOp[] { transfer, transfer }, "no unique raw machine transfer"));
            cases.add(new Case("output on transfer", new PcodeOp[] {
                new PcodeOp(instruction.getAddress(), 0, transfer.getOpcode(), transfer.getInputs(), cell) }, "malformed raw transfer"));
            cases.add(new Case("missing target", new PcodeOp[] {
                new PcodeOp(instruction.getAddress(), 0, transfer.getOpcode(), new Varnode[0], null) }, "malformed raw transfer"));
            for (int opcode : new int[] { PcodeOp.CALLOTHER, PcodeOp.UNIMPLEMENTED }) {
                cases.add(new Case("opaque opcode " + opcode, new PcodeOp[] {
                    new PcodeOp(instruction.getAddress(), 0, opcode, new Varnode[0], null), transfer }, "opaque instruction effects"));
            }
            if (instruction.getFlowType().isCall()) {
                cases.add(new Case("extra call argument", new PcodeOp[] {
                    new PcodeOp(instruction.getAddress(), 0, transfer.getOpcode(), new Varnode[] { target, cell }, null) },
                    "call lacks an ordinary decoded return address"));
                cases.add(new Case("effect after call", new PcodeOp[] { transfer, copy },
                    "call lacks an ordinary decoded return address"));
                var local = new Varnode(program.getAddressFactory().getConstantSpace().getAddress(1), 4);
                for (int opcode : new int[] { PcodeOp.BRANCH, PcodeOp.CBRANCH }) {
                    var inputs = opcode == PcodeOp.BRANCH ? new Varnode[] { local } : new Varnode[] { local, cell };
                    cases.add(new Case("internal control before call " + opcode, new PcodeOp[] {
                        new PcodeOp(instruction.getAddress(), 0, opcode, inputs, null), transfer },
                        "call has unproved intra-instruction control flow"));
                }
                int wrong = transfer.getOpcode() == PcodeOp.CALL ? PcodeOp.RETURN : PcodeOp.CALL;
                cases.add(new Case("call kind contradiction", new PcodeOp[] {
                    new PcodeOp(instruction.getAddress(), 0, wrong, transfer.getInputs(), null) },
                    "raw call kind differs from listing"));
            }
            else if (transfer.getOpcode() == PcodeOp.BRANCH || transfer.getOpcode() == PcodeOp.CBRANCH) {
                int wrong = transfer.getOpcode() == PcodeOp.BRANCH ? PcodeOp.CBRANCH : PcodeOp.BRANCH;
                var inputs = wrong == PcodeOp.CBRANCH ? new Varnode[] { target, cell } : new Varnode[] { target };
                cases.add(new Case("branch condition contradiction", new PcodeOp[] {
                    new PcodeOp(instruction.getAddress(), 0, wrong, inputs, null) }, "branch condition differs from listing"));
            }
            if (transfer.getOpcode() == PcodeOp.CALL || transfer.getOpcode() == PcodeOp.BRANCH ||
                    transfer.getOpcode() == PcodeOp.CBRANCH) {
                Varnode[] wrongInputs = transfer.getInputs().clone();
                wrongInputs[0] = new Varnode(target.getAddress().add(1), target.getSize());
                cases.add(new Case("target contradiction", new PcodeOp[] {
                    new PcodeOp(instruction.getAddress(), 0, transfer.getOpcode(), wrongInputs, null) },
                    "raw and decoded targets disagree"));
            }
            if (transfer.getOpcode() == PcodeOp.CALL) {
                for (int count : new int[] { 4096, 4097 }) {
                    var padded = new ArrayList<PcodeOp>(List.of(original));
                    while (padded.size() < count) padded.add(padded.size() - 1, copy);
                    cases.add(new Case("operation budget " + count, padded.toArray(PcodeOp[]::new),
                        count == 4096 ? null : "missing or unbounded raw p-code"));
                }
            }
            cases.add(new Case("transparent original", original, null));
            for (Case test : cases) {
                Instruction altered = rawView(instruction, test.operations());
                var actual = GhidraCallSiteEvidence.incomingTransfer(program, altered, elf, effects,
                    delta, TaskMonitor.DUMMY, () -> false);
                if (test.reason() == null) {
                    require(actual.equals(baseline), test.name() + " changed valid transfer");
                }
                else {
                    require(actual.kind() == GhidraCallSiteEvidence.Kind.UNAVAILABLE && actual.reason().equals(test.reason()),
                        test.name() + " wrong refusal: " + actual);
                    require(actual.target() == null && actual.returnPc() == null && actual.callee() == null,
                        test.name() + " retained invented call identity");
                }
                require(program.getModificationNumber() == modification && Arrays.equals(bytes, instruction.getParsedBytes()),
                    test.name() + " changed original program");
                require(GhidraCallSiteEvidence.incomingTransfer(program, instruction, elf, effects,
                    delta, TaskMonitor.DUMMY, () -> false).equals(baseline), test.name() + " poisoned original retry");
            }
            System.out.println("call-transfer-contracts=PASS kind=" + baseline.kind() + " cases=" + cases.size());
        }
    }

    private record Case(String name, PcodeOp[] operations, String reason) { }

    private static Instruction rawView(Instruction original, PcodeOp[] operations) {
        return (Instruction) Proxy.newProxyInstance(Instruction.class.getClassLoader(), new Class<?>[] { Instruction.class },
            (proxy, method, args) -> {
                if (method.getName().equals("getPcode")) return operations;
                try { return method.invoke(original, args); }
                catch (InvocationTargetException failure) { throw failure.getCause(); }
            });
    }

    private static void require(boolean condition, String reason) {
        if (!condition) throw new AssertionError(reason);
    }
}
