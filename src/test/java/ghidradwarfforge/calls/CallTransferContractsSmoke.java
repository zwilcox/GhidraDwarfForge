package ghidradwarfforge.calls;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
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
            metadata(program, instruction, elf, effects, delta, baseline);
        }
    }

    private static void metadata(Program program, Instruction instruction, ElfCodeBytes elf,
            ElfRelocationEffects effects, long delta, GhidraCallSiteEvidence.Transfer baseline) throws Exception {
        byte[] original = instruction.getParsedBytes();
        byte[] stale = original.clone();
        stale[0] ^= 1;
        var cases = new ArrayList<Metadata>();
        cases.add(new Metadata("transparent", Map.of(), null));
        cases.add(new Metadata("zero length", Map.of("getLength", 0), "partial or overridden instruction length"));
        cases.add(new Metadata("wrong parsed length", Map.of("getParsedLength", instruction.getLength() + 1),
            "partial or overridden instruction length"));
        cases.add(new Metadata("overridden length", Map.of("isLengthOverridden", true), "partial or overridden instruction length"));
        cases.add(new Metadata("delay owner", Map.of("getDelaySlotDepth", 1), "delayed transfer requires a separate return-address proof"));
        cases.add(new Metadata("delay slot", Map.of("isInDelaySlot", true), "delayed transfer requires a separate return-address proof"));
        cases.add(new Metadata("contradictory flow", Map.of("getFlowType", RefType.TERMINATOR), "listing control flow differs from raw decode"));
        var wrongNext = instruction.getMaxAddress().add(2);
        cases.add(new Metadata("contradictory fallthrough", Map.of("getFallThrough", wrongNext), "fallthrough differs from raw decode"));
        cases.add(new Metadata("short parsed bytes", Map.of("getParsedBytes", Arrays.copyOf(original, original.length - 1)),
            "instruction bytes changed after decoding"));
        cases.add(new Metadata("stale parsed bytes", Map.of("getParsedBytes", stale), "instruction bytes changed after decoding"));
        for (AddressSpace space : List.of(program.getAddressFactory().getRegisterSpace(),
                new GenericAddressSpace("fixture_foreign_ram", 64, AddressSpace.TYPE_RAM, 70))) {
            var address = space.getAddress(0x1000);
            cases.add(new Metadata("foreign address " + space.getName(),
                Map.of("getAddress", address, "getMaxAddress", address.add(original.length - 1)), "unsupported instruction address space"));
        }
        if (instruction.getFlowType().isCall()) {
            cases.add(new Metadata("nonadjacent return address", Map.of("getFallThrough", wrongNext,
                "getDefaultFallThrough", wrongNext), "call lacks an ordinary decoded return address"));
        }
        long modification = program.getModificationNumber();
        int count = 0;
        for (Metadata test : cases) {
            var altered = view(Instruction.class, instruction, test.overrides());
            var actual = GhidraCallSiteEvidence.incomingTransfer(program, altered, elf, effects,
                delta, TaskMonitor.DUMMY, () -> false);
            if (test.reason() == null) require(actual.equals(baseline), "transparent metadata changed transfer");
            else unavailable(actual, test.reason(), test.name());
            unchanged(program, instruction, elf, effects, delta, baseline, modification, original, test.name());
            count++;
        }
        for (boolean unreadable : List.of(false, true)) {
            var memory = (Memory) Proxy.newProxyInstance(Memory.class.getClassLoader(), new Class<?>[] { Memory.class },
                (proxy, method, args) -> {
                    if (method.getName().equals("getBytes")) {
                        if (unreadable) throw new MemoryAccessException("controlled instruction read failure");
                        byte[] live = (byte[]) args[1];
                        program.getMemory().getBytes(instruction.getAddress(), live);
                        return live.length - 1;
                    }
                    try { return method.invoke(program.getMemory(), args); }
                    catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
            var observed = view(Program.class, program, Map.of("getMemory", memory));
            var actual = GhidraCallSiteEvidence.incomingTransfer(observed, instruction, elf, effects,
                delta, TaskMonitor.DUMMY, () -> false);
            String reason = unreadable ? "controlled instruction read failure" : "instruction bytes changed after decoding";
            unavailable(actual, reason, "memory observation");
            unchanged(program, instruction, elf, effects, delta, baseline, modification, original, reason);
            count++;
        }
        System.out.println("call-transfer-metadata=PASS kind=" + baseline.kind() + " cases=" + count);
    }

    private static void unavailable(GhidraCallSiteEvidence.Transfer actual, String reason, String label) {
        // Several independent guards can reject inconsistent observations.
        // Require safe omission, without depending on which guard runs first.
        require(actual.kind() == GhidraCallSiteEvidence.Kind.UNAVAILABLE && !actual.reason().isBlank(),
            label + " expected omission for " + reason + ": " + actual);
        require(actual.target() == null && actual.returnPc() == null && actual.callee() == null,
            label + " retained unproved identity");
    }

    private static void unchanged(Program program, Instruction instruction, ElfCodeBytes elf,
            ElfRelocationEffects effects, long delta, GhidraCallSiteEvidence.Transfer baseline,
            long modification, byte[] original, String label) throws Exception {
        byte[] live = new byte[original.length];
        require(program.getModificationNumber() == modification && Arrays.equals(original, instruction.getParsedBytes()) &&
            program.getMemory().getBytes(instruction.getAddress(), live) == live.length && Arrays.equals(original, live),
            label + " modified original program or code");
        require(GhidraCallSiteEvidence.incomingTransfer(program, instruction, elf, effects,
            delta, TaskMonitor.DUMMY, () -> false).equals(baseline), label + " poisoned ordinary retry");
    }

    private record Metadata(String name, Map<String, Object> overrides, String reason) { }

    private static <T> T view(Class<T> type, T original, Map<String, Object> overrides) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type }, (proxy, method, args) -> {
            if (overrides.containsKey(method.getName())) return overrides.get(method.getName());
            try { return method.invoke(original, args); }
            catch (InvocationTargetException failure) { throw failure.getCause(); }
        }));
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
