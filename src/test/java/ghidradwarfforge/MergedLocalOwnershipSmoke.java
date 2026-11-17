package ghidradwarfforge;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.RegisterRelativeStorage;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;

/** Real saved identities: reject stale/foreign evidence without granting ownership of other bytes. */
final class MergedLocalOwnershipSmoke {
    private static int checks;

    private MergedLocalOwnershipSmoke() { }

    static void run() throws Exception {
        for (boolean x86 : new boolean[] { true, false }) {
            for (boolean stack : new boolean[] { false, true }) {
                for (int bytes : new int[] { 4, 8 }) {
                    try (var fixture = new Fixture(x86, stack, bytes)) {
                        verify(fixture);
                    }
                }
            }
        }
        System.out.println("merged-local-ownership=PASS checks=" + checks);
    }

    private static void verify(Fixture f) throws Exception {
        var group = f.group();
        var baseline = f.prove(group);
        require(!baseline.isEmpty(), "positive saved identity " + f.label);
        require(!at(baseline, f.firstPc).available(), "definition has not executed");
        var initial = at(baseline, f.firstReady);
        require(f.stack ? initial instanceof RegisterRelativeStorage :
            initial instanceof RegisterStorage r && r.register().dwarfNumber() == (f.x86 ? 10 : 9),
            "initial carrier matches independently encoded instructions");
        int latest = f.x86 ? (f.stack ? 10 : 11) : (f.stack ? 9 : 10);
        require(at(baseline, f.secondReady) instanceof RegisterStorage r && r.register().dwarfNumber() == latest,
            "saved handoff uses the new register");
        require(at(baseline, f.thirdReady) instanceof RegisterStorage r && r.register().dwarfNumber() == latest,
            "updated logical value uses the current register");
        require(!at(baseline, f.lost).available(), "clobbered value cannot reappear from a stale physical backup");

        // These are explicit proof-boundary inputs, not claims that the saved
        // Ghidra extractor itself produces malformed mapping lists.
        f.reject(new GhidraLocalMappings.Group(group.canonical(), group.mappings().subList(0, 1)),
            "one observation cannot establish a merged identity");
        f.reject(new GhidraLocalMappings.Group(group.canonical(), group.mappings().subList(1, 3)),
            "canonical owner must participate");
        var duplicate = new ArrayList<>(group.mappings());
        duplicate.add(group.mappings().get(1));
        f.reject(new GhidraLocalMappings.Group(group.canonical(), duplicate), "duplicate owner observation");
        var missingRegister = new ArrayList<>(group.mappings());
        var second = missingRegister.get(1);
        missingRegister.set(1, new GhidraLocalMappings.Mapping(second.variable(), second.definition(), null));
        f.reject(new GhidraLocalMappings.Group(group.canonical(), missingRegister), "missing assignment register");
        if (f.stack) {
            var wrongCanonical = new ArrayList<>(group.mappings());
            var canonical = wrongCanonical.getFirst();
            wrongCanonical.set(0, new GhidraLocalMappings.Mapping(canonical.variable(), canonical.definition(), f.first));
            f.reject(new GhidraLocalMappings.Group(group.canonical(), wrongCanonical),
                "stack canonical observation must not claim a register assignment");
        }
        String stackName = f.x86 ? "RSP" : "sp";
        var incomplete = new TargetRegisterMap(f.registers.target(), "fixture omits local registers",
            Map.of(stackName, f.x86 ? 7 : 31));
        require(MergedLocalLifetime.prove(f.program, f.function, group, incomplete, TaskMonitor.DUMMY).isEmpty(),
            "an unmapped carrier cannot be assigned a guessed DWARF register");

        f.alter("lost curated provenance", false, g ->
            g.mappings().get(1).variable().getSymbol().setSource(SourceType.ANALYSIS));
        f.alter("same-width signedness is a different identity", false, g ->
            g.mappings().get(1).variable().setDataType(f.bytes == 4 ? UnsignedIntegerDataType.dataType :
                UnsignedLongLongDataType.dataType, SourceType.USER_DEFINED));
        f.alter("definition PC changed after extraction", false, g ->
            ((LocalVariable) g.mappings().get(1).variable()).setFirstUseOffset(f.secondPc + 1));
        f.alter("recorded register assignment no longer writes its carrier", false, g -> f.removeDefinition());
        f.alter("saved assignment lost its storage", false, g ->
            g.mappings().get(1).variable().setDataType(f.type, VariableStorage.UNASSIGNED_STORAGE,
                true, SourceType.USER_DEFINED));
        f.alter("saved assignment has invalid storage", false, g ->
            g.mappings().get(1).variable().setDataType(f.type, VariableStorage.BAD_STORAGE,
                true, SourceType.USER_DEFINED));
        f.alter("saved assignment moved to another register", false, g -> {
            var register = f.program.getRegister(f.x86 ? (f.bytes == 4 ? "R12D" : "R12") :
                (f.bytes == 4 ? "w11" : "x11"));
            g.mappings().get(1).variable().setDataType(f.type, new VariableStorage(f.program, register),
                true, SourceType.USER_DEFINED);
        });
        if (f.stack) {
            f.alter("stack identity lost its explicit initialization point", false, g ->
                ((LocalVariable) g.canonical()).setFirstUseOffset(0));
        }
        f.alter("overlapping nonmember owner", false, g -> f.addOther(true));
        f.alter("disjoint nonmember owner", true, g -> f.addOther(false));
        f.alter("unassigned unrelated local owns no bytes", true, g ->
            f.function.addLocalVariable(new LocalVariableImpl("unavailable", 0, f.type,
                VariableStorage.UNASSIGNED_STORAGE, false, f.program, SourceType.USER_DEFINED), SourceType.USER_DEFINED));
        f.alter("another function cannot supply this identity", true, g -> {
            var otherEntry = f.entry.add(0x100);
            f.program.getMemory().createInitializedBlock("other", otherEntry, 32, (byte) 0, TaskMonitor.DUMMY, false);
            var other = f.program.getFunctionManager().createFunction("other", otherEntry,
                new AddressSet(otherEntry, otherEntry.add(31)), SourceType.USER_DEFINED);
            var variable = other.addLocalVariable(new LocalVariableImpl("foreign", f.secondPc,
                f.type, f.second, f.program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
            require(MergedLocalLifetime.prove(f.program, other, g, f.registers, TaskMonitor.DUMMY).isEmpty(),
                "canonical owner belongs to a different function");
            var mixed = new ArrayList<>(g.mappings());
            mixed.set(1, new GhidraLocalMappings.Mapping(variable, f.entry.add(f.secondPc), f.second));
            f.reject(new GhidraLocalMappings.Group(g.canonical(), mixed), "mapping from a different function");
        });

        // Cancel throughout inspection, mapping validation, ownership traversal
        // and dataflow. All checks operate on the unchanged actual program.
        var completed = new CountingMonitor(Integer.MAX_VALUE);
        MergedLocalLifetime.prove(f.program, f.function, f.group(), f.registers, completed);
        String before = f.snapshot();
        for (int stop : new java.util.LinkedHashSet<>(List.of(1, completed.visits / 3,
                completed.visits * 2 / 3, completed.visits))) {
            var monitor = new CountingMonitor(stop);
            try {
                MergedLocalLifetime.prove(f.program, f.function, f.group(), f.registers, monitor);
                throw new AssertionError("cancelled lifetime returned a proof");
            }
            catch (CancelledException expected) {
                require(monitor.visits == stop, "prompt cancellation at an observed traversal point");
            }
            require(before.equals(f.snapshot()), "cancelled proof preserves program and locals");
        }
        require(f.prove(f.group()).equals(baseline), "all controls preserve the positive lifetime");
        // Keep this intentionally bad saved row until ProgramDB release: deleting
        // bad rows can leave Ghidra's cached variable list holding a deleted row.
        var finalGroup = f.group();
        int tx = f.program.startTransaction("unknown ownership extent");
        try {
            var bad = f.function.addLocalVariable(new LocalVariableImpl("unknown_owner", f.thirdPc + 1,
                f.type, VariableStorage.BAD_STORAGE, true, f.program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
            require(bad.hasAssignedStorage() && !bad.getVariableStorage().isValid(),
                "nonmember fixture must have an assigned but invalid extent");
            f.reject(finalGroup, "a saved owner with unknown extent may overlap the merged value");
        }
        finally { f.program.endTransaction(tx, true); }
    }

    private static final class CountingMonitor extends TaskMonitorAdapter {
        private final int stop;
        private int visits;
        CountingMonitor(int stop) { this.stop = stop; }
        @Override public void checkCancelled() throws CancelledException {
            if (++visits == stop) throw new CancelledException();
        }
    }

    @FunctionalInterface
    private interface Change {
        void apply(GhidraLocalMappings.Group group) throws Exception;
    }

    private static final class Fixture implements AutoCloseable {
        final boolean x86, stack;
        final int bytes, firstPc, firstReady, secondPc, secondReady, thirdPc, thirdReady, lost;
        final String label;
        final Object owner = new Object();
        final ProgramDB program;
        final Function function;
        final Address entry;
        final DataType type;
        final Register first, second;
        final TargetRegisterMap registers;
        final byte[] machine;

        Fixture(boolean x86, boolean stack, int bytes) throws Exception {
            this.x86 = x86; this.stack = stack; this.bytes = bytes;
            label = (x86 ? "x86" : "arm") + "/" + stack + "/" + bytes;
            String nop = x86 ? "90" : "1f2003d5";
            String define = stack ? (x86 ? (bytes == 4 ? "897c2408" : "48897c2408") :
                (bytes == 4 ? "e00b00b9" : "e00700f9")) :
                (x86 ? (bytes == 4 ? "41ba07000000" : "49c7c207000000") : (bytes == 4 ? "e9008052" : "e90080d2"));
            String load = stack ? (x86 ? (bytes == 4 ? "448b542408" : "4c8b542408") :
                (bytes == 4 ? "e90b40b9" : "e90740f9")) :
                (x86 ? (bytes == 4 ? "4589d3" : "4d89d3") : (bytes == 4 ? "ea03092a" : "ea0309aa"));
            String update = x86 ? (stack ? (bytes == 4 ? "4183c205" : "4983c205") :
                (bytes == 4 ? "4183c305" : "4983c305")) : (stack ?
                (bytes == 4 ? "29150011" : "29150091") : (bytes == 4 ? "4a150011" : "4a150091"));
            var code = new StringBuilder(stack ? (x86 ? "4883ec20" : "ff8300d1") : "").append(nop);
            firstPc = code.length() / 2; code.append(define); firstReady = code.length() / 2; code.append(nop);
            secondPc = code.length() / 2; code.append(load); secondReady = code.length() / 2; code.append(nop);
            thirdPc = code.length() / 2; code.append(update); thirdReady = code.length() / 2; code.append(nop);
            code.append(x86 ? (stack ? "4531d2" : "4531db") : (stack ? "e9031f2a" : "ea031f2a"));
            lost = code.length() / 2; code.append(nop);
            if (stack) code.append(x86 ? "4883c420" : "ff830091");
            code.append(x86 ? "c3" : "c0035fd6");
            machine = HexFormat.of().parseHex(code.toString());
            var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
                x86 ? "x86:LE:64:default" : "AARCH64:LE:64:v8A"));
            program = new ProgramDB("merged-ownership", language, language.getDefaultCompilerSpec(), owner);
            entry = language.getDefaultSpace().getAddress(0x1000);
            type = bytes == 4 ? IntegerDataType.dataType : LongLongDataType.dataType;
            first = program.getRegister(x86 ? (bytes == 4 ? "R10D" : "R10") : (bytes == 4 ? "w9" : "x9"));
            second = stack ? first : program.getRegister(x86 ? (bytes == 4 ? "R11D" : "R11") : (bytes == 4 ? "w10" : "x10"));
            registers = TargetRegisterMap.forTarget(x86 ? "x86_64" : "aarch64");
            int tx = program.startTransaction("actual saved assignments");
            try {
                var body = new AddressSet(entry, entry.add(machine.length - 1));
                var block = program.getMemory().createInitializedBlock("body", entry, machine.length, (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(entry, machine);
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "decode " + label);
                function = program.getFunctionManager().createFunction("owner", entry, body, SourceType.USER_DEFINED);
                LocalVariable canonical = (LocalVariable) function.addLocalVariable(stack ?
                    new LocalVariableImpl("value", type, -24, program, SourceType.USER_DEFINED) :
                    new LocalVariableImpl("value", firstPc, type, first, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                if (stack) canonical.setFirstUseOffset(firstPc);
                function.addLocalVariable(new LocalVariableImpl("value$1", secondPc, type, second, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                function.addLocalVariable(new LocalVariableImpl("value$2", thirdPc, type, second, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
            }
            finally { program.endTransaction(tx, true); }
        }

        GhidraLocalMappings.Group group() throws Exception {
            var groups = GhidraLocalMappings.extract(program, function, TaskMonitor.DUMMY, ignored -> { });
            require(groups.size() == 1 && groups.getFirst().mappings().size() == 3, "three actual saved mappings " + label);
            return groups.getFirst();
        }

        List<GhidraVariableStorage.StorageInterval> prove(GhidraLocalMappings.Group group) throws Exception {
            return MergedLocalLifetime.prove(program, function, group, registers, TaskMonitor.DUMMY);
        }

        void reject(GhidraLocalMappings.Group group, String reason) throws Exception {
            String before = snapshot();
            require(prove(group).isEmpty(), reason + " " + label);
            require(before.equals(snapshot()), "rejected proof preserves state: " + reason);
        }

        void alter(String reason, boolean retain, Change change) throws Exception {
            var group = group();
            var expected = prove(group);
            String before = snapshot();
            int tx = program.startTransaction(reason);
            try {
                change.apply(group);
                String altered = snapshot();
                var actual = prove(group);
                require(retain ? actual.equals(expected) : actual.isEmpty(), reason + " " + label);
                require(altered.equals(snapshot()), "proof must not repair analyst state: " + reason);
            }
            finally { program.endTransaction(tx, false); }
            require(before.equals(snapshot()), "rollback restores fixture: " + reason);
            require(prove(group()).equals(expected), "restored fixture retains independent positive proof: " + reason);
        }

        void addOther(boolean overlap) throws Exception {
            if (stack) {
                var local = (LocalVariable) function.addLocalVariable(new LocalVariableImpl("other", type,
                    overlap ? -24 : -24 + bytes, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                local.setFirstUseOffset(thirdPc + 1);
            }
            else {
                var register = overlap ? first : program.getRegister(x86 ? (bytes == 4 ? "R12D" : "R12") :
                    (bytes == 4 ? "w11" : "x11"));
                function.addLocalVariable(new LocalVariableImpl("other", thirdPc + 1, type, register,
                    program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
            }
        }

        void removeDefinition() throws Exception {
            Address start = entry.add(secondPc), end = entry.add(secondReady - 1);
            program.getListing().clearCodeUnits(start, end, false);
            byte[] nops = HexFormat.of().parseHex((x86 ? "90" : "1f2003d5").repeat(x86 ? secondReady - secondPc : 1));
            program.getMemory().setBytes(start, nops);
            require(new DisassembleCommand(start, new AddressSet(start, end), true).applyTo(program, TaskMonitor.DUMMY),
                "decode replacement NOPs");
        }

        String snapshot() throws Exception {
            byte[] bytes = new byte[machine.length];
            program.getMemory().getBytes(entry, bytes);
            return HexFormat.of().formatHex(bytes) + ":" + Arrays.stream(function.getAllVariables()).map(v ->
                v.getSymbol().getID() + "/" + v.getName() + "/" + v.getSource() + "/" + v.getFirstUseOffset() + "/" +
                v.getDataType().getPathName() + "/" + v.getVariableStorage()).sorted().toList();
        }

        @Override public void close() {
            // Disassembly registers Ghidra's analysis listener. Deliver pending
            // database notifications while their program is still open.
            try { program.flushEvents(); }
            finally { program.release(owner); }
        }
    }

    private static ghidradwarfforge.locations.VariableStorageModel.Storage at(
            List<GhidraVariableStorage.StorageInterval> intervals, int offset) {
        return intervals.stream().filter(i -> i.start() <= 0x1000L + offset && i.end() > 0x1000L + offset)
            .findFirst().orElseThrow().storage();
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }
}
