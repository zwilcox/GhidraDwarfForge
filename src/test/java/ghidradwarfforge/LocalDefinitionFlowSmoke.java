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
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.Storage;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;

/** Real decoded diamonds, loops and split bodies, plus isolated raw-control contracts. */
public final class LocalDefinitionFlowSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        UnreachableLocalDefinitionSmoke.check();
        RegisterControlBoundarySmoke.run();
        for (boolean x86 : new boolean[] { true, false }) {
            for (int bytes : new int[] { 4, 8 }) {
                for (String shape : List.of("diamond", "loop", "split", "bypass")) {
                    check(x86, bytes, shape, false);
                    if (!shape.equals("bypass")) check(x86, bytes, shape, true);
                }
            }
        }
        System.out.println("local-definition-flow-smoke=PASS checks=" + checks);
    }

    private static void check(boolean x86, int bytes, String shape, boolean kill) throws Exception {
        String target = x86 ? "x86_64" : "aarch64";
        String nop = x86 ? "90" : "1f2003d5";
        String define = x86 ? (bytes == 4 ? "41ba07000000" : "49c7c207000000") :
            (bytes == 4 ? "e9008052" : "e90080d2");
        String clobber = x86 ? "4531d2" : "e9031f2a";
        String result = x86 ? (bytes == 4 ? "4489d0" : "4c89d0") :
            (bytes == 4 ? "e003092a" : "e00309aa");
        String ret = x86 ? "c3" : "c0035fd6";
        String before = nop;
        if (shape.equals("bypass")) {
            before += x86 ? "85ff74" + HexFormat.of().toHexDigits((byte) ((define.length() + nop.length()) / 2)) :
                "1f00007160000054";
        }
        int firstUse = before.length() / 2;
        String prefix = before + define;
        int ready = prefix.length() / 2;
        String middle = switch (shape) {
            case "diamond" -> x86 ? "85ff7404" + (kill ? clobber : "909090") + nop :
                "1f00007160000054" + (kill ? clobber : nop) + nop;
            case "loop" -> nop + (x86 ? (kill ? clobber + "ffcf75f9" : "ffcf75fc") :
                (kill ? clobber + "00040071c1ffff54" : "00040071e1ffff54"));
            case "split" -> x86 ? "eb03cccccc" : "02000014000020d4";
            case "bypass" -> nop;
            default -> throw new AssertionError(shape);
        };
        byte[] code = HexFormat.of().parseHex(prefix + middle + result + ret);
        int join = ready + middle.length() / 2;
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
            x86 ? "x86:LE:64:default" : "AARCH64:LE:64:v8A"));
        Object owner = new Object();
        var program = new ProgramDB("local-definition-flow", language, language.getDefaultCompilerSpec(), owner);
        try {
            int tx = program.startTransaction("decoded control flow");
            try {
                var entry = language.getDefaultSpace().getAddress(0x1000);
                var body = new AddressSet(entry, entry.add(code.length - 1));
                var block = program.getMemory().createInitializedBlock("code", entry, code.length,
                    (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(entry, code);
                if (shape.equals("split") && !kill) {
                    body.delete(entry.add(ready + (x86 ? 2 : 4)), entry.add(join - 1));
                }
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "decode");
                var function = program.getFunctionManager().createFunction("local_flow", entry, body, SourceType.USER_DEFINED);
                var type = bytes == 4 ? IntegerDataType.dataType : LongLongDataType.dataType;
                var register = program.getRegister(x86 ? (bytes == 4 ? "R10D" : "R10") :
                    (bytes == 4 ? "w9" : "x9"));
                var local = (LocalVariable) function.addLocalVariable(new LocalVariableImpl("held", firstUse,
                    type, register, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                var map = TargetRegisterMap.forTarget(target);
                var rejected = GhidraVariableStorage.stableLocal(program, function, local, map, TaskMonitor.DUMMY);
                var intervals = RegisterDefinitionFlow.prove(program, function, local, map, rejected, TaskMonitor.DUMMY);
                String context = target + "/" + bytes + "/" + shape + "/kill=" + kill + " " + intervals;
                if (shape.equals("split") && kill) {
                    require(intervals.isEmpty(), "undecoded included gap accepted " + context);
                    return;
                }
                require(!intervals.isEmpty(), "missing proof " + context);
                if (shape.equals("diamond") && !kill) {
                    ownership(program, function, local, map, rejected, intervals);
                }
                require(!available(intervals, 0x1000), "stale entry value " + context);
                require(!available(intervals, 0x1000 + firstUse), "unfinished definition " + context);
                require(available(intervals, 0x1000 + join) == (!kill && !shape.equals("bypass")),
                    "join agreement " + context);
                if (shape.equals("bypass")) {
                    require(available(intervals, 0x1000 + ready), "defined path before join " + context);
                }
                if (shape.equals("diamond")) {
                    require(available(intervals, 0x1000 + ready), "prefix before branch " + context);
                    int killAddress = ready + (x86 ? 4 : 8);
                    require(available(intervals, 0x1000 + killAddress), "pre-execution write state " + context);
                    require(available(intervals, 0x1000 + killAddress + (x86 ? 3 : 4)) == !kill,
                        "completed write boundary " + context);
                }
                if (shape.equals("loop")) {
                    require(available(intervals, 0x1000 + ready), "established value before loop " + context);
                    require(available(intervals, 0x1000 + ready + nop.length() / 2) == !kill,
                        "loop backedge agreement " + context);
                }
                for (var interval : intervals) {
                    require(body.contains(entry.getAddressSpace().getAddress(interval.start()),
                        entry.getAddressSpace().getAddress(interval.end() - 1)), "interval crossed body hole " + context);
                }
                var cancelled = new TaskMonitorAdapter(true);
                cancelled.cancel();
                try {
                    RegisterDefinitionFlow.prove(program, function, local, map, rejected, cancelled);
                    throw new AssertionError("cancellation ignored");
                }
                catch (CancelledException expected) {
                    checks++;
                }
                local.setFirstUseOffset(firstUse + 1);
                require(RegisterDefinitionFlow.prove(program, function, local, map, rejected,
                    TaskMonitor.DUMMY).isEmpty(), "offcut definition accepted " + context);
                local.setFirstUseOffset(firstUse);
                var references = program.getReferenceManager();
                var ordinaryEntry = references.addMemoryReference(entry.subtract(16), entry,
                    RefType.UNCONDITIONAL_JUMP, SourceType.USER_DEFINED, 0);
                require(RegisterDefinitionFlow.prove(program, function, local, map, rejected,
                    TaskMonitor.DUMMY).equals(intervals), "ordinary entry rejected " + context);
                references.delete(ordinaryEntry);
                var secondaryEntry = references.addMemoryReference(entry.subtract(16), entry.add(join),
                    RefType.UNCONDITIONAL_JUMP, SourceType.USER_DEFINED, 0);
                require(RegisterDefinitionFlow.prove(program, function, local, map, rejected,
                    TaskMonitor.DUMMY).isEmpty(), "unproved alternate entry accepted " + context);
                references.delete(secondaryEntry);
                var instruction = program.getListing().getInstructionAt(entry.add(firstUse));
                instruction.setFlowOverride(FlowOverride.CALL);
                require(RegisterDefinitionFlow.prove(program, function, local, map, rejected,
                    TaskMonitor.DUMMY).isEmpty(), "flow override accepted " + context);
                instruction.setFlowOverride(FlowOverride.NONE);
                require(RegisterDefinitionFlow.prove(program, function, local, map, rejected,
                    TaskMonitor.DUMMY).equals(intervals), "controls did not restore proof " + context);
                if (shape.equals("diamond") && !kill) {
                    // Keep the intentionally bad row until this owned ProgramDB
                    // is released. Deleting it in this Ghidra version leaves a
                    // deleted variable in the function's cached variable list.
                    var bad = function.addLocalVariable(new LocalVariableImpl("bad_storage", firstUse + 1,
                        IntegerDataType.dataType, VariableStorage.BAD_STORAGE, true, program, SourceType.USER_DEFINED),
                        SourceType.USER_DEFINED);
                    require(bad.hasAssignedStorage() && !bad.getVariableStorage().isValid(),
                        "fixture must retain a saved invalid storage row");
                    require(RegisterDefinitionFlow.prove(program, function, local, map, rejected,
                        TaskMonitor.DUMMY).isEmpty(), "invalid saved ownership acquired a register lifetime");
                }
            }
            finally {
                program.endTransaction(tx, true);
            }
        }
        finally {
            program.release(owner);
        }
    }

    private static void ownership(ProgramDB program, Function function, LocalVariable local,
            TargetRegisterMap map, Storage rejected, List<GhidraVariableStorage.StorageInterval> expected)
            throws Exception {
        RegisterLocalMetadataSmoke.check(program, function, local, expected,
            (owner, value) -> RegisterDefinitionFlow.prove(program, owner, value, map, rejected, TaskMonitor.DUMMY));
        var register = local.getRegister();
        var base = register.getBaseRegister();
        int firstUse = local.getFirstUseOffset();
        var originalBody = new AddressSet(function.getBody());
        byte[] before = new byte[Math.toIntExact(originalBody.getNumAddresses())];
        program.getMemory().getBytes(originalBody.getMinAddress(), before);
        for (OmissionReason reason : OmissionReason.values()) {
            if (reason == OmissionReason.UNKNOWN_LIFETIME) continue;
            require(RegisterDefinitionFlow.prove(program, function, local, map,
                new UnavailableStorage(reason, "independent rejection reason"), TaskMonitor.DUMMY).isEmpty(),
                "definition proof overrode an unrelated rejection: " + reason);
        }
        Storage established = expected.stream().filter(row -> row.storage().available()).findFirst().orElseThrow().storage();
        require(RegisterDefinitionFlow.prove(program, function, local, map, established, TaskMonitor.DUMMY).isEmpty(),
            "definition fallback replaced an established location");
        var unsaved = new LocalVariableImpl("unsaved", firstUse, local.getDataType(), register,
            program, SourceType.USER_DEFINED);
        require(RegisterDefinitionFlow.prove(program, function, unsaved, map, rejected, TaskMonitor.DUMMY).isEmpty(),
            "unsaved local acquired a lifetime from another saved variable");
        for (SourceType provenance : List.of(SourceType.ANALYSIS, SourceType.IMPORTED)) {
            local.setName("noncurated_" + provenance.name(), provenance);
            require(local.getSource() == provenance, "fixture did not change saved provenance: " + local.getSource());
            require(RegisterDefinitionFlow.prove(program, function, local, map, rejected, TaskMonitor.DUMMY).isEmpty(),
                "noncurated definition was promoted to analyst evidence");
        }
        local.setName("held", SourceType.USER_DEFINED);
        local.setFirstUseOffset(0);
        require(RegisterDefinitionFlow.prove(program, function, local, map, rejected, TaskMonitor.DUMMY).isEmpty(),
            "entry local acquired an unproved initial value");
        local.setFirstUseOffset(firstUse);
        require(RegisterDefinitionFlow.prove(program, function, local, TargetRegisterMap.forTarget("mips"),
            rejected, TaskMonitor.DUMMY).isEmpty(), "unmapped register acquired a location");

        // Saved variables may reuse storage at different first-use offsets. A
        // second identity anywhere in the physical base register is ambiguous,
        // including an unnamed high byte outside the selected 32-bit alias.
        for (int offset : new int[] {-1, 0, 1, base.getMinimumByteSize() - 1, base.getMinimumByteSize()}) {
            var node = new Varnode(base.getAddress().add(offset), 1);
            var storage = new VariableStorage(program, node);
            var other = function.addLocalVariable(new LocalVariableImpl("other", firstUse + 1,
                ByteDataType.dataType, storage, false, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
            try {
                require(other != local && other.getVariableStorage().equals(storage),
                    "fixture must preserve distinct identity and exact register byte");
                boolean overlaps = offset >= 0 && offset < base.getMinimumByteSize();
                var actual = RegisterDefinitionFlow.prove(program, function, local, map, rejected, TaskMonitor.DUMMY);
                require(overlaps ? actual.isEmpty() : actual.equals(expected),
                    "physical register ownership disagrees at byte " + offset);
            }
            finally { function.removeVariable(other); }
        }
        var stack = function.addLocalVariable(new LocalVariableImpl("separate_stack", IntegerDataType.dataType,
            -16, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
        try {
            require(RegisterDefinitionFlow.prove(program, function, local, map, rejected, TaskMonitor.DUMMY).equals(expected),
                "unrelated stack storage invalidated the register proof");
        }
        finally { function.removeVariable(stack); }
        var unknown = function.addLocalVariable(new LocalVariableImpl("unknown", firstUse + 1,
            IntegerDataType.dataType, VariableStorage.UNASSIGNED_STORAGE, true, program, SourceType.USER_DEFINED),
            SourceType.USER_DEFINED);
        try {
            require(unknown.getVariableStorage().isUnassignedStorage(), "saved fixture changed unknown storage");
            var actual = RegisterDefinitionFlow.prove(program, function, local, map, rejected, TaskMonitor.DUMMY);
            require(actual.equals(expected), "unassigned storage invalidated the register proof");
        }
        finally { function.removeVariable(unknown); }
        long modifications = program.getModificationNumber();
        require(RegisterDefinitionFlow.prove(program, function, local, map, rejected, TaskMonitor.DUMMY).equals(expected),
            "ownership controls did not restore the original proof: " + java.util.Arrays.stream(function.getAllVariables())
                .map(value -> value.getName() + ":" + value.getVariableStorage() + ":same=" + (value == local)).toList());
        require(program.getModificationNumber() == modifications && function.getBody().equals(originalBody),
            "definition proof changed the saved program");
        byte[] after = new byte[before.length];
        program.getMemory().getBytes(originalBody.getMinAddress(), after);
        require(java.util.Arrays.equals(before, after), "ownership proof changed machine instructions");
    }

    private static boolean available(List<GhidraVariableStorage.StorageInterval> intervals, long address) {
        return intervals.stream().anyMatch(interval -> interval.start() <= address && address < interval.end() &&
            interval.storage().available());
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
