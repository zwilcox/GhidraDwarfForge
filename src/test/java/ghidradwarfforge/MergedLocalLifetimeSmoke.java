package ghidradwarfforge;

import java.io.File;
import java.util.ArrayList;
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
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** Exact copies and updates of one saved identity; stale backups must disappear. */
public final class MergedLocalLifetimeSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (boolean x86 : new boolean[] { true, false }) {
            for (int bytes : new int[] { 4, 8 }) {
                for (String shape : List.of("straight", "old-killed", "branch", "loop")) check(x86, bytes, shape);
            }
        }
        System.out.println("merged-local-lifetime-smoke=PASS checks=" + checks);
    }

    private static void check(boolean x86, int bytes, String shape) throws Exception {
        String target = x86 ? "x86_64" : "aarch64";
        String nop = x86 ? "90" : "1f2003d5";
        String definition = x86 ? (bytes == 4 ? "41ba07000000" : "49c7c207000000") :
            (bytes == 4 ? "e9008052" : "e90080d2");
        String copy = x86 ? (bytes == 4 ? "4589d3" : "4d89d3") : (bytes == 4 ? "ea03092a" : "ea0309aa");
        String update = x86 ? (bytes == 4 ? "4183c305" : "4983c305") : (bytes == 4 ? "4a150011" : "4a150091");
        String reset = x86 ? (bytes == 4 ? "41bb0c000000" : "49c7c30c000000") : (bytes == 4 ? "8a018052" : "8a0180d2");
        String kill = x86 ? "4531db" : "ea031f2a";
        var code = new StringBuilder(nop);
        int firstPc = code.length() / 2;
        code.append(definition).append(nop);
        int firstReady = firstPc + definition.length() / 2;
        if (shape.equals("branch")) code.append(x86 ? "85ff7406" : "1f00007180000054");
        int copyPc = code.length() / 2;
        code.append(copy).append(nop);
        int copyReady = copyPc + copy.length() / 2;
        if (shape.equals("old-killed")) code.append(x86 ? "4531d2" : "e9031f2a");
        int join = -1;
        int loop = -1;
        if (shape.equals("branch")) {
            code.append(x86 ? "eb01" : "02000014").append(nop);
            join = code.length() / 2;
            code.append(nop);
        }
        if (shape.equals("loop")) {
            code.append(x86 ? "bf02000000" : "40008052");
            loop = code.length() / 2;
            code.append(nop);
        }
        int updatePc = code.length() / 2;
        String change = shape.equals("branch") ? reset : update;
        code.append(change).append(nop);
        int updateReady = updatePc + change.length() / 2;
        if (shape.equals("loop")) {
            if (x86) {
                code.append("ffcf");
                int displacement = loop - (code.length() / 2 + 2);
                code.append("75").append(HexFormat.of().toHexDigits((byte) displacement));
            }
            else code.append("0004007181ffff54");
        }
        int killPc = code.length() / 2;
        code.append(kill);
        int lost = code.length() / 2;
        code.append(nop).append(x86 ? "c3" : "c0035fd6");
        byte[] machine = HexFormat.of().parseHex(code.toString());
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
            x86 ? "x86:LE:64:default" : "AARCH64:LE:64:v8A"));
        Object owner = new Object();
        var program = new ProgramDB("merged-lifetime", language, language.getDefaultCompilerSpec(), owner);
        try {
            int tx = program.startTransaction("physical definitions");
            try {
                var entry = language.getDefaultSpace().getAddress(0x1000);
                var body = new AddressSet(entry, entry.add(machine.length - 1));
                var block = program.getMemory().createInitializedBlock("code", entry, machine.length, (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(entry, machine);
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "decode");
                var function = program.getFunctionManager().createFunction("merged", entry, body, SourceType.USER_DEFINED);
                var type = bytes == 4 ? IntegerDataType.dataType : LongLongDataType.dataType;
                var first = program.getRegister(x86 ? (bytes == 4 ? "R10D" : "R10") : (bytes == 4 ? "w9" : "x9"));
                var second = program.getRegister(x86 ? (bytes == 4 ? "R11D" : "R11") : (bytes == 4 ? "w10" : "x10"));
                function.addLocalVariable(new LocalVariableImpl("value", firstPc, type, first, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                function.addLocalVariable(new LocalVariableImpl("value$1", copyPc, type, second, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                var changed = (LocalVariable) function.addLocalVariable(new LocalVariableImpl("value$2", updatePc, type, second, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                var diagnostics = new ArrayList<String>();
                var group = GhidraLocalMappings.extract(program, function, TaskMonitor.DUMMY, diagnostics::add).getFirst();
                var registers = TargetRegisterMap.forTarget(target);
                var intervals = MergedLocalLifetime.prove(program, function, group, registers, TaskMonitor.DUMMY);
                String context = target + "/" + bytes + "/" + shape + " " + intervals;
                require(!intervals.isEmpty(), "missing mapping proof " + context);
                int firstNumber = x86 ? 10 : 9;
                int secondNumber = firstNumber + 1;
                require(location(intervals, firstPc) == -1, "definition must finish " + context);
                require(location(intervals, firstReady) == firstNumber, "initial value " + context);
                require(location(intervals, copyPc) == firstNumber, "copy pre-state " + context);
                require(location(intervals, copyReady) == secondNumber, "completed copy handoff " + context);
                require(location(intervals, updatePc) == (shape.equals("branch") ? -1 : secondNumber), "assignment pre-state " + context);
                require(location(intervals, updateReady) == secondNumber, "new logical value after assignment " + context);
                require(location(intervals, killPc) == secondNumber, "pre-clobber value " + context);
                require(location(intervals, lost) == -1, "old first register must not masquerade as the updated value " + context);
                if (join >= 0) require(location(intervals, join) == -1, "join lacks common physical carrier " + context);
                if (loop >= 0) require(location(intervals, loop) == secondNumber, "latest value at each loop visit " + context);
                var model = GhidraTypeGraph.extract(program, List.of(new FunctionSymbol("merged", 0x1000, machine.length)),
                    target, 0, TaskMonitor.DUMMY, diagnostics::add);
                require(model.functions().getFirst().locals().size() == 1 &&
                    model.functions().getFirst().locals().getFirst().name().equals("value"), "one canonical local declaration");
                require(model.variableStorage().variables().stream().filter(variable -> variable.name().equals("value")).count() == 1,
                    "one canonical location model");
                changed.setFirstUseOffset(updatePc + 1);
                var offcut = GhidraLocalMappings.extract(program, function, TaskMonitor.DUMMY, diagnostics::add).getFirst();
                require(MergedLocalLifetime.prove(program, function, offcut, registers, TaskMonitor.DUMMY).isEmpty(), "offcut assignment rejected");
                changed.setFirstUseOffset(updatePc);
                var other = function.addLocalVariable(new LocalVariableImpl("unrelated", firstPc + 1,
                    type, first, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                require(MergedLocalLifetime.prove(program, function, group, registers, TaskMonitor.DUMMY).isEmpty(), "nonmember overlapping identity rejected");
                function.removeVariable(other);
                require(MergedLocalLifetime.prove(program, function, group, registers, TaskMonitor.DUMMY).equals(intervals), "controls restore proof");
            }
            finally { program.endTransaction(tx, true); }
        }
        finally { program.release(owner); }
    }

    private static int location(List<GhidraVariableStorage.StorageInterval> intervals, long offset) {
        for (var interval : intervals) {
            if (interval.start() <= 0x1000 + offset && 0x1000 + offset < interval.end()) {
                return interval.storage() instanceof RegisterStorage register ? register.register().dwarfNumber() : -1;
            }
        }
        return -1;
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
