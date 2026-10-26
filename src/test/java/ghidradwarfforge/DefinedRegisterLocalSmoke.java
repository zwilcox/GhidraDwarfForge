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
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.locations.TargetRegisterMap;

/** Actual machine definitions must complete before a curated local acquires a location. */
public final class DefinedRegisterLocalSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (String target : List.of("x86_64", "aarch64")) {
            for (int width : new int[] { 4, 8 }) check(target, width);
        }
        System.out.println("defined-register-local-smoke=PASS checks=" + checks);
    }

    private static void check(String target, int width) throws Exception {
        boolean x86 = target.equals("x86_64");
        var language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID(x86 ? "x86:LE:64:default" : "AARCH64:LE:64:v8A"));
        String hex = x86 ? (width == 4 ? "90909090448d57074489d04531d290c3" : "909090904c8d57074c89d04531d290c3") :
            (width == 4 ? "1f2003d5091c0011e003092ae9031faa1f2003d5c0035fd6" :
                "1f2003d5091c0091e00309aae9031faa1f2003d5c0035fd6");
        byte[] bytes = HexFormat.of().parseHex(hex);
        Object owner = new Object();
        var program = new ProgramDB("definition", language, language.getDefaultCompilerSpec(), owner);
        try {
            int transaction = program.startTransaction("definition boundary");
            try {
                var entry = language.getDefaultSpace().getAddress(0x1000);
                var body = new AddressSet(entry, entry.add(bytes.length - 1));
                var block = program.getMemory().createInitializedBlock("code", entry, bytes.length,
                    (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(entry, bytes);
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "decode");
                var function = program.getFunctionManager().createFunction("definition", entry, body, SourceType.USER_DEFINED);
                var register = program.getRegister(x86 ? (width == 4 ? "R10D" : "R10") : (width == 4 ? "w9" : "x9"));
                var type = width == 4 ? IntegerDataType.dataType : LongLongDataType.dataType;
                var local = (LocalVariable) function.addLocalVariable(new LocalVariableImpl("held", 4,
                    type, register, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                var mapping = TargetRegisterMap.forTarget(target);
                var rejected = GhidraVariableStorage.stableLocal(program, function, local, mapping, TaskMonitor.DUMMY);
                var ranges = GhidraVariableStorage.localPrefix(program, function, local, mapping, rejected, TaskMonitor.DUMMY);
                require(ranges.size() == 3 && ranges.get(0).start() == 0x1000 && ranges.get(0).end() == 0x1008 &&
                    !ranges.get(0).storage().available() && ranges.get(1).start() == 0x1008 &&
                    ranges.get(1).end() == 0x1000 + (x86 ? 14 : 16) && ranges.get(1).storage().available() &&
                    ranges.get(2).end() == 0x1000 + bytes.length && !ranges.get(2).storage().available(),
                    "recorded definition must finish before availability: " + target + "/" + width + " " + ranges);
                local.setFirstUseOffset(8);
                var reads = GhidraVariableStorage.localPrefix(program, function, local, mapping, rejected, TaskMonitor.DUMMY);
                require(reads.equals(ranges), "same completed definition and next read must agree");
                local.setFirstUseOffset(5);
                require(GhidraVariableStorage.localPrefix(program, function, local, mapping, rejected,
                    TaskMonitor.DUMMY).isEmpty(), "offcut definition accepted");
                local.setFirstUseOffset(4);
                for (String replacement : x86 ? List.of("90909090", "41b20790") : List.of("1f2003d5")) {
                    byte[] changed = bytes.clone();
                    System.arraycopy(HexFormat.of().parseHex(replacement), 0, changed, 4, 4);
                    program.getListing().clearCodeUnits(body.getMinAddress(), body.getMaxAddress(), false);
                    program.getMemory().setBytes(entry, changed);
                    require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "negative decode");
                    require(GhidraVariableStorage.localPrefix(program, function, local, mapping, rejected,
                        TaskMonitor.DUMMY).isEmpty(), "incomplete definition accepted " + replacement);
                }
            }
            finally { program.endTransaction(transaction, true); }
        }
        finally { program.release(owner); }
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
