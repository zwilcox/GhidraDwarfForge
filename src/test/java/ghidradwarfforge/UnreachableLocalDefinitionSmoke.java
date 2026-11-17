package ghidradwarfforge;

import java.util.Arrays;
import java.util.HexFormat;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.locations.TargetRegisterMap;

/** Real decoded dead blocks must not create locations or pollute executable joins. */
public final class UnreachableLocalDefinitionSmoke {
    private static int checks;

    static void check() throws Exception {
        for (boolean x86 : new boolean[] { true, false }) {
            for (int width : new int[] { 4, 8 }) {
                for (long base : new long[] { 0x1000, 0x1_0000_0000L }) {
                    for (boolean deadCycle : new boolean[] { false, true }) check(x86, width, base, deadCycle);
                }
            }
        }
        System.out.println("unreachable-local-definitions=PASS checks=" + checks);
    }

    private static void check(boolean x86, int width, long base, boolean deadCycle) throws Exception {
        String target = x86 ? "x86_64" : "aarch64";
        String define = x86 ? (width == 4 ? "41ba07000000" : "49c7c207000000") :
            (width == 4 ? "e9008052" : "e90080d2");
        String clear = x86 ? (width == 4 ? "4531d2" : "4d31d2") :
            (width == 4 ? "e9031f2a" : "e9031faa");
        // entry -> definition -> join -> return. The separately decoded dead
        // block clears the local, then either enters the join or loops on itself.
        String deadJump = x86 ? (deadCycle ? "ebfb" : "eb" + HexFormat.of().toHexDigits((byte) (define.length() / 2))) :
            (deadCycle ? "ffffff17" : "02000014");
        String result = x86 ? (width == 4 ? "4489d0" : "4c89d0") :
            (width == 4 ? "e003092a" : "e00309aa");
        byte[] code = HexFormat.of().parseHex((x86 ? "eb05" : "03000014") + clear + deadJump + define +
            result + (x86 ? "c3" : "c0035fd6"));
        int dead = x86 ? 2 : 4, definition = x86 ? 7 : 12;
        int ready = definition + define.length() / 2;
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
            x86 ? "x86:LE:64:default" : "AARCH64:LE:64:v8A"));
        Object owner = new Object();
        var program = new ProgramDB("unreachable-local", language, language.getDefaultCompilerSpec(), owner);
        String context = target + "/" + width + "/" + Long.toHexString(base) + "/cycle=" + deadCycle;
        try {
            int transaction = program.startTransaction("curated body with dead blocks");
            try {
                var entry = language.getDefaultSpace().getAddress(base);
                var body = new AddressSet(entry, entry.add(code.length - 1));
                var block = program.getMemory().createInitializedBlock("code", entry, code.length,
                    (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(entry, code);
                for (int offset : new int[] { 0, dead }) {
                    require(new DisassembleCommand(entry.add(offset), body, true).applyTo(program, TaskMonitor.DUMMY),
                        "decode " + context);
                }
                var function = program.getFunctionManager().createFunction("dead_blocks", entry, body, SourceType.USER_DEFINED);
                require(function.getBody().equals(body), "curated body changed " + context);
                var type = width == 4 ? IntegerDataType.dataType : LongLongDataType.dataType;
                var register = program.getRegister(x86 ? (width == 4 ? "R10D" : "R10") : (width == 4 ? "w9" : "x9"));
                var local = (LocalVariable) function.addLocalVariable(new LocalVariableImpl("held", definition,
                    type, register, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                var map = TargetRegisterMap.forTarget(target);
                var rejected = GhidraVariableStorage.stableLocal(program, function, local, map, TaskMonitor.DUMMY);
                long modifications = program.getModificationNumber();
                var intervals = RegisterDefinitionFlow.prove(program, function, local, map, rejected, TaskMonitor.DUMMY);
                require(!intervals.isEmpty(), "dead predecessor suppressed reachable proof " + context);
                for (int offset = 0; offset < code.length; offset++) {
                    long address = base + offset;
                    var rows = intervals.stream().filter(r -> r.start() <= address && address < r.end()).toList();
                    require(rows.size() == 1, "missing/overlapping instruction coverage " + context);
                    require(rows.getFirst().storage().available() == (offset >= ready),
                        "wrong reachability or definition boundary at " + offset + " " + context);
                }
                require(program.getModificationNumber() == modifications, "proof changed saved program " + context);
                byte[] after = new byte[code.length];
                program.getMemory().getBytes(entry, after);
                require(Arrays.equals(code, after), "proof changed machine bytes " + context);
                local.setFirstUseOffset(dead);
                require(RegisterDefinitionFlow.prove(program, function, local, map, rejected, TaskMonitor.DUMMY).isEmpty(),
                    "unreachable definition acquired a local lifetime " + context);
                local.setFirstUseOffset(definition);
                var reference = program.getReferenceManager().addMemoryReference(entry.subtract(16), entry.add(dead),
                    RefType.UNCONDITIONAL_JUMP, SourceType.USER_DEFINED, 0);
                require(RegisterDefinitionFlow.prove(program, function, local, map, rejected, TaskMonitor.DUMMY).isEmpty(),
                    "alternate entry was ignored because its block looked dead " + context);
                program.getReferenceManager().delete(reference);
                require(RegisterDefinitionFlow.prove(program, function, local, map, rejected, TaskMonitor.DUMMY).equals(intervals),
                    "removed alternate entry did not restore proof " + context);
            }
            finally { program.endTransaction(transaction, true); }
        }
        finally { program.release(owner); }
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }
}
