package ghidradwarfforge;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.elf.ElfFunctionAlias;
import ghidradwarfforge.elf.ElfFunctionModeCue;
import ghidradwarfforge.nativeapi.DwarfTarget;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** Actual saved ARM/Thumb code: address boundaries and stale alias evidence. */
final class Arm32AliasEvidenceBoundarySmoke {
    private static final DwarfTarget TARGET = new DwarfTarget("arm", "arm", 4, true, "ARM");
    private static int checks;

    static int run() throws Exception {
        checks = 0;
        for (String bytes : List.of("0100a0e31eff2fe1", "01207047", "40f201007047")) {
            int mode = bytes.length() == 16 ? 0 : 1;
            int length = bytes.length() / 2;
            for (long entry : new long[] {0x1000, 0x8000_0000L, 0x1_0000_0000L - length}) {
                boundaries(bytes, mode, entry);
            }
        }
        staleSavedProgram();
        System.out.println("arm32-alias-evidence-boundaries=PASS checks=" + checks);
        return checks;
    }

    private static void boundaries(String hex, int mode, long entry) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("ARM:LE:32:v8"));
        Object owner = new Object();
        var program = new ProgramDB("arm32-boundary", language, language.getDefaultCompilerSpec(), owner);
        byte[] bytes = HexFormat.of().parseHex(hex);
        String expectedHash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        try {
            int transaction = program.startTransaction("real decoded boundary function");
            try {
                var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(entry);
                var end = start.addNoWrap(bytes.length - 1);
                program.getMemory().createInitializedBlock("code", start, bytes.length,
                    (byte) 0, TaskMonitor.DUMMY, false).setExecute(true);
                program.getMemory().setBytes(start, bytes);
                program.getProgramContext().setValue(program.getRegister("TMode"), start, end, BigInteger.valueOf(mode));
                require(new DisassembleCommand(start, new AddressSet(start, end), false).applyTo(program, TaskMonitor.DUMMY),
                    "boundary instructions decode");
                var function = program.getFunctionManager().createFunction("edge", start,
                    new AddressSet(start, end), SourceType.USER_DEFINED);
                program.getSymbolTable().createLabel(start, "edge_alias", SourceType.USER_DEFINED);
                for (long link : new long[] {0, 0x1000, 0x8000_0000L, 0x1_0000_0000L - bytes.length}) {
                    long delta = entry - link;
                    var symbols = List.of(new FunctionSymbol("edge", link, bytes.length));
                    var messages = new ArrayList<String>();
                    var aliases = GhidraFunctionAliases.extract(program, symbols, delta, TaskMonitor.DUMMY, messages::add);
                    require(aliases.size() == 1 && messages.isEmpty(), "real analyst alias extraction: " + messages);
                    var expected = new ElfFunctionModeCue("edge", link, bytes.length, link | mode, expectedHash);
                    require(GhidraArm32FunctionModes.extractAliases(program, aliases, TARGET, delta,
                        TaskMonitor.DUMMY, messages::add).equals(List.of(expected)), "rebased extent, mode and bytes");
                    var primary = GhidraArm32FunctionModes.extract(program, symbols, TARGET, delta,
                        TaskMonitor.DUMMY, messages::add);
                    require(primary.equals(mode == 1 ? List.of(expected) : List.of()),
                        "Thumb primary evidence or silent ARM-only primary path");
                    require(messages.isEmpty(), "valid boundary emitted omission");
                    require(function.getEntryPoint().equals(start) && function.getBody().equals(new AddressSet(start, end)),
                        "extractors changed saved function body");
                    byte[] after = new byte[bytes.length];
                    require(program.getMemory().getBytes(start, after) == bytes.length && java.util.Arrays.equals(bytes, after),
                        "extractors changed code");
                }
                var original = new ElfFunctionAlias("edge_alias", "edge", entry, bytes.length, expectedHash);
                for (long delta : new long[] {Long.MAX_VALUE, Long.MIN_VALUE, -entry - 1, 0x1_0000_0000L - entry}) {
                    var messages = new ArrayList<String>();
                    require(GhidraArm32FunctionModes.extractAliases(program, List.of(original), TARGET, delta,
                        TaskMonitor.DUMMY, messages::add).isEmpty(), "invalid analysis address must not wrap to code");
                    require(messages.size() == 1 && messages.getFirst().startsWith("Omitted ARM32 alias mode evidence for edge:"),
                        "invalid analysis address needs an omission");
                }
                var recovered = GhidraArm32FunctionModes.extractAliases(program, List.of(original), TARGET, 0,
                    TaskMonitor.DUMMY, ignored -> { throw new AssertionError("valid retry omitted"); });
                require(recovered.equals(List.of(new ElfFunctionModeCue("edge", entry, bytes.length, entry | mode, expectedHash))),
                    "invalid rebase attempts contaminated subsequent evidence");
            }
            finally { program.endTransaction(transaction, false); }
        }
        finally { program.release(owner); }
    }

    private static void staleSavedProgram() throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("ARM:LE:32:v8"));
        Object owner = new Object();
        var program = new ProgramDB("arm32-stale-alias", language, language.getDefaultCompilerSpec(), owner);
        try {
            int transaction = program.startTransaction("saved alias and subsequent analyst edits");
            try {
                var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                var end = start.add(3);
                program.getMemory().createInitializedBlock("code", start, 16, (byte) 0, TaskMonitor.DUMMY, false).setExecute(true);
                byte[] original = HexFormat.of().parseHex("01207047");
                program.getMemory().setBytes(start, original);
                program.getProgramContext().setValue(program.getRegister("TMode"), start, start.add(15), BigInteger.ONE);
                require(new DisassembleCommand(start, new AddressSet(start, end), false).applyTo(program, TaskMonitor.DUMMY),
                    "stale fixture decoded");
                var function = program.getFunctionManager().createFunction("saved", start,
                    new AddressSet(start, end), SourceType.USER_DEFINED);
                program.getSymbolTable().createLabel(start, "saved_alias", SourceType.USER_DEFINED);
                var symbols = List.of(new FunctionSymbol("saved", 0x1000, 4));
                var aliases = GhidraFunctionAliases.extract(program, symbols, 0, TaskMonitor.DUMMY,
                    ignored -> { throw new AssertionError("initial alias omitted"); });
                require(aliases.size() == 1, "initial saved alias inventory");
                var originalCue = GhidraArm32FunctionModes.extractAliases(program, aliases, TARGET, 0,
                    TaskMonitor.DUMMY, ignored -> { throw new AssertionError("initial mode omitted"); });
                require(originalCue.size() == 1, "initial saved cue inventory");
                function.setBody(new AddressSet(start, start.add(5)));
                omitted(program, aliases, "alias body changed");
                function.setBody(new AddressSet(start, end));
                require(GhidraArm32FunctionModes.extractAliases(program, aliases, TARGET, 0,
                    TaskMonitor.DUMMY, ignored -> { }).equals(originalCue), "restored body did not restore evidence");

                program.getListing().clearCodeUnits(start, end, false);
                omitted(program, aliases, "not a decoded instruction boundary");
                program.getMemory().setBytes(start, HexFormat.of().parseHex("02207047"));
                require(new DisassembleCommand(start, new AddressSet(start, end), false).applyTo(program, TaskMonitor.DUMMY),
                    "analyst replacement decoded");
                omitted(program, aliases, "code changed after extraction");
                var fresh = GhidraFunctionAliases.extract(program, symbols, 0, TaskMonitor.DUMMY,
                    ignored -> { throw new AssertionError("fresh alias omitted"); });
                var freshCue = GhidraArm32FunctionModes.extractAliases(program, fresh, TARGET, 0,
                    TaskMonitor.DUMMY, ignored -> { throw new AssertionError("fresh mode omitted"); });
                require(freshCue.size() == 1 && !freshCue.getFirst().codeSha256().equals(originalCue.getFirst().codeSha256()),
                    "new evidence must bind current bytes");
                require(program.getFunctionManager().removeFunction(start), "analyst removed function");
                omitted(program, fresh, "alias owner or body changed");
            }
            finally { program.endTransaction(transaction, false); }
        }
        finally { program.release(owner); }
    }

    private static void omitted(ProgramDB program, List<ElfFunctionAlias> aliases, String reason) throws Exception {
        var messages = new ArrayList<String>();
        require(GhidraArm32FunctionModes.extractAliases(program, aliases, TARGET, 0,
            TaskMonitor.DUMMY, messages::add).isEmpty(), "stale evidence was accepted: " + reason);
        require(messages.size() == 1 && messages.getFirst().contains(reason), "missing precise omission: " + messages);
    }

    private static void require(boolean condition, String reason) {
        if (!condition) throw new AssertionError(reason);
        checks++;
    }
}
