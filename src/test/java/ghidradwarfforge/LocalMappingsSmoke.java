package ghidradwarfforge;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/** Exercise the actual saved Ghidra merge contract, including negative identities. */
public final class LocalMappingsSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (String language : List.of("x86:LE:64:default", "AARCH64:LE:64:v8A",
                "MIPS:BE:32:default", "MIPS:LE:32:default")) {
            check(language);
        }
        System.out.println("local-mappings-smoke=PASS checks=" + checks);
    }

    private static void check(String languageId) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
        Object owner = new Object();
        var program = new ProgramDB("saved-local-mappings", language, language.getDefaultCompilerSpec(), owner);
        try {
            int tx = program.startTransaction("saved identity");
            try {
                var entry = language.getDefaultSpace().getAddress(0x1000);
                program.getMemory().createInitializedBlock("body", entry, 64, (byte) 0, TaskMonitor.DUMMY, false);
                var function = program.getFunctionManager().createFunction("merged", entry,
                    new AddressSet(entry, entry.add(31)), SourceType.USER_DEFINED);
                boolean x86 = languageId.startsWith("x86:");
                boolean arm = languageId.startsWith("AARCH64:");
                var first = program.getRegister(x86 ? "R10D" : arm ? "w9" : "t0");
                var second = program.getRegister(x86 ? "R11D" : arm ? "w10" : "t1");
                var type = IntegerDataType.dataType;
                var canonical = function.addLocalVariable(new LocalVariableImpl("value", 4,
                    type, first, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                var copy = function.addLocalVariable(new LocalVariableImpl("value$1", 12,
                    type, second, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                var update = function.addLocalVariable(new LocalVariableImpl("value$2", 20,
                    type, second, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                var diagnostics = new ArrayList<String>();
                var groups = GhidraLocalMappings.extract(program, function, TaskMonitor.DUMMY, diagnostics::add);
                require(groups.size() == 1 && diagnostics.isEmpty(), "canonical identity " + languageId + diagnostics);
                var group = groups.getFirst();
                require(group.canonical() == canonical, "canonical listing object");
                require(group.mappings().stream().map(GhidraLocalMappings.Mapping::variable).toList()
                    .equals(List.of(canonical, copy, update)), "all saved mappings in identity order");
                require(group.mappings().stream().map(mapping -> mapping.definition().subtract(entry)).toList()
                    .equals(List.of(4L, 12L, 20L)), "all exact definition addresses");
                require(group.mappings().stream().map(GhidraLocalMappings.Mapping::register).toList()
                    .equals(List.of(first, second, second)), "physical storage changes and reuse");
                require(function.getLocalVariables().length == 3 && copy.getName().equals("value$1"),
                    "extraction must not rewrite saved locals");

                copy.setName("unrelated", SourceType.USER_DEFINED);
                require(GhidraLocalMappings.extract(program, function, TaskMonitor.DUMMY, diagnostics::add).isEmpty(),
                    "same bits/shape without Ghidra identity must not merge");
                copy.setName("value$1", SourceType.USER_DEFINED);
                copy.setDataType(UnsignedIntegerDataType.dataType, SourceType.USER_DEFINED);
                require(GhidraLocalMappings.extract(program, function, TaskMonitor.DUMMY, diagnostics::add).isEmpty(),
                    "different signed type must not merge");
                copy.setDataType(type, SourceType.USER_DEFINED);
                update.setName("value$3", SourceType.USER_DEFINED);
                var incomplete = GhidraLocalMappings.extract(program, function, TaskMonitor.DUMMY, diagnostics::add);
                require(incomplete.size() == 1 && incomplete.getFirst().mappings().size() == 2,
                    "Ghidra stops merging at a missing ordinal; later spelling is separate");
                update.setName("value$2", SourceType.USER_DEFINED);
                copy.getSymbol().setSource(SourceType.ANALYSIS);
                diagnostics.clear();
                require(GhidraLocalMappings.extract(program, function, TaskMonitor.DUMMY, diagnostics::add).isEmpty(),
                    "all mappings must have explicit curated provenance");
                require(diagnostics.size() == 1, "unsupported group diagnosed");
                copy.getSymbol().setSource(SourceType.USER_DEFINED);
                require(GhidraLocalMappings.extract(program, function, TaskMonitor.DUMMY, diagnostics::add).equals(groups),
                    "negative controls restore identical evidence");

                var cancelled = new TaskMonitorAdapter(true) {
                    private int calls;
                    @Override public void checkCancelled() throws CancelledException {
                        if (++calls == 12) throw new CancelledException();
                    }
                };
                try {
                    GhidraLocalMappings.extract(program, function, cancelled, diagnostics::add);
                    throw new AssertionError("encoder cancellation lost");
                }
                catch (CancelledException expected) { checks++; }
                var typedef = new ghidra.program.model.data.TypedefDataType("curated_count", type);
                for (var variable : function.getLocalVariables()) variable.setDataType(typedef, SourceType.USER_DEFINED);
                var typed = GhidraLocalMappings.extract(program, function, TaskMonitor.DUMMY, diagnostics::add);
                require(typed.size() == 1 && typed.getFirst().canonical().getDataType().getName().equals("curated_count"),
                    "named analyst type is preserved without crashing its encoder");
                for (var variable : function.getLocalVariables()) variable.setDataType(type, SourceType.USER_DEFINED);
                function.removeVariable(canonical);
                function.addLocalVariable(new LocalVariableImpl("value", type, -16,
                    program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                diagnostics.clear();
                require(GhidraLocalMappings.extract(program, function, TaskMonitor.DUMMY, diagnostics::add).isEmpty(),
                    "address-tied stack base has no recorded definition PC");
                require(diagnostics.size() == 1 && diagnostics.getFirst().contains("distinct curated full-width definition"),
                    "unsupported stack merge diagnosed without fabricated lifetime");
                var stack = (ghidra.program.model.listing.LocalVariable) function.getLocalVariables()[0];
                for (var local : function.getLocalVariables()) {
                    if (local.getName().equals("value")) stack = (ghidra.program.model.listing.LocalVariable) local;
                }
                stack.setFirstUseOffset(4);
                diagnostics.clear();
                var stackGroups = GhidraLocalMappings.extract(program, function, TaskMonitor.DUMMY, diagnostics::add);
                require(stackGroups.size() == 1 && diagnostics.isEmpty(),
                    "saved stack owner plus register updates must retain Ghidra identity " + languageId + diagnostics);
                require(stackGroups.getFirst().canonical() == stack && stackGroups.getFirst().mappings().size() == 3,
                    "stack canonical plus both register mappings");
                require(stackGroups.getFirst().mappings().getFirst().definition().equals(entry.add(4)),
                    "stack definition comes from the saved listing first use, not an invented decompiler PC");
                require(stackGroups.getFirst().mappings().getFirst().register() == null,
                    "stack mapping must not fabricate a register");
            }
            finally { program.endTransaction(tx, true); }
        }
        finally { program.release(owner); }
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
