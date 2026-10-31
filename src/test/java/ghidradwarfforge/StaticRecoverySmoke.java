package ghidradwarfforge;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

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
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** Real saved identities and listing conflicts; actual decompiler evidence is tested headlessly. */
public final class StaticRecoverySmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (String[] profile : List.of(new String[] {"x86:LE:64:default", "x86_64"},
                new String[] {"AARCH64:LE:64:v8A", "aarch64"}, new String[] {"ARM:LE:32:v8", "arm"},
                new String[] {"MIPS:BE:32:default", "mips"}, new String[] {"MIPS:LE:32:default", "mipsel"})) check(profile);
        System.out.println("static-recovery=PASS checks=" + checks);
    }

    private static void check(String[] profile) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(profile[0]));
        Object token = new Object();
        var program = new ProgramDB("static-recovery", language, language.getDefaultCompilerSpec(), token);
        try {
            int tx = program.startTransaction("test recovery");
            try {
                var entry = language.getDefaultSpace().getAddress(0x401000);
                var object = entry.add(256);
                program.getMemory().createInitializedBlock("image", entry, 512, (byte) 0, TaskMonitor.DUMMY, false);
                var function = program.getFunctionManager().createFunction("owner", entry,
                    new AddressSet(entry, entry.add(63)), SourceType.USER_DEFINED);
                function.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
                var label = program.getSymbolTable().createLabel(object, "recovered", function, SourceType.USER_DEFINED);
                label.setPrimary();
                var candidate = new GhidraStaticRecovery.Candidate(function.getID(), label.getID(), label.getName(),
                    label.getSource(), object, IntegerDataType.dataType);
                var recovery = new GhidraStaticRecovery.Result(List.of(candidate), List.of());
                var symbols = List.of(new FunctionSymbol("owner", entry.getOffset(), 64));
                var registers = TargetRegisterMap.forTarget(profile[1]);
                var diagnostics = new ArrayList<String>();
                var model = GhidraTypeGraph.extract(program, symbols, registers, 0, TaskMonitor.DUMMY, diagnostics::add,
                    Map.of(), Map.of(), Map.of(entry.getOffset(), recovery));
                require(model.functionStatics().size() == 1 && model.functionStatics().getFirst().size() == 4, "recovered object");
                require(model.functionStatics().getFirst().source().contains("DECOMPILER_INFERRED"), "inference provenance");
                require(!program.getListing().getDataAt(object).isDefined(), "does not apply inferred Data");
                require(GhidraTypeGraph.extract(program, symbols, profile[1], 0, TaskMonitor.DUMMY, diagnostics::add)
                    .functionStatics().isEmpty(), "no same-pass evidence means no inference");
                program.getListing().createData(object, UnsignedIntegerDataType.dataType);
                var curated = GhidraTypeGraph.extract(program, symbols, registers, 0, TaskMonitor.DUMMY, diagnostics::add,
                    Map.of(), Map.of(), Map.of(entry.getOffset(), recovery));
                require(!curated.functionStatics().getFirst().source().contains("INFERRED"), "saved type precedence");
                GhidraStaticBindings.save(program, label, function, "", "recovered", "fixture", TaskMonitor.DUMMY);
                program.getListing().clearCodeUnits(object, object.add(3), false);
                require(GhidraTypeGraph.extract(program, symbols, registers, 0, TaskMonitor.DUMMY, diagnostics::add,
                    Map.of(), Map.of(), Map.of(entry.getOffset(), recovery)).functionStatics().isEmpty(), "stale binding not recovered");
                GhidraStaticBindings.remove(program, label.getID(), TaskMonitor.DUMMY);
                var middle = program.getSymbolTable().createLabel(object.add(2), "next_object", SourceType.USER_DEFINED);
                require(GhidraStaticRecovery.accept(program, function, label, object, 0, candidate, TaskMonitor.DUMMY, diagnostics::add) == null,
                    "inference cannot cross saved symbol");
                middle.delete();
                program.getListing().createData(object.add(2), ghidra.program.model.data.ShortDataType.dataType);
                require(GhidraStaticRecovery.accept(program, function, label, object, 0, candidate, TaskMonitor.DUMMY, diagnostics::add) == null,
                    "inference cannot cross defined Data");
                program.getListing().clearCodeUnits(object, object.add(3), false);
                label.setName("renamed", SourceType.USER_DEFINED);
                require(GhidraStaticRecovery.accept(program, function, label, object, 0, candidate, TaskMonitor.DUMMY, diagnostics::add) == null,
                    "stale saved name");
                label.setName("recovered", SourceType.USER_DEFINED);
                var namespace = program.getSymbolTable().createNameSpace(program.getGlobalNamespace(), "owner", SourceType.USER_DEFINED);
                label.setNamespace(namespace);
                require(GhidraStaticRecovery.accept(program, function, label, object, 0, candidate, TaskMonitor.DUMMY, diagnostics::add) == null,
                    "namespace spelling is not ownership");
                label.delete();
                var local = function.addLocalVariable(new LocalVariableImpl("memory_local", 0, IntegerDataType.dataType,
                    object, program, SourceType.ANALYSIS), SourceType.ANALYSIS);
                var blocks = List.of(new GhidraLexicalScopes.Block("inner", "", new AddressSet(entry.add(8), entry.add(15))));
                GhidraLexicalScopes.save(function, "explicit memory-local scope", blocks,
                    List.of(new GhidraLexicalScopes.Local(local, "inner", "shadow")), TaskMonitor.DUMMY);
                var saved = GhidraTypeGraph.extract(program, symbols, profile[1], 0, TaskMonitor.DUMMY, diagnostics::add);
                require(saved.functionStatics().size() == 1 && saved.functionStatics().getFirst().block().equals("inner") &&
                    saved.functionStatics().getFirst().name().equals("shadow"), "saved memory local retains lexical owner and display name");
                require(saved.functions().getFirst().locals().isEmpty() && saved.globals().isEmpty() &&
                    saved.lexicalScopes().getFirst().locals().isEmpty(), "single static declaration, no local/global duplicate");
                local.setName("stale_local", SourceType.USER_DEFINED);
                require(GhidraTypeGraph.extract(program, symbols, profile[1], 0, TaskMonitor.DUMMY, diagnostics::add)
                    .functionStatics().isEmpty(), "stale lexical binding cannot move memory local to root");
                var cancelled = new ghidra.util.task.TaskMonitorAdapter(true);
                cancelled.cancel();
                try {
                    GhidraStaticRecovery.accept(program, function, local.getSymbol(), object, 4, candidate, cancelled, diagnostics::add);
                    throw new AssertionError("cancellation ignored");
                }
                catch (ghidra.util.exception.CancelledException expected) { checks++; }
                System.out.println("static-recovery-target=PASS " + profile[0]);
            }
            finally { program.endTransaction(tx, false); }
        }
        finally { program.release(token); }
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }
}
