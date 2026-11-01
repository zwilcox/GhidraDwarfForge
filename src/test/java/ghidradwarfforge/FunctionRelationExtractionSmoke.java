package ghidradwarfforge;

import java.io.File;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import db.DBHandle;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.FunctionRelations;

public final class FunctionRelationExtractionSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])), new HeadlessGhidraApplicationConfiguration());
        for (String[] profile : List.of(new String[] {"x86:LE:64:default", "x86_64"},
                new String[] {"AARCH64:LE:64:v8A", "aarch64"}, new String[] {"ARM:LE:32:v8", "arm"},
                new String[] {"MIPS:BE:32:default", "mips"}, new String[] {"MIPS:LE:32:default", "mipsel"})) check(profile);
        System.out.println("function-relation-extraction=PASS checks=" + checks);
    }

    private static void check(String[] profile) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(profile[0]));
        Object owner = new Object();
        var program = new ProgramDB("relationships", language, language.getDefaultCompilerSpec(), owner);
        var folder = Files.createTempDirectory("forge-function-relations-");
        var saved = folder.resolve("program.db");
        FunctionRelations expected;
        try {
            int tx = program.startTransaction("saved relationships");
            try {
                var start = language.getDefaultSpace().getAddress(0x1000);
                program.getMemory().createInitializedBlock("image", start, 0x1000, (byte) 0, TaskMonitor.DUMMY, false);
                var a = function(program, "gateway", 0x1000);
                var b = function(program, "bridge", 0x1100);
                var c = function(program, "target", 0x1200);
                var e = function(program, "external_gateway", 0x1300);
                var u = function(program, "unknown_gateway", 0x1400);
                var external = program.getExternalManager().addExtFunction("library", "external", null, SourceType.USER_DEFINED).getFunction();
                external.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
                var unknown = program.getExternalManager().addExtFunction("library", "unknown", null, SourceType.IMPORTED).getFunction();
                b.setThunkedFunction(c);
                a.setThunkedFunction(b);
                e.setThunkedFunction(external);
                u.setThunkedFunction(unknown);
                var diagnostics = new ArrayList<String>();
                expected = extract(program, profile[1], 0, "", diagnostics);
                require(expected.thunks().size() == 3, "known chain and external only");
                require(expected.thunks().stream().anyMatch(t -> t.id() == a.getID() && t.targetId() == b.getID()), "direct target, not recursive destination");
                var externalRelation = expected.thunks().stream().filter(t -> t.id() == e.getID()).findFirst().orElseThrow();
                require(externalRelation.target().address() == -1 && externalRelation.target().declarationKey().equals("external:" + external.getID()),
                    "external reference has no invented image address");
                require(diagnostics.stream().anyMatch(d -> d.contains("unknown_gateway") && d.contains("not exported")), "unknown prototype diagnosed");
                var missing = extract(program, profile[1], 0, "bridge", diagnostics);
                require(missing.thunks().size() == 1 && missing.thunks().getFirst().id() == e.getID(), "missing direct target cannot collapse chain");
                a.setThunkedFunction(c);
                var changed = extract(program, profile[1], 0, "", diagnostics);
                require(changed.thunks().stream().anyMatch(t -> t.id() == a.getID() && t.targetId() == c.getID()), "saved target edit reflected");
                a.setThunkedFunction(b);
                b.setName("renamed_bridge", SourceType.USER_DEFINED);
                var renamed = extract(program, profile[1], 0, "", diagnostics);
                require(renamed.thunks().stream().anyMatch(t -> t.id() == a.getID() && t.targetId() == b.getID() && t.target().name().equals("renamed_bridge")),
                    "rename preserves identity without stale display");
                b.setName("bridge", SourceType.USER_DEFINED);
                require(extract(program, profile[1], 0, "", diagnostics).equals(expected), "restored graph deterministic");
                program.setImageBase(program.getImageBase().add(0x200000), true);
                require(extract(program, profile[1], 0x200000, "", diagnostics).equals(expected), "rebase preserves normalized identities");
            }
            finally { program.endTransaction(tx, true); }
            program.getDBHandle().saveAs(saved.toFile(), false, TaskMonitor.DUMMY);
            byte[] before = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(saved));
            Object reader = new Object();
            var reopened = new ProgramDB(new DBHandle(saved.toFile()), OpenMode.IMMUTABLE, TaskMonitor.DUMMY, reader);
            try {
                require(extract(reopened, profile[1], 0x200000, "", new ArrayList<>()).equals(expected), "immutable reopen exact graph");
                var cancelled = new ghidra.util.task.TaskMonitorAdapter(true);
                cancelled.cancel();
                try {
                    GhidraFunctionRelations.extract(reopened, List.of(), List.of(), 0, cancelled, ignored -> { });
                    throw new AssertionError("ignored cancellation");
                }
                catch (ghidra.util.exception.CancelledException expectedCancellation) { checks++; }
            }
            finally { reopened.release(reader); }
            require(Arrays.equals(before, MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(saved))), "immutable database unchanged");
            System.out.println("function-relations-target=PASS " + profile[0]);
        }
        finally { program.release(owner); }
    }

    private static Function function(ProgramDB program, String name, long offset) throws Exception {
        var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        var function = program.getFunctionManager().createFunction(name, address, new AddressSet(address, address.add(3)), SourceType.USER_DEFINED);
        function.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
        return function;
    }

    private static FunctionRelations extract(ProgramDB program, String target, long delta, String omitted,
            List<String> diagnostics) throws Exception {
        var symbols = new ArrayList<FunctionSymbol>();
        for (var function : program.getFunctionManager().getFunctions(true)) {
            if (!function.getName().equals(omitted)) symbols.add(new FunctionSymbol(function.getName(), function.getEntryPoint().getOffset() - delta, 4));
        }
        return GhidraTypeGraph.extract(program, symbols, target, delta, TaskMonitor.DUMMY, diagnostics::add).functionRelations();
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
