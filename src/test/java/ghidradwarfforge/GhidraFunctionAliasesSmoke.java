package ghidradwarfforge;

import java.io.File;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import db.DBHandle;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/** Explicit secondary labels, qualified collisions, omission and immutable reopened programs. */
public final class GhidraFunctionAliasesSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (String id : List.of("x86:LE:64:default", "AARCH64:LE:64:v8A", "ARM:LE:32:v7",
                "MIPS:BE:32:default", "MIPS:LE:32:default", "x86:LE:32:default")) {
            var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(id));
            Object owner = new Object();
            var program = new ProgramDB("aliases", language, language.getDefaultCompilerSpec(), owner);
            try {
                int transaction = program.startTransaction("explicit aliases");
                try {
                    var space = program.getAddressFactory().getDefaultAddressSpace();
                    var block = program.getMemory().createInitializedBlock("code", space.getAddress(0x400000),
                        0x1000, (byte) 0x37, TaskMonitor.DUMMY, false);
                    block.setExecute(true);
                    var symbols = program.getSymbolTable();
                    var namespace = symbols.createNameSpace(null, "recovered", SourceType.USER_DEFINED);
                    var type = symbols.createClass(namespace, "Class", SourceType.USER_DEFINED);
                    Function first = function(program, "primary", 0x400000);
                    first.setParentNamespace(namespace);
                    symbols.createLabel(first.getEntryPoint(), "alternate", namespace, SourceType.USER_DEFINED);
                    symbols.createLabel(first.getEntryPoint(), "class_alias", type, SourceType.USER_DEFINED);
                    symbols.createLabel(first.getEntryPoint(), "imported", namespace, SourceType.IMPORTED);
                    symbols.createLabel(first.getEntryPoint(), "inferred", namespace, SourceType.ANALYSIS);
                    symbols.createLabel(first.getEntryPoint(), "owned", first, SourceType.USER_DEFINED);
                    Function second = function(program, "other", 0x400100);
                    symbols.createLabel(first.getEntryPoint(), "duplicate", namespace, SourceType.USER_DEFINED);
                    symbols.createLabel(second.getEntryPoint(), "duplicate", namespace, SourceType.USER_DEFINED);
                    symbols.createLabel(first.getEntryPoint(), "literal::name", namespace, SourceType.USER_DEFINED);
                    var nested = symbols.createNameSpace(namespace, "literal", SourceType.USER_DEFINED);
                    symbols.createLabel(second.getEntryPoint(), "name", nested, SourceType.USER_DEFINED);
                    symbols.createLabel(first.getEntryPoint().add(4), "interior_primary", namespace, SourceType.USER_DEFINED);
                    symbols.createLabel(first.getEntryPoint().add(4), "interior_secondary", namespace, SourceType.USER_DEFINED);
                    Function split = function(program, "split", 0x400200);
                    var body = new AddressSet(split.getBody());
                    body.add(space.getAddress(0x400240), space.getAddress(0x40024f));
                    split.setBody(body);
                    symbols.createLabel(split.getEntryPoint(), "split_alias", namespace, SourceType.USER_DEFINED);
                }
                finally {
                    program.endTransaction(transaction, true);
                }
                observe(program);
                negativeControls(program);
                var saved = Files.createTempDirectory("forge-alias-program-").resolve("saved.db");
                program.getDBHandle().saveAs(saved.toFile(), false, TaskMonitor.DUMMY);
                byte[] bytes = Files.readAllBytes(saved);
                var mtime = Files.getLastModifiedTime(saved);
                Object reopenedOwner = new Object();
                DBHandle handle = new DBHandle(saved.toFile());
                ProgramDB reopened = null;
                try {
                    reopened = new ProgramDB(handle, OpenMode.IMMUTABLE, TaskMonitor.DUMMY, reopenedOwner);
                    observe(reopened);
                }
                finally {
                    if (reopened == null) handle.close();
                    else reopened.release(reopenedOwner);
                }
                require(Arrays.equals(bytes, Files.readAllBytes(saved)) && mtime.equals(Files.getLastModifiedTime(saved)),
                    "immutable program changed");
                System.out.println("ghidra-function-aliases-target=PASS " + id);
            }
            finally {
                program.release(owner);
            }
        }
        System.out.println("ghidra-function-aliases-smoke=PASS checks=" + checks);
    }

    private static Function function(ProgramDB program, String name, long at) throws Exception {
        var entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(at);
        return program.getFunctionManager().createFunction(name, entry,
            new AddressSet(entry, entry.add(15)), SourceType.USER_DEFINED);
    }

    private static void observe(ProgramDB program) throws Exception {
        long delta = 0x10000;
        var functions = GhidraFunctionSymbols.extract(program, TaskMonitor.DUMMY, ignored -> { }, delta);
        var diagnostics = new ArrayList<String>();
        var aliases = GhidraFunctionAliases.extract(program, functions, delta, TaskMonitor.DUMMY, diagnostics::add);
        require(aliases.size() == 2, "expected two aliases: " + aliases + diagnostics);
        require(aliases.stream().map(a -> a.name()).toList().equals(
            List.of("recovered::Class::class_alias", "recovered::alternate")), "qualified stable ordering lost");
        byte[] code = new byte[16];
        Arrays.fill(code, (byte) 0x37);
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(code));
        for (var alias : aliases) {
            require(alias.owner().equals("recovered::primary") && alias.address() == 0x3f0000 &&
                alias.size() == 16 && alias.codeSha256().equals(hash), "owner/extent/hash or rebase changed");
        }
        require(diagnostics.stream().filter(s -> s.contains("ambiguous current")).count() == 4,
            "duplicate/literal-path collision was not omitted: " + diagnostics);
        require(diagnostics.toString().contains("unsupported namespace ownership") &&
            diagnostics.toString().contains("not a unique exported function entry") &&
            diagnostics.toString().contains("contiguous entry-first"), "missing omission: " + diagnostics);
        require(diagnostics.stream().noneMatch(s -> s.contains("imported") || s.contains("inferred")),
            "non-analyst labels treated as aliases");
        require(aliases.equals(GhidraFunctionAliases.extract(program, functions, delta, TaskMonitor.DUMMY,
            ignored -> { })), "nondeterministic extraction");
        var cancelled = new TaskMonitorAdapter(true);
        cancelled.cancel();
        try {
            GhidraFunctionAliases.extract(program, functions, delta, cancelled, ignored -> { });
            throw new AssertionError("ignored cancellation");
        }
        catch (CancelledException expected) {
            checks++;
        }
    }

    private static void negativeControls(ProgramDB program) throws Exception {
        var functions = GhidraFunctionSymbols.extract(program, TaskMonitor.DUMMY, ignored -> { }, 0);
        var diagnostics = new ArrayList<String>();
        require(GhidraFunctionAliases.extract(program, List.of(), 0, TaskMonitor.DUMMY,
            diagnostics::add).isEmpty(), "aliases invented without exported owner");
        int transaction = program.startTransaction("negative alias controls");
        try {
            program.getMemory().getBlock("code").setExecute(false);
            diagnostics.clear();
            require(GhidraFunctionAliases.extract(program, functions, 0, TaskMonitor.DUMMY,
                diagnostics::add).isEmpty() && diagnostics.toString().contains("executable memory"),
                "nonexecutable program bytes accepted");
            program.getMemory().getBlock("code").setExecute(true);
            var primary = program.getFunctionManager().getFunctionAt(
                program.getAddressFactory().getDefaultAddressSpace().getAddress(0x400000));
            primary.setName("renamed", SourceType.USER_DEFINED);
            diagnostics.clear();
            require(GhidraFunctionAliases.extract(program, functions, 0, TaskMonitor.DUMMY,
                diagnostics::add).isEmpty() && diagnostics.toString().contains("definition changed"),
                "stale owner accepted");
        }
        finally {
            program.endTransaction(transaction, false);
        }
        observe(program);
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
