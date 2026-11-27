package ghidradwarfforge;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.TypeGraph;

/** Saved memory-local extraction; explicit recovery candidates do not claim decompiler execution. */
final class MemoryLocalExtractionSmoke {
    private static int checks;
    private static final List<String> CASES = List.of("root", "inferred", "no-evidence", "curated-wins",
        "last-complete-object", "crosses-block", "missing-block", "upper-half-address", "rebased",
        "later-use", "default-source", "rejected-binding", "uninitialized", "rejected-scope",
        "stale-evidence", "wrong-inferred-width", "overlay", "mapped");

    static void check(String[] profile) throws Exception {
        for (String mode : CASES) check(profile, mode);
        System.out.println("memory-local-extraction=PASS target=" + profile[1] + " cases=" + CASES.size() + " checks=" + checks);
    }

    /** Rejection-only Harvard fixture: this does not establish dsPIC export support. */
    static void checkSeparateDataSpace(java.nio.file.Path ghidra) throws Exception {
        var mapping = ghidra.resolve("Ghidra/Processors/PIC/data/languages/PIC30.dwarf");
        String description = java.nio.file.Files.readString(mapping);
        require(description.contains("dwarf=\"0\" ghidra=\"W0\"") &&
            description.contains("dwarf=\"15\" ghidra=\"W15\""), "pinned dsPIC register subset changed");
        var registers = new TargetRegisterMap("dspic30f", "Rejection-only subset from " + mapping,
            Map.of("W0", 0, "W15", 15));
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("dsPIC30F:LE:24:default"));
        require(language.getRegister("W0") != null && language.getRegister("W15") != null,
            "pinned dsPIC registers are unavailable");
        Object owner = new Object();
        var program = new ProgramDB("separate-data-space", language, language.getDefaultCompilerSpec(), owner);
        try {
            int tx = program.startTransaction("distinct physical memory spaces");
            try {
                var code = program.getAddressFactory().getDefaultAddressSpace();
                var ram = program.getAddressFactory().getAddressSpace("ram");
                require(ram != null && !ram.equals(code), "fixture needs distinct code and data spaces");
                var entry = code.getAddress(0x4000);
                var dataStart = ram.getAddress(0x4000);
                program.getMemory().createInitializedBlock("code", entry, 64, (byte) 0x11, TaskMonitor.DUMMY, false);
                var block = program.getMemory().createInitializedBlock("objects", dataStart, 64,
                    (byte) 0x55, TaskMonitor.DUMMY, false);
                require(block.isLoaded() && !block.isOverlay() && !block.isMapped(),
                    "fixture must exercise physical non-default memory, not an overlay or mapped block");
                var function = program.getFunctionManager().createFunction("owner", entry,
                    new AddressSet(entry, entry.add(31)), SourceType.USER_DEFINED);
                var address = dataStart.add(16);
                var local = function.addLocalVariable(new LocalVariableImpl("saved_memory", 0,
                    IntegerDataType.dataType, address, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                require(local.getVariableStorage().isMemoryStorage() && local.getVariableStorage().getMinAddress().equals(address),
                    "saved local lost its real data-space identity");
                var diagnostics = new ArrayList<String>();
                long modifications = program.getModificationNumber();
                var model = GhidraTypeGraph.extract(program, List.of(new FunctionSymbol("owner", entry.getOffset(), 32)),
                    registers, 0, TaskMonitor.DUMMY, diagnostics::add, Map.of(), Map.of(), Map.of());
                require(model.functionStatics().isEmpty() && model.globals().isEmpty() && model.functions().size() == 1 &&
                    model.functions().getFirst().locals().isEmpty() && model.variableStorage().variables().isEmpty(),
                    "a distinct physical address space was flattened into an ELF address");
                require(diagnostics.contains("Omitted memory local saved_memory: unsupported memory mapping"),
                    "unsupported physical address space was not diagnosed");
                require(program.getModificationNumber() == modifications &&
                    program.getMemory().getByte(entry.add(16)) == 0x11 && program.getMemory().getByte(address) == 0x55 &&
                    local.getVariableStorage().getMinAddress().equals(address), "extraction changed saved memory or storage");
            }
            finally { program.endTransaction(tx, false); }
        }
        finally { program.release(owner); }
        System.out.println("memory-local-separate-space=PASS rejection-only=dsPIC30F checks=" + checks);
    }

    private static void check(String[] profile, String mode) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(profile[0]));
        Object owner = new Object();
        var program = new ProgramDB("memory-local-" + mode, language, language.getDefaultCompilerSpec(), owner);
        try {
            int tx = program.startTransaction("saved memory local");
            try {
                var space = language.getDefaultSpace();
                var entry = space.getAddress(0x4000);
                var dataStart = space.getAddress(0x1000);
                program.getMemory().createInitializedBlock("code", entry, 64, (byte) 0, TaskMonitor.DUMMY, false);
                if (mode.equals("mapped")) {
                    program.getMemory().createInitializedBlock("backing", space.getAddress(0x2000), 64,
                        (byte) 0x5a, TaskMonitor.DUMMY, false);
                }
                var block = mode.equals("mapped")
                    ? program.getMemory().createByteMappedBlock("objects", dataStart, space.getAddress(0x2000), 64, false)
                    : mode.equals("uninitialized")
                    ? program.getMemory().createUninitializedBlock("objects", dataStart, 64, false)
                    : program.getMemory().createInitializedBlock("objects", dataStart, 64, (byte) 0x5a,
                        TaskMonitor.DUMMY, mode.equals("overlay"));
                var function = program.getFunctionManager().createFunction("owner", entry,
                    new AddressSet(entry, entry.add(31)), SourceType.USER_DEFINED);
                function.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
                int offset = switch (mode) {
                    case "last-complete-object" -> 60;
                    case "crosses-block" -> 61;
                    case "missing-block" -> 128;
                    default -> 16;
                };
                var address = block.getStart().add(offset);
                boolean undefined = List.of("inferred", "no-evidence", "stale-evidence", "wrong-inferred-width").contains(mode);
                DataType type = undefined ? Undefined4DataType.dataType : mode.equals("curated-wins")
                    ? UnsignedIntegerDataType.dataType : IntegerDataType.dataType;
                var source = mode.equals("default-source") ? SourceType.DEFAULT : SourceType.ANALYSIS;
                var local = (LocalVariable) function.addLocalVariable(new LocalVariableImpl(
                    source == SourceType.DEFAULT ? null : "saved_memory", 0, type, address, program, source), source);
                require(local.getSource() == source && local.getLength() == 4 && local.getVariableStorage().isMemoryStorage(),
                    "saved fixture must retain source, width and memory storage: " + mode);
                if (mode.equals("later-use")) {
                    require(local.setFirstUseOffset(4) && local.getFirstUseOffset() == 4,
                        "saved memory first-use change was not retained");
                }
                if (mode.equals("rejected-binding")) {
                    program.getOptions(GhidraStaticBindings.OPTIONS_NAME).setString("static-" + local.getSymbol().getID(), "GDFSB1:!");
                }
                if (mode.equals("rejected-scope")) {
                    program.getUsrPropertyManager().createStringPropertyMap(GhidraLexicalScopes.PROPERTY_NAME).add(entry, "GDFLS1:!");
                }
                long delta = mode.equals("upper-half-address") ? 0x2000 : mode.equals("rebased") ? 0x800 : 0;
                var symbols = List.of(new FunctionSymbol("owner", entry.getOffset() - delta, 32));
                var diagnostics = new ArrayList<String>();
                var candidate = new GhidraStaticRecovery.Candidate(function.getID(), local.getSymbol().getID(),
                    mode.equals("stale-evidence") ? "old_name" : local.getName(), local.getSource(), address,
                    mode.equals("wrong-inferred-width") ? LongLongDataType.dataType : IntegerDataType.dataType);
                Map<Long, GhidraStaticRecovery.Result> recovery = mode.equals("no-evidence") ? Map.of() :
                    Map.of(entry.getOffset() - delta, new GhidraStaticRecovery.Result(List.of(candidate), List.of()));
                var registers = TargetRegisterMap.forTarget(profile[1]);
                long modifications = program.getModificationNumber();
                byte[] before = block.isInitialized() ? new byte[64] : null;
                if (before != null) program.getMemory().getBytes(block.getStart(), before);
                var model = GhidraTypeGraph.extract(program, symbols, registers, delta, TaskMonitor.DUMMY,
                    diagnostics::add, Map.of(), Map.of(), recovery);
                boolean accepted = List.of("root", "inferred", "curated-wins", "last-complete-object", "rebased", "uninitialized").contains(mode) ||
                    (mode.equals("upper-half-address") && program.getDefaultPointerSize() == Long.BYTES);
                require(model.functionStatics().size() == (accepted ? 1 : 0), "wrong memory-local admission: " + profile[1] + "/" + mode);
                require(model.globals().isEmpty() && model.functions().size() == 1 &&
                    model.functions().getFirst().locals().isEmpty() && model.variableStorage().variables().isEmpty(),
                    "memory local acquired duplicate global, ordinary local or register location: " + mode);
                require(model.lexicalScopes().isEmpty(), "root memory local acquired invented lexical scope");
                if (accepted) {
                    var value = model.functionStatics().getFirst();
                    require(value.name().equals(local.getName()) && value.block().isEmpty()
                        && value.address() == address.getOffset() - delta && value.ownerAddress() == entry.getOffset() - delta
                        && value.size() == 4, "saved identity, extent or normalized address changed: " + mode);
                    require(value.source().contains("SAVED_MEMORY_LOCAL: ANALYSIS") &&
                        value.source().contains("DECOMPILER_INFERRED_TYPE") == mode.equals("inferred"),
                        "saved/inferred provenance differs: " + mode);
                    require(model.types().byKey().get(value.type().key()) instanceof TypeGraph.BaseType base && base.byteSize() == 4
                        && base.encoding() == (mode.equals("curated-wins") ? TypeGraph.BaseEncoding.UNSIGNED : TypeGraph.BaseEncoding.SIGNED),
                        "saved type lost precedence or inferred type was not retained: " + mode);
                }
                if (mode.equals("stale-evidence") || mode.equals("wrong-inferred-width")) {
                    require(diagnostics.stream().anyMatch(s -> s.contains("saved identity or extent changed")), "stale inference was not diagnosed");
                }
                if (mode.equals("later-use") || mode.equals("default-source") || mode.equals("rejected-scope")) {
                    require(diagnostics.stream().anyMatch(s -> s.startsWith("Omitted memory local")), "unsupported saved identity was not diagnosed");
                }
                if (mode.equals("overlay") || mode.equals("mapped")) {
                    require(diagnostics.stream().anyMatch(s -> s.equals(
                        "Omitted memory local saved_memory: unsupported memory mapping")),
                        "unsupported memory mapping was not diagnosed");
                }
                require(model.equals(GhidraTypeGraph.extract(program, symbols, registers, delta, TaskMonitor.DUMMY,
                    ignored -> { }, Map.of(), Map.of(), recovery)), "memory-local extraction is not deterministic");
                var cancelled = new TaskMonitorAdapter(true);
                cancelled.cancel();
                try {
                    GhidraTypeGraph.extract(program, symbols, registers, delta, cancelled, ignored -> { }, Map.of(), Map.of(), recovery);
                    throw new AssertionError("memory-local cancellation ignored");
                }
                catch (CancelledException expected) { checks++; }
                require(program.getModificationNumber() == modifications && local.getSource() == source
                    && local.getDataType().isEquivalent(type) && local.getVariableStorage().getMinAddress().equals(address),
                    "extraction changed saved analyst state: " + mode);
                if (before != null) {
                    byte[] after = new byte[64];
                    program.getMemory().getBytes(block.getStart(), after);
                    require(Arrays.equals(before, after), "extraction wrote object bytes");
                }
                else require(!block.isInitialized(), "extraction initialized unknown object bytes");
            }
            finally { program.endTransaction(tx, false); }
        }
        finally { program.release(owner); }
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
