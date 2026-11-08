package ghidradwarfforge;

import java.io.File;
import java.util.List;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.types.TypeGraph;

/** Actual Ghidra type extraction: sizeof differs from floating value storage on padded targets. */
public final class FloatingTypeLayoutSmoke {
    private record Target(String language, String compiler, String map, int encoded, int object) { }
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (var target : List.of(
                new Target("x86:LE:32:default", "gcc", "x86", 10, 12),
                new Target("x86:LE:64:default", "gcc", "x86_64", 10, 16),
                new Target("x86:LE:32:default", "windows", "x86", 8, 8),
                new Target("AARCH64:LE:64:v8A", "default", "aarch64", 8, 8),
                new Target("ARM:LE:32:v8", "default", "arm", 8, 8),
                new Target("MIPS:BE:32:default", "default", "mips", 8, 8),
                new Target("MIPS:LE:32:default", "default", "mipsel", 8, 8))) {
            Object owner = new Object();
            var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(target.language()));
            var program = new ProgramDB("floating-layout", language,
                language.getCompilerSpecByID(new CompilerSpecID(target.compiler())), owner);
            try {
                int tx = program.startTransaction("typed memory objects");
                try {
                    var manager = program.getDataTypeManager();
                    var extended = new LongDoubleDataType(manager);
                    var alias = new TypedefDataType(CategoryPath.ROOT, "ExtendedAlias", extended, manager);
                    var array = new ArrayDataType(alias, 3, alias.getLength(), manager);
                    var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                    program.getMemory().createInitializedBlock("data", start, 512, (byte)0, TaskMonitor.DUMMY, false);
                    int offset = 0;
                    for (DataType type : List.of(extended, alias, array, new FloatDataType(manager), new DoubleDataType(manager))) {
                        var address = start.add(offset);
                        program.getListing().createData(address, type);
                        program.getSymbolTable().createLabel(address, "value_" + offset, SourceType.USER_DEFINED);
                        offset += 64;
                    }
                    var model = GhidraTypeGraph.extract(program, List.of(), target.map(), 0, TaskMonitor.DUMMY, ignored -> { });
                    var nodes = model.types().nodes();
                    var actual = nodes.stream().filter(n -> n instanceof TypeGraph.BaseType && n.name().equals("longdouble"))
                        .map(n -> (TypeGraph.BaseType)n).findFirst().orElseThrow();
                    require(actual.valueByteSize() == target.encoded(), "lost floating payload width");
                    require(actual.byteSize() == target.object(), "lost compiler object size");
                    require(extended.getLength() == target.encoded(), "mutated saved primitive");
                    var aliasType = nodes.stream().filter(n -> n instanceof TypeGraph.TypedefType)
                        .map(n -> (TypeGraph.TypedefType)n).findFirst().orElseThrow();
                    require(aliasType.byteSize() == target.object(), "alias object size differs");
                    require(model.types().valueByteSize(new TypeGraph.TypeRef(aliasType.key())) == target.encoded(),
                        "alias location proof includes padding");
                    var arrayType = nodes.stream().filter(n -> n instanceof TypeGraph.ArrayType)
                        .map(n -> (TypeGraph.ArrayType)n).findFirst().orElseThrow();
                    require(arrayType.byteSize() == target.object() * 3 && arrayType.elementCount() == 3, "array stride changed");
                    for (String name : List.of("float", "double")) {
                        var scalar = nodes.stream().filter(n -> n instanceof TypeGraph.BaseType && n.name().equals(name))
                            .map(n -> (TypeGraph.BaseType)n).findFirst().orElseThrow();
                        require(scalar.byteSize() == (name.equals("float") ? 4 : 8), "ordinary floating sizeof changed");
                        require(scalar.valueByteSize() == scalar.byteSize(), "ordinary floating payload changed");
                    }
                }
                finally { program.endTransaction(tx, true); }
            }
            finally { program.release(owner); }
        }
        for (long valueSize : List.of(0L, 13L)) {
            try {
                new TypeGraph.BaseType("invalid", "invalid", 12, TypeGraph.BaseEncoding.FLOAT, valueSize);
                throw new AssertionError("accepted invalid floating payload");
            }
            catch (IllegalArgumentException expected) { checks++; }
        }
        try {
            new TypeGraph.BaseType("invalid", "invalid", 12, TypeGraph.BaseEncoding.SIGNED, 10);
            throw new AssertionError("padded nonfloating encoding accepted");
        }
        catch (IllegalArgumentException expected) { checks++; }
        System.out.println("floating-type-layout-smoke=PASS checks=" + checks);
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
