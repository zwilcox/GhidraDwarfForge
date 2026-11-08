// Observe computed ABI storage for the owned aggregate/alignment audit.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;
import java.util.*;

public class ProbeMipsLayoutArguments extends GhidraScript {
    protected void run() throws Exception {
        var args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("labels output-json");
        long delta = currentProgram.getImageBase().getOffset() -
            ghidradwarfforge.GhidraImageBase.originalImageBase(currentProgram);
        var labels = new LinkedHashMap<String, Long>();
        for (String line : Files.readAllLines(Path.of(args[0]))) {
            String[] fields = line.split(" ");
            if (fields.length != 2 || labels.put(fields[0], Long.decode(fields[1])) != null) {
                throw new IllegalArgumentException("invalid labels");
            }
        }
        var encoder = new ghidra.program.model.pcode.XmlEncode(false);
        currentProgram.getCompilerSpec().getDefaultCallingConvention().encode(encoder,
            currentProgram.getCompilerSpec().getPcodeInjectLibrary());
        println("PROTOTYPE_SHA256=" + java.util.HexFormat.of().formatHex(java.security.MessageDigest
            .getInstance("SHA-256").digest(encoder.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8))));
        var manager = currentProgram.getDataTypeManager();
        var word = new LongLongDataType(manager);
        var real = new DoubleDataType(manager);
        var scalar = new FloatDataType(manager);
        var wide = new Integer16DataType(manager);
        var array = new StructureDataType("ArrayDoubles", 0, manager);
        array.add(new ArrayDataType(real, 2, 8, manager), "elements", null);
        var choice = new UnionDataType(CategoryPath.ROOT, "DoubleChoice", manager);
        choice.add(real, "value", null);
        var union = new StructureDataType("UnionDouble", 0, manager);
        union.add(choice, "first", null); union.add(real, "second", null);
        var box = new StructureDataType("DoubleBox", 0, manager);
        box.add(real, "value", null);
        var nested = new StructureDataType("NestedDouble", 0, manager);
        nested.add(box, "first", null); nested.add(real, "second", null);
        var floatBox = new StructureDataType("FloatBox", 0, manager);
        floatBox.add(scalar, "value", null);
        var small = new StructureDataType("SmallBytes", 0, manager);
        small.add(new ArrayDataType(new UnsignedCharDataType(manager), 3, 1, manager), "elements", null);
        var padded = new StructureDataType("Padded", 16, manager);
        padded.replaceAtOffset(0, scalar, 4, "first", null);
        padded.replaceAtOffset(8, real, 8, "second", null);
        var alignedPair = new StructureDataType("AlignedPair", 16, manager);
        alignedPair.replaceAtOffset(0, word, 8, "first", null);
        alignedPair.replaceAtOffset(8, word, 8, "second", null);
        alignedPair.setExplicitMinimumAlignment(16);
        var alignedMixed = new StructureDataType("AlignedMixed", 32, manager);
        alignedMixed.replaceAtOffset(0, real, 8, "first", null);
        alignedMixed.replaceAtOffset(8, word, 8, "second", null);
        alignedMixed.setExplicitMinimumAlignment(32);
        var image = ghidradwarfforge.elf.ElfImage.read(Path.of(currentProgram.getExecutablePath()));
        var policy = ghidradwarfforge.targets.TargetParameterAllocation.forProgram(currentProgram, image, monitor, this::println);
        var rows = new ArrayList<Object>();
        for (var entry : labels.entrySet()) {
            if (entry.getKey().endsWith("_body")) continue;
            var function = getFunctionAt(toAddr(Math.addExact(entry.getValue(), delta)));
            if (function == null) throw new IllegalStateException("no function " + entry);
            String name = entry.getKey();
            function.setName(name, SourceType.USER_DEFINED);
            DataType type = switch (name) {
                case "layout_array" -> array;
                case "layout_union" -> union;
                case "layout_nested" -> nested;
                case "layout_float_box" -> floatBox;
                case "layout_small" -> small;
                case "layout_padded" -> padded;
                case "layout_pair16", "layout_pair16_stack" -> alignedPair;
                case "layout_mixed32", "layout_mixed32_edge" -> alignedMixed;
                default -> wide;
            };
            var parameters = new ArrayList<Parameter>();
            if (name.equals("layout_aligned_stack") || name.equals("layout_pair16_stack")) {
                for (String parameter : List.of("a","b","c","d","e","f","g","h")) {
                    parameters.add(new ParameterImpl(parameter, word, currentProgram, SourceType.USER_DEFINED));
                }
            }
            if (name.equals("layout_mixed32_edge")) {
                for (String parameter : List.of("a","b","c","d","e","f","g")) {
                    parameters.add(new ParameterImpl(parameter, word, currentProgram, SourceType.USER_DEFINED));
                }
            }
            if (name.startsWith("layout_aligned") || name.startsWith("layout_pair16") || name.equals("layout_mixed32")) parameters.add(new ParameterImpl("lead", word, currentProgram, SourceType.USER_DEFINED));
            parameters.add(new ParameterImpl("value", type, currentProgram, SourceType.USER_DEFINED));
            parameters.add(new ParameterImpl("tail", word, currentProgram, SourceType.USER_DEFINED));
            function.updateFunction(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName(),
                new ReturnParameterImpl(VoidDataType.dataType, currentProgram), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                true, SourceType.USER_DEFINED, parameters.toArray(Parameter[]::new));
            var corrections = policy.corrections(function, monitor, this::println);
            var storage = new ArrayList<Object>();
            for (var parameter : function.getParameters()) {
                storage.add(Map.of("name", parameter.getName(), "type", parameter.getFormalDataType().getDisplayName(),
                    "size", parameter.getFormalDataType().getLength(), "alignment", parameter.getFormalDataType().getAlignment(),
                    "saved", parameter.getVariableStorage().toString(), "exported", corrections.getOrDefault(parameter.getOrdinal(), parameter.getVariableStorage()).toString()));
            }
            rows.add(Map.of("function", name, "parameters", storage));
        }
        Files.writeString(Path.of(args[1]), new com.google.gson.GsonBuilder().setPrettyPrinting().create().toJson(Map.of(
            "functions", rows, "language", currentProgram.getLanguageID().toString(),
            "compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString(),
            "pointerBytes", currentProgram.getDefaultPointerSize(),
            "delta", delta,
            "exporterOrigin", ghidradwarfforge.GhidraParameterAllocation.class.getProtectionDomain()
                .getCodeSource().getLocation().toString())) + "\n");
        println("MIPS_LAYOUT_PROBE_PASS");
    }
}
