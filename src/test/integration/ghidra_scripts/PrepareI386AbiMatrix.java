// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;
import java.util.*;
import com.google.gson.GsonBuilder;

public class PrepareI386AbiMatrix extends GhidraScript {
    protected void run() throws Exception {
        boolean curate = getScriptArgs()[0].equals("curate");
        long delta = currentProgram.getImageBase().getOffset() - ghidradwarfforge.GhidraImageBase.originalImageBase(currentProgram);
        var labels = new HashMap<String, Long>();
        for (String line : Files.readAllLines(Path.of(getScriptArgs()[1]))) {
            var fields = line.split(" ");
            labels.put(fields[0], Long.decode(fields[1]));
        }
        var manager = currentProgram.getDataTypeManager();
        DataType integer = new IntegerDataType(manager), single = new FloatDataType(manager), real = new DoubleDataType(manager);
        DataType extended = new LongDoubleDataType(manager);
        var pair = new StructureDataType("Pair", 0, manager);
        pair.add(integer, "left", null);
        pair.add(integer, "right", null);
        var mixed = new StructureDataType("Mixed", 0, manager);
        mixed.add(integer, "code", null);
        mixed.add(real, "value", null);
        mixed.add(single, "fraction", null);
        DataType vector = new TypedefDataType(CategoryPath.ROOT, "AnalystFloatLanes4",
            new ArrayDataType(single, 4, 4, manager), manager);
        if (curate) {
            // Analyst-supplied fixture conventions: never installed into the product compiler spec.
            var extensions = new ghidra.program.database.SpecExtension((ghidra.program.database.ProgramDB)currentProgram);
            for (String convention : List.of("__sseregparm", "__stdcall", "__fastcall")) {
                String inputs = "";
                if (convention.equals("__sseregparm")) {
                    for (int i = 0; i < 3; i++) inputs += "<pentry minsize=\"4\" maxsize=\"8\" metatype=\"float\"><register name=\"XMM" + i + "\"/></pentry>";
                }
                else if (convention.equals("__fastcall")) {
                    for (String register : List.of("ECX", "EDX")) inputs += "<pentry minsize=\"1\" maxsize=\"4\"><register name=\"" + register + "\"/></pentry>";
                }
                inputs += "<pentry minsize=\"1\" maxsize=\"500\" align=\"4\"><addr offset=\"4\" space=\"stack\"/></pentry>";
                String output = convention.equals("__sseregparm")
                    ? "<pentry minsize=\"4\" maxsize=\"8\" metatype=\"float\"><register name=\"XMM0\"/></pentry>"
                    : "<pentry minsize=\"1\" maxsize=\"4\"><register name=\"EAX\"/></pentry>";
                extensions.addReplaceCompilerSpecExtension("<prototype name=\"" + convention + "\" extrapop=\"" +
                    (convention.equals("__sseregparm") ? "4" : "unknown") + "\" stackshift=\"4\"><input>" + inputs +
                    "</input><output killedbycall=\"true\">" + output + "</output><unaffected><register name=\"ESP\"/>" +
                    "<register name=\"EBP\"/><register name=\"EBX\"/><register name=\"ESI\"/><register name=\"EDI\"/>" +
                    "</unaffected><killedbycall><register name=\"EAX\"/><register name=\"ECX\"/><register name=\"EDX\"/>" +
                    "</killedbycall></prototype>", monitor);
            }
        }
        var rows = new ArrayList<Object>();
        for (String name : List.of("scalar_float","scalar_double","scalar_extended","pair_return","mixed_return","register_parameters","vector_add","sse_parameters","stdcall_parameters","fastcall_parameters","thiscall_parameters")) {
            var function = getFunctionAt(toAddr(labels.get(name) + delta));
            if (function == null) throw new AssertionError(name);
            if (curate) function.setName(name, SourceType.USER_DEFINED);
            String convention = switch(name) {
                case "register_parameters" -> "__regparm3";
                case "thiscall_parameters" -> "__thiscall";
                case "stdcall_parameters" -> "__stdcall";
                case "fastcall_parameters" -> "__fastcall";
                case "sse_parameters" -> "__sseregparm";
                default -> "__cdecl";
            };
            DataType returned = switch(name) {
                case "scalar_float" -> single;
                case "scalar_double" -> real;
                case "scalar_extended" -> extended;
                case "vector_add" -> vector;
                case "sse_parameters" -> real;
                case "pair_return" -> pair;
                case "mixed_return" -> mixed;
                default -> integer;
            };
            var parameters = new ArrayList<Parameter>();
            if (name.startsWith("scalar_")) {
                parameters.add(new ParameterImpl("a",returned,currentProgram));
                parameters.add(new ParameterImpl("b",returned,currentProgram));
            }
            else if (name.equals("pair_return")) {
                parameters.add(new ParameterImpl("value",pair,currentProgram));
                parameters.add(new ParameterImpl("tail",integer,currentProgram));
            }
            else if (name.equals("mixed_return")) {
                parameters.add(new ParameterImpl("leading",integer,currentProgram));
                parameters.add(new ParameterImpl("value",mixed,currentProgram));
                parameters.add(new ParameterImpl("tail",integer,currentProgram));
            }
            else if (name.equals("vector_add")) {
                for (int i = 0; i < 2; i++) parameters.add(new ParameterImpl(i == 0 ? "a" : "b", vector,
                    new VariableStorage(currentProgram, currentProgram.getRegister("XMM" + i)), currentProgram));
            }
            else if (name.equals("sse_parameters")) {
                for (int i = 0; i < 3; i++) parameters.add(new ParameterImpl(Character.toString('a' + i), real,
                    new VariableStorage(currentProgram, new ghidra.program.model.pcode.Varnode(
                        currentProgram.getRegister("XMM" + i).getAddress(), 8)), currentProgram));
            }
            else if (name.equals("thiscall_parameters")) {
                parameters.add(new ParameterImpl("object", new PointerDataType(pair, manager), currentProgram.getRegister("ECX"), currentProgram));
                parameters.add(new ParameterImpl("tail", integer, 4, currentProgram));
            }
            else if (name.equals("stdcall_parameters") || name.equals("fastcall_parameters")) {
                for (int i = 0; i < 3; i++) {
                    VariableStorage storage = name.equals("fastcall_parameters") && i < 2
                        ? new VariableStorage(currentProgram, currentProgram.getRegister(i == 0 ? "ECX" : "EDX"))
                        : new VariableStorage(currentProgram, 4 + 4 * (name.equals("fastcall_parameters") ? i - 2 : i), 4);
                    parameters.add(new ParameterImpl(Character.toString('a' + i), integer, storage, currentProgram));
                }
            }
            else for (String field : List.of("a","b","c","d")) parameters.add(new ParameterImpl(field,integer,currentProgram));
            boolean custom = Set.of("vector_add","sse_parameters","stdcall_parameters","fastcall_parameters","thiscall_parameters").contains(name);
            var result = custom ? new ReturnParameterImpl(returned, new VariableStorage(currentProgram,
                new ghidra.program.model.pcode.Varnode(currentProgram.getRegister(name.equals("vector_add") ||
                    name.equals("sse_parameters") ? "XMM0" : "EAX").getAddress(), returned.getLength())), currentProgram)
                : new ReturnParameterImpl(returned,currentProgram);
            if (curate) {
                function.updateFunction(convention, result,
                    custom ? Function.FunctionUpdateType.CUSTOM_STORAGE : Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    true, SourceType.USER_DEFINED, parameters.toArray(Parameter[]::new));
                if (name.equals("stdcall_parameters")) function.setStackPurgeSize(12);
                if (name.equals("fastcall_parameters") || name.equals("thiscall_parameters")) function.setStackPurgeSize(4);
            }
            var row = new LinkedHashMap<String,Object>();
            row.put("name",name);row.put("convention",function.getCallingConventionName());row.put("custom",function.hasCustomVariableStorage());row.put("body",function.getBody().toString());
            row.put("return",function.getReturn().getVariableStorage().toString());
            row.put("returnLength",returned.getLength());row.put("returnAlignedLength",returned.getAlignedLength());
            row.put("parameters",Arrays.stream(function.getParameters()).map(p -> Map.of("name",p.getName(),"type",p.getDataType().getPathName(),"size",p.getLength(),"storage",p.getVariableStorage().toString())).toList());
            rows.add(row);
        }
        Files.writeString(Path.of(getScriptArgs()[2]),new GsonBuilder().setPrettyPrinting().create().toJson(Map.of("delta",delta,"origin",ghidradwarfforge.GhidraTypeGraph.class.getProtectionDomain().getCodeSource().getLocation().toString(),"language",currentProgram.getLanguageID().toString(),"compiler",currentProgram.getCompilerSpec().getCompilerSpecID().toString(),"functions",rows)));
    }
}
