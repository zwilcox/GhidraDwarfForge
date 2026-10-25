// Observe the curated formal return and naturally allocated hidden ABI parameter.
// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraTypeGraph;

public class PrepareReturnTriple extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3 || !(args[0].equals("natural") || args[0].equals("curate") || args[0].equals("reopen"))) {
            throw new IllegalArgumentException("natural|curate|reopen labels output required");
        }
        var labels = new LinkedHashMap<String, Long>();
        for (String line : Files.readAllLines(Path.of(args[1]))) {
            String[] parts = line.split(" ");
            if (parts.length != 2 || labels.put(parts[0], Long.decode(parts[1])) != null) {
                throw new IllegalArgumentException("invalid label record");
            }
        }
        Function function = getFunctionAt(toAddr(labels.get("make_result")));
        if (function == null) { throw new IllegalStateException("natural analysis did not create make_result"); }
        String convention = currentProgram.getCompilerSpec().getDefaultCallingConvention().getName();
        if (args[0].equals("curate")) {
            var manager = currentProgram.getDataTypeManager();
            var word = new UnsignedLongLongDataType(manager);
            var shape = new StructureDataType(new CategoryPath("/Analyst"), "RecoveredReturnTriple", 0, manager);
            for (String name : new String[] { "first", "second", "third" }) { shape.add(word, name, "analyst field"); }
            DataType triple = manager.resolve(shape, DataTypeConflictHandler.DEFAULT_HANDLER);
            if (triple.getLength() != 24) { throw new IllegalStateException("unexpected aggregate size"); }
            function.setName("curated_make_result", SourceType.USER_DEFINED);
            function.setReturnType(triple, SourceType.USER_DEFINED);
            function.updateFunction(convention, function.getReturn(), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                true, SourceType.USER_DEFINED,
                new ParameterImpl("seed", word, currentProgram, SourceType.USER_DEFINED),
                new ParameterImpl("delta", new IntegerDataType(manager), currentProgram, SourceType.USER_DEFINED));
            for (String name : new String[] { "observed_first", "observed_second", "observed_third" }) {
                var address = toAddr(labels.get(name));
                DataUtilities.createData(currentProgram, address, word, 8, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
                currentProgram.getSymbolTable().createLabel(address, name, SourceType.USER_DEFINED).setPrimary();
            }
        }
        if (function.hasCustomVariableStorage()) { throw new IllegalStateException("unexpected custom storage"); }
        var result = new LinkedHashMap<String, Object>();
        result.put("phase", args[0]);
        result.put("javaVersion", System.getProperty("java.version"));
        result.put("exporterOrigin", GhidraTypeGraph.class.getProtectionDomain().getCodeSource().getLocation().toExternalForm());
        result.put("executablePath", currentProgram.getExecutablePath());
        result.put("language", currentProgram.getLanguageID().toString());
        result.put("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        result.put("defaultConvention", convention);
        result.put("pointerBytes", currentProgram.getDefaultPointerSize());
        result.put("name", function.getName());
        result.put("entry", function.getEntryPoint().toString());
        result.put("signature", function.getSignature().getPrototypeString());
        result.put("signatureSource", function.getSignatureSource().name());
        result.put("callingConvention", function.getCallingConventionName());
        result.put("customStorage", function.hasCustomVariableStorage());
        result.put("getReturnType", type(function.getReturnType(), 0));
        result.put("return", parameter(function.getReturn()));
        var parameters = new ArrayList<Object>();
        for (Parameter parameter : function.getParameters()) {
            monitor.checkCancelled();
            var row = parameter(parameter);
            DataType formal = parameter.getFormalDataType();
            row.put("pointsToFormalReturn", formal instanceof Pointer pointer && pointer.getDataType() == function.getReturn().getFormalDataType());
            parameters.add(row);
        }
        result.put("parameters", parameters);
        var ranges = new ArrayList<Object>();
        var rangeIterator = function.getBody().getAddressRanges();
        while (rangeIterator.hasNext()) {
            var range = rangeIterator.next();
            ranges.add(java.util.List.of(range.getMinAddress().toString(), range.getMaxAddress().next().toString()));
        }
        result.put("ranges", ranges);
        var instructions = new ArrayList<Object>();
        var iterator = currentProgram.getListing().getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            var instruction = iterator.next();
            var row = new LinkedHashMap<String, Object>();
            row.put("address", instruction.getAddress().toString());
            row.put("length", instruction.getLength());
            row.put("bytes", java.util.HexFormat.of().formatHex(instruction.getBytes()));
            row.put("text", instruction.toString());
            row.put("flow", instruction.getFlowType().toString());
            row.put("fallthrough", instruction.getFallThrough() == null ? null : instruction.getFallThrough().toString());
            row.put("lengthOverride", instruction.isLengthOverridden());
            row.put("flowOverride", instruction.getFlowOverride().toString());
            var operations = new ArrayList<Object>();
            for (var op : instruction.getPcode()) {
                var operation = new LinkedHashMap<String, Object>();
                operation.put("opcode", op.getMnemonic());
                operation.put("output", node(op.getOutput()));
                var inputs = new ArrayList<Object>();
                for (var input : op.getInputs()) { inputs.add(node(input)); }
                operation.put("inputs", inputs);
                operations.add(operation);
            }
            row.put("pcode", operations);
            instructions.add(row);
        }
        result.put("instructions", instructions);
        var decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) { throw new IllegalStateException(decompiler.getLastMessage()); }
            var decompiled = decompiler.decompileFunction(function, 30, monitor);
            result.put("decompileCompleted", decompiled.decompileCompleted());
            result.put("decompilerError", decompiled.getErrorMessage());
            result.put("decompiledC", decompiled.getDecompiledFunction() == null ? null : decompiled.getDecompiledFunction().getC());
            if (decompiled.getHighFunction() != null) {
                var highParameters = new ArrayList<Object>();
                for (int i = 0; i < decompiled.getHighFunction().getLocalSymbolMap().getNumParams(); i++) {
                    var symbol = decompiled.getHighFunction().getLocalSymbolMap().getParamSymbol(i);
                    if (symbol == null) { highParameters.add(null); continue; }
                    var row = new LinkedHashMap<String, Object>();
                    row.put("name", symbol.getName());
                    row.put("type", type(symbol.getDataType(), 0));
                    row.put("storage", symbol.getStorage().getSerializationString());
                    highParameters.add(row);
                }
                result.put("highParameters", highParameters);
            }
        }
        finally { decompiler.dispose(); }
        Files.writeString(Path.of(args[2]), new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(result) + "\n", StandardOpenOption.CREATE_NEW);
        println("RETURN_TRIPLE_OBSERVATION " + args[0]);
    }

    private LinkedHashMap<String, Object> parameter(Parameter parameter) {
        var result = new LinkedHashMap<String, Object>();
        var storage = parameter.getVariableStorage();
        result.put("name", parameter.getName());
        result.put("class", parameter.getClass().getName());
        result.put("ordinal", parameter.getOrdinal());
        result.put("source", parameter.getSource().name());
        result.put("formal", type(parameter.getFormalDataType(), 0));
        result.put("effective", type(parameter.getDataType(), 0));
        result.put("forcedIndirect", parameter.isForcedIndirect());
        result.put("auto", parameter.isAutoParameter());
        result.put("autoKind", parameter.getAutoParameterType() == null ? null : parameter.getAutoParameterType().name());
        result.put("hasAssignedStorage", parameter.hasAssignedStorage());
        result.put("storage", storage.getSerializationString());
        result.put("storageClass", storage.getClass().getName());
        result.put("storageValid", storage.isValid());
        result.put("storageBad", storage.isBadStorage());
        result.put("storageUnassigned", storage.isUnassignedStorage());
        result.put("storageForcedIndirect", storage.isForcedIndirect());
        var nodes = new ArrayList<Object>();
        for (var node : storage.getVarnodes()) {
            var row = new LinkedHashMap<String, Object>();
            row.put("space", node.getAddress().getAddressSpace().getName());
            row.put("address", node.getAddress().toString());
            row.put("bytes", node.getSize());
            var register = currentProgram.getRegister(node);
            row.put("register", register == null ? null : register.getName());
            nodes.add(row);
        }
        result.put("varnodes", nodes);
        return result;
    }

    private Object type(DataType dataType, int depth) {
        if (dataType == null) { return null; }
        var result = new LinkedHashMap<String, Object>();
        result.put("name", dataType.getDisplayName());
        result.put("path", dataType.getPathName());
        result.put("class", dataType.getClass().getName());
        result.put("bytes", dataType.getLength());
        if (depth < 3 && dataType instanceof Pointer pointer) { result.put("pointee", type(pointer.getDataType(), depth + 1)); }
        if (depth < 3 && dataType instanceof Structure structure) {
            var fields = new ArrayList<Object>();
            for (var component : structure.getDefinedComponents()) {
                fields.add(java.util.Map.of("name", component.getFieldName(), "offset", component.getOffset(),
                    "bytes", component.getLength(), "type", type(component.getDataType(), depth + 1)));
            }
            result.put("fields", fields);
        }
        return result;
    }

    private Object node(ghidra.program.model.pcode.Varnode node) {
        if (node == null) { return null; }
        return java.util.Map.of("space", node.getAddress().getAddressSpace().getName(), "offset", node.getOffset(), "bytes", node.getSize());
    }
}
