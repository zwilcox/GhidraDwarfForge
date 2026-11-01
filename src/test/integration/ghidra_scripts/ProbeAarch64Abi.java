// Record effective AArch64 ABI storage from curated signatures and immutable reopen.
// @category DWARF.Tests

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.Integer16DataType;
import ghidra.program.model.data.SignedByteDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;

public class ProbeAarch64Abi extends GhidraScript {
    private DataType structure(String name, DataType element, int count, boolean curate) {
        var manager = currentProgram.getDataTypeManager();
        if (!curate) {
            DataType existing = manager.getDataType("/" + name);
            if (existing == null) throw new IllegalStateException("missing saved type " + name);
            return existing;
        }
        var type = new StructureDataType(name, 0, manager);
        String[] names = { "first", "second", "third", "fourth" };
        for (int index = 0; index < count; index++) type.add(element, names[index], null);
        return manager.addDataType(type, DataTypeConflictHandler.REPLACE_HANDLER);
    }

    private Object storage(Parameter parameter) {
        var result = new LinkedHashMap<String, Object>();
        var storage = parameter.getVariableStorage();
        result.put("name", parameter.getName());
        result.put("formalType", parameter.getFormalDataType().getDisplayName());
        result.put("effectiveType", parameter.getDataType().getDisplayName());
        result.put("formalBytes", parameter.getFormalDataType().getLength());
        result.put("effectiveBytes", parameter.getLength());
        result.put("storage", storage.toString());
        result.put("forcedIndirect", storage.isForcedIndirect());
        result.put("auto", parameter.isAutoParameter());
        result.put("autoKind", parameter.isAutoParameter() ? parameter.getAutoParameterType().name() : "");
        result.put("valid", storage.isValid());
        var nodes = new ArrayList<Object>();
        for (var node : storage.getVarnodes()) {
            var row = new LinkedHashMap<String, Object>();
            row.put("space", node.getAddress().getAddressSpace().getName());
            row.put("offset", node.getOffset());
            row.put("bytes", node.getSize());
            var register = currentProgram.getRegister(node);
            row.put("register", register == null ? "" : register.getName());
            nodes.add(row);
        }
        result.put("nodes", nodes);
        return result;
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3 || !(args[0].equals("curate") || args[0].equals("observe"))) {
            throw new IllegalArgumentException("expected curate|observe labels-file output-json");
        }
        boolean curate = args[0].equals("curate");
        long delta = currentProgram.getImageBase().getOffset() -
            ghidradwarfforge.GhidraImageBase.originalImageBase(currentProgram);
        var manager = currentProgram.getDataTypeManager();
        var word = new LongLongDataType(manager);
        var real = new DoubleDataType(manager);
        var wide = new Integer16DataType(manager);
        var tiny = new SignedByteDataType(manager);
        var half = new UnsignedShortDataType(manager);
        var integer = new IntegerDataType(manager);
        var pair = structure("AbiPair", word, 2, curate);
        var large = structure("AbiLarge", word, 3, curate);
        var hfa = structure("AbiHfa", new FloatDataType(manager), 4, curate);
        var labels = new LinkedHashMap<String, Long>();
        for (String line : Files.readAllLines(Path.of(args[1]))) {
            String[] fields = line.split(" ");
            if (fields.length != 2 || labels.put(fields[0], Long.decode(fields[1])) != null) {
                throw new IllegalArgumentException("invalid labels file");
            }
        }
        var result = new LinkedHashMap<String, Object>();
        result.put("language", currentProgram.getLanguageID().toString());
        result.put("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        result.put("pointerBytes", currentProgram.getDefaultPointerSize());
        result.put("delta", delta);
        result.put("exporterOrigin", ghidradwarfforge.GhidraTypeGraph.class.getProtectionDomain()
            .getCodeSource().getLocation().toURI().toString());
        String convention = currentProgram.getCompilerSpec().getDefaultCallingConvention().getName();
        result.put("convention", convention);
        var functions = new ArrayList<Object>();
        for (String name : List.of("abi_words", "abi_floats", "abi_pair", "abi_large",
                "abi_large_stack", "abi_large_spill", "abi_large_spill_alias", "abi_hfa", "abi_hfa_exhausted",
                "abi_narrow_stack", "abi_aligned_stack", "abi_aligned_register", "abi_pair_stack", "abi_pair_chain", "abi_pair_variadic")) {
            monitor.checkCancelled();
            Function function = getFunctionAt(toAddr(Math.addExact(labels.get(name), delta)));
            if (function == null) throw new IllegalStateException("missing function " + name);
            DataType returnType = switch (name) {
                case "abi_words", "abi_large_stack", "abi_narrow_stack", "abi_pair_stack", "abi_pair_chain", "abi_pair_variadic" -> word;
                case "abi_aligned_stack", "abi_aligned_register" -> wide;
                case "abi_floats", "abi_hfa_exhausted" -> real;
                case "abi_pair" -> pair;
                case "abi_large", "abi_large_spill", "abi_large_spill_alias" -> large;
                default -> hfa;
            };
            if (curate) {
                var parameters = new ArrayList<Parameter>();
                if (name.equals("abi_aligned_register")) {
                    parameters.add(new ParameterImpl("first", word, currentProgram, SourceType.USER_DEFINED));
                    parameters.add(new ParameterImpl("wide", wide, currentProgram, SourceType.USER_DEFINED));
                    parameters.add(new ParameterImpl("tail", word, currentProgram, SourceType.USER_DEFINED));
                }
                else if (name.equals("abi_narrow_stack") || name.equals("abi_aligned_stack") ||
                        name.equals("abi_pair_stack") || name.equals("abi_pair_chain") || name.equals("abi_pair_variadic")) {
                    int words = name.startsWith("abi_pair_") ? 7 : 8;
                    for (int index = 0; index < words; index++) {
                        parameters.add(new ParameterImpl(Character.toString('a' + index), word,
                            currentProgram, SourceType.USER_DEFINED));
                    }
                    String[] names = name.equals("abi_narrow_stack") ? new String[] {"low", "high", "middle", "wide"} :
                        name.equals("abi_aligned_stack") ? new String[] {"lead", "wide", "tail"} : new String[] {"value", "tail"};
                    DataType[] types = name.equals("abi_narrow_stack") ? new DataType[] {tiny, half, integer, word} :
                        name.equals("abi_aligned_stack") ? new DataType[] {tiny, wide, tiny} : new DataType[] {pair, word};
                    for (int index = 0; index < names.length; index++) {
                        parameters.add(new ParameterImpl(names[index], types[index], currentProgram, SourceType.USER_DEFINED));
                    }
                    if (name.equals("abi_pair_chain")) {
                        parameters.add(new ParameterImpl("wide", wide, currentProgram, SourceType.USER_DEFINED));
                        parameters.add(new ParameterImpl("object", large, currentProgram, SourceType.USER_DEFINED));
                        parameters.add(new ParameterImpl("floating", real, currentProgram, SourceType.USER_DEFINED));
                    }
                }
                else {
                    int scalars = name.equals("abi_words") || name.equals("abi_floats") ? 10 :
                        name.equals("abi_hfa_exhausted") ? 7 : name.equals("abi_large_stack") ? 8 : 0;
                    for (int index = 0; index < scalars; index++) {
                        parameters.add(new ParameterImpl(Character.toString('a' + index),
                            name.equals("abi_words") || name.equals("abi_large_stack") ? word : real,
                            currentProgram, SourceType.USER_DEFINED));
                    }
                    if (scalars < 10) parameters.add(new ParameterImpl("value",
                        name.equals("abi_hfa_exhausted") ? hfa : name.equals("abi_large_stack") ? large : returnType,
                        currentProgram, SourceType.USER_DEFINED));
                    if (name.equals("abi_hfa_exhausted")) parameters.add(new ParameterImpl("tail", real,
                        currentProgram, SourceType.USER_DEFINED));
                }
                function.setVarArgs(name.equals("abi_pair_variadic"));
                function.setName("curated_" + name, SourceType.USER_DEFINED);
                function.setReturnType(returnType, SourceType.USER_DEFINED);
                function.updateFunction(convention, function.getReturn(),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
                    parameters.toArray(Parameter[]::new));
            }
            var row = new LinkedHashMap<String, Object>();
            row.put("name", function.getName());
            row.put("entry", function.getEntryPoint().toString());
            row.put("signature", function.getPrototypeString(false, false));
            row.put("customStorage", function.hasCustomVariableStorage());
            row.put("return", storage(function.getReturn()));
            var parameters = new ArrayList<Object>();
            for (var parameter : function.getParameters()) parameters.add(storage(parameter));
            row.put("parameters", parameters);
            functions.add(row);
        }
        result.put("functions", functions);
        Files.writeString(Path.of(args[2]), new GsonBuilder().setPrettyPrinting().create().toJson(result) + "\n");
        println("AARCH64_ABI_OBSERVATION_PASS");
    }
}
