// Curate dynamic arguments, then retain their exact Ghidra joins when enabling custom storage.
// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraTargetAgreement;
import ghidradwarfforge.elf.ElfImage;

public class PrepareDynamicCompositeStorage extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3 || !(args[0].equals("natural") || args[0].equals("curate") || args[0].equals("inspect") || args[0].equals("custom") || args[0].equals("reopen-custom"))) {
            throw new IllegalArgumentException("expected natural|curate|inspect|custom|reopen-custom labels output");
        }
        var labels = new LinkedHashMap<String, Long>();
        for (String line : Files.readAllLines(Path.of(args[1]))) {
            String[] fields = line.split(" ");
            if (fields.length != 2 || labels.put(fields[0], Long.decode(fields[1])) != null) {
                throw new IllegalArgumentException("invalid label");
            }
        }
        var result = new LinkedHashMap<String, Object>();
        result.put("phase", args[0]);
        result.put("language", currentProgram.getLanguageID().toString());
        result.put("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        result.put("pointerBytes", currentProgram.getDefaultPointerSize());
        result.put("imageBase", currentProgram.getImageBase().toString());
        result.put("executablePath", currentProgram.getExecutablePath());
        result.put("javaVersion", System.getProperty("java.version"));
        result.put("exporterOrigin", GhidraTargetAgreement.class.getProtectionDomain().getCodeSource().getLocation().toExternalForm());
        String convention = currentProgram.getCompilerSpec().getDefaultCallingConvention().getName();
        result.put("defaultCallingConvention", convention);
        var elf = ElfImage.read(Path.of(currentProgram.getExecutablePath()));
        result.put("elfFlags", Long.toUnsignedString(elf.flags(), 16));
        try {
            result.put("forgeTargetAgreement", GhidraTargetAgreement.requireAgreement(currentProgram, elf).toString());
        }
        catch (IllegalStateException | IllegalArgumentException failure) {
            result.put("forgeTargetAgreementFailure", failure.getClass().getName() + ": " + failure.getMessage());
        }
        var registers = new LinkedHashMap<String, Object>();
        for (String name : new String[] { "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "sp" }) {
            var register = currentProgram.getRegister(name);
            registers.put(name, register == null ? null : register.getBitLength());
        }
        result.put("registerBits", registers);
        var type = new IntegerDataType(currentProgram.getDataTypeManager());
        ghidra.program.model.data.DataType pair = currentProgram.getDataTypeManager().getDataType("/Analyst/RecoveredPair");
        if (args[0].equals("curate")) {
            var structure = new ghidra.program.model.data.StructureDataType(
                new ghidra.program.model.data.CategoryPath("/Analyst"), "RecoveredPair", 0,
                currentProgram.getDataTypeManager());
            structure.add(type, "first", "analyst field");
            structure.add(type, "second", "analyst field");
            pair = currentProgram.getDataTypeManager().resolve(structure,
                ghidra.program.model.data.DataTypeConflictHandler.DEFAULT_HANDLER);
        }
        result.put("aggregateBytes", pair == null ? null : pair.getLength());
        if (args[0].equals("curate")) {
            for (String name : new String[] { "observed_first", "observed_second", "observed_scalar" }) {
                var address = toAddr(labels.get(name));
                ghidra.program.model.data.DataType dataType = name.equals("observed_scalar") ?
                    new UnsignedLongLongDataType(currentProgram.getDataTypeManager()) : type;
                DataUtilities.createData(currentProgram, address, dataType, dataType.getLength(), DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
                currentProgram.getSymbolTable().createLabel(address, name, SourceType.USER_DEFINED).setPrimary();
            }
        }
        var functions = new ArrayList<Object>();
        for (String name : new String[] { "capture_pair", "capture_scalar" }) {
            monitor.checkCancelled();
            Function function = getFunctionAt(toAddr(labels.get(name)));
            var row = new LinkedHashMap<String, Object>();
            row.put("compilerName", name);
            row.put("present", function != null);
            if (function == null) {
                if (!args[0].equals("natural")) {
                    throw new IllegalStateException("analysis did not create " + name);
                }
                functions.add(row);
                continue;
            }
            if (args[0].equals("curate")) {
                function.setName("curated_" + name, SourceType.USER_DEFINED);
                function.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
                var parameters = new ArrayList<ParameterImpl>();
                parameters.add(new ParameterImpl("value", name.equals("capture_pair") ? pair :
                    new UnsignedLongLongDataType(currentProgram.getDataTypeManager()), currentProgram, SourceType.USER_DEFINED));
                function.updateFunction(convention, function.getReturn(), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    true, SourceType.USER_DEFINED, parameters.toArray(new ParameterImpl[0]));
            }
            if (args[0].equals("custom")) {
                if (function.hasCustomVariableStorage()) {
                    throw new IllegalStateException("custom conversion would be vacuous");
                }
                function.setCustomVariableStorage(true);
            }
            if (args[0].equals("reopen-custom") && !function.hasCustomVariableStorage()) {
                throw new IllegalStateException("custom storage did not survive reopening");
            }
            row.put("name", function.getName());
            row.put("functionClass", function.getClass().getName());
            row.put("entry", function.getEntryPoint().toString());
            row.put("signature", function.getPrototypeString(false, false));
            row.put("signatureSource", function.getSignatureSource().name());
            var ranges = new ArrayList<Object>();
            var rangeIterator = function.getBody().getAddressRanges();
            while (rangeIterator.hasNext()) {
                var range = rangeIterator.next();
                ranges.add(java.util.List.of(range.getMinAddress().toString(),
                    range.getMaxAddress().add(1).toString()));
            }
            row.put("ranges", ranges);
            row.put("callingConvention", function.getCallingConventionName());
            row.put("customStorage", function.hasCustomVariableStorage());
            row.put("returnType", function.getReturnType().getDisplayName());
            var parameters = new ArrayList<Object>();
            for (var parameter : function.getParameters()) {
                var storage = parameter.getVariableStorage();
                var register = parameter.getRegister();
                var value = new LinkedHashMap<String, Object>();
                value.put("name", parameter.getName());
                value.put("parameterClass", parameter.getClass().getName());
                value.put("ordinal", parameter.getOrdinal());
                value.put("ownerIsFunction", parameter.getFunction() == function);
                value.put("isAttachedParameter", function.getParameter(parameter.getOrdinal()) == parameter);
                value.put("type", parameter.getDataType().getDisplayName());
                if (parameter.getDataType() instanceof ghidra.program.model.data.Structure parameterStructure) {
                    var fields = new ArrayList<Object>();
                    for (var field : parameterStructure.getDefinedComponents()) {
                        fields.add(java.util.Map.of("name", field.getFieldName(), "offset", field.getOffset(),
                            "bytes", field.getLength(), "type", field.getDataType().getDisplayName()));
                    }
                    value.put("fields", fields);
                }
                value.put("source", parameter.getSource().name());
                value.put("hasAssignedStorage", parameter.hasAssignedStorage());
                value.put("storage", storage.toString());
                value.put("storageSerialization", storage.getSerializationString());
                value.put("storageClass", storage.getClass().getName());
                value.put("storageValid", storage.isValid());
                value.put("storageBad", storage.isBadStorage());
                value.put("storageUnassigned", storage.isUnassignedStorage());
                value.put("storageForcedIndirect", storage.isForcedIndirect());
                value.put("storageRegister", storage.isRegisterStorage());
                value.put("storageStack", storage.isStackStorage());
                value.put("byteSize", storage.size());
                value.put("register", register == null ? null : register.getName());
                value.put("registerBits", register == null ? null : register.getBitLength());
                var nodes = new ArrayList<Object>();
                for (var node : storage.getVarnodes()) {
                    var fields = new LinkedHashMap<String, Object>();
                    fields.put("space", node.getAddress().getAddressSpace().getName());
                    fields.put("address", node.getAddress().toString());
                    fields.put("size", node.getSize());
                    nodes.add(fields);
                }
                value.put("varnodes", nodes);
                parameters.add(value);
            }
            row.put("parameters", parameters);
            var instructions = new ArrayList<Object>();
            var listing = currentProgram.getListing().getInstructions(function.getBody(), true);
            while (listing.hasNext()) {
                monitor.checkCancelled();
                var instruction = listing.next();
                var item = new LinkedHashMap<String, Object>();
                item.put("address", instruction.getAddress().toString());
                item.put("length", instruction.getLength());
                item.put("text", instruction.toString());
                var stores = new ArrayList<Object>();
                for (var operation : instruction.getPcode()) {
                    if (operation.getOpcode() != ghidra.program.model.pcode.PcodeOp.STORE) {
                        continue;
                    }
                    var store = new LinkedHashMap<String, Object>();
                    store.put("inputCount", operation.getNumInputs());
                    store.put("hasOutput", operation.getOutput() != null);
                    store.put("constantSelector", operation.getInput(0).isConstant());
                    var space = currentProgram.getAddressFactory().getAddressSpace(
                        (int) operation.getInput(0).getOffset());
                    store.put("space", space.getName());
                    store.put("memorySpace", space.isMemorySpace());
                    store.put("pointerBytes", space.getPointerSize());
                    store.put("addressBytes", operation.getInput(1).getSize());
                    store.put("valueBytes", operation.getInput(2).getSize());
                    stores.add(store);
                }
                item.put("stores", stores);
                instructions.add(item);
            }
            row.put("instructions", instructions);
            if (!args[0].equals("natural") && name.equals("capture_pair")) {
                var decompiler = new DecompInterface();
                try {
                    if (!decompiler.openProgram(currentProgram)) {
                        throw new IllegalStateException(decompiler.getLastMessage());
                    }
                    var decompiled = decompiler.decompileFunction(function, 30, monitor);
                    if (!decompiled.decompileCompleted() || decompiled.getHighFunction() == null ||
                            decompiled.getDecompiledFunction() == null) {
                        throw new IllegalStateException(decompiled.getErrorMessage());
                    }
                    row.put("decompilerMessage", decompiled.getErrorMessage());
                    row.put("decompiledC", decompiled.getDecompiledFunction().getC());
                    var high = decompiled.getHighFunction().getLocalSymbolMap().getParamSymbol(0);
                    row.put("highParameterType", high.getDataType().getPathName());
                    row.put("highParameterStorage", high.getStorage().toString());
                    row.put("highParameterStorageSerialization", high.getStorage().getSerializationString());
                }
                finally {
                    decompiler.dispose();
                }
            }
            functions.add(row);
        }
        result.put("functions", functions);
        String json = new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(result);
        Files.writeString(Path.of(args[2]), json + "\n", StandardOpenOption.CREATE_NEW);
        println("DYNAMIC_COMPOSITE_OBSERVATION_PASS " + args[0] + " " + currentProgram.getLanguageID());
    }
}
