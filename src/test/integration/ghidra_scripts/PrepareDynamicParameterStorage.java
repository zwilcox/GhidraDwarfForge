// Curate ordinary dynamic int parameters without choosing registers or changing code.
// @category DWARF.Tests

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;

public class PrepareDynamicParameterStorage extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2 || !(args[0].equals("curate") || args[0].equals("inspect"))) {
            throw new IllegalArgumentException("expected curate|inspect labels-file");
        }
        var labels = new LinkedHashMap<String, Long>();
        for (String line : Files.readAllLines(Path.of(args[1]))) {
            String[] fields = line.split(" ");
            if (fields.length != 2 || labels.put(fields[0], Long.decode(fields[1])) != null) {
                throw new IllegalArgumentException("invalid fixture label");
            }
        }
        var type = new IntegerDataType(currentProgram.getDataTypeManager());
        String convention = currentProgram.getCompilerSpec().getDefaultCallingConvention().getName();
        var result = new LinkedHashMap<String, Object>();
        result.put("phase", args[0]);
        result.put("language", currentProgram.getLanguageID().toString());
        result.put("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        result.put("defaultCallingConvention", convention);
        result.put("exporterOrigin", ghidradwarfforge.GhidraVariableStorage.class
            .getProtectionDomain().getCodeSource().getLocation().toExternalForm());
        var functions = new ArrayList<Object>();
        for (String name : new String[] { "dynamic_keep", "dynamic_change" }) {
            monitor.checkCancelled();
            Function function = getFunctionAt(toAddr(labels.get(name)));
            if (function == null) {
                throw new IllegalStateException("analysis did not create " + name);
            }
            if (args[0].equals("curate")) {
                function.setName("curated_" + name, SourceType.USER_DEFINED);
                function.setReturnType(name.equals("dynamic_keep") ? VoidDataType.dataType : type,
                    SourceType.USER_DEFINED);
                function.updateFunction(convention, function.getReturn(),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
                    new ParameterImpl("first", type, currentProgram, SourceType.USER_DEFINED),
                    new ParameterImpl("second", type, currentProgram, SourceType.USER_DEFINED));
            }
            if (function.hasCustomVariableStorage() ||
                    !convention.equals(function.getCallingConventionName())) {
                throw new IllegalStateException("function does not retain dynamic default storage");
            }
            var row = new LinkedHashMap<String, Object>();
            row.put("name", function.getName());
            row.put("entry", function.getEntryPoint().toString());
            row.put("signature", function.getPrototypeString(false, false));
            row.put("signatureSource", function.getSignatureSource().name());
            row.put("callingConvention", function.getCallingConventionName());
            row.put("customStorage", function.hasCustomVariableStorage());
            row.put("returnType", function.getReturnType().getDisplayName());
            var ranges = new ArrayList<Object>();
            var iterator = function.getBody().getAddressRanges();
            while (iterator.hasNext()) {
                var range = iterator.next();
                ranges.add(new String[] { range.getMinAddress().toString(),
                    range.getMaxAddress().add(1).toString() });
            }
            row.put("ranges", ranges);
            var parameters = new ArrayList<Object>();
            for (var parameter : function.getParameters()) {
                var storage = parameter.getVariableStorage();
                var register = parameter.getRegister();
                var value = new LinkedHashMap<String, Object>();
                value.put("name", parameter.getName());
                value.put("type", parameter.getDataType().getDisplayName());
                value.put("source", parameter.getSource().name());
                value.put("hasAssignedStorage", parameter.hasAssignedStorage());
                value.put("storage", storage.toString());
                value.put("storageValid", storage.isValid());
                value.put("storageBad", storage.isBadStorage());
                value.put("storageUnassigned", storage.isUnassignedStorage());
                value.put("storageForcedIndirect", storage.isForcedIndirect());
                value.put("storageRegister", storage.isRegisterStorage());
                value.put("storageStack", storage.isStackStorage());
                value.put("byteSize", storage.size());
                value.put("register", register == null ? null : register.getName());
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
                instructions.add(item);
            }
            row.put("instructions", instructions);
            functions.add(row);
        }
        if (args[0].equals("curate")) {
            for (String name : new String[] { "dynamic_first", "dynamic_second", "dynamic_before", "dynamic_after" }) {
                var address = toAddr(labels.get(name));
                DataUtilities.createData(currentProgram, address, type, type.getLength(),
                    DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
                currentProgram.getSymbolTable().createLabel(address, name, SourceType.USER_DEFINED).setPrimary();
            }
        }
        result.put("functions", functions);
        println("DYNAMIC_PARAMETER_STORAGE=" + new GsonBuilder().serializeNulls().create().toJson(result));
    }
}
