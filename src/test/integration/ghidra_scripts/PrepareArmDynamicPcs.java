// Applies per-function named dynamic PCS; records effective storage without custom storage.
// @category DWARF.Tests

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;

public class PrepareArmDynamicPcs extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2 || !(args[0].equals("curate") || args[0].equals("inspect"))) {
            throw new IllegalArgumentException("expected curate|inspect labels-file");
        }
        var labels = new LinkedHashMap<String, Long>();
        for (String line : Files.readAllLines(Path.of(args[1]))) {
            String[] parts = line.split(" ");
            if (parts.length != 2 || labels.put(parts[0], Long.decode(parts[1])) != null) {
                throw new IllegalArgumentException("invalid fixture label");
            }
        }
        var type = new FloatDataType(currentProgram.getDataTypeManager());
        var result = new LinkedHashMap<String, Object>();
        result.put("phase", args[0]);
        result.put("language", currentProgram.getLanguageID().toString());
        result.put("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        result.put("exporterOrigin", ghidradwarfforge.GhidraVariableStorage.class
            .getProtectionDomain().getCodeSource().getLocation().toExternalForm());
        var records = new ArrayList<Object>();
        for (String name : new String[] { "base_probe", "vfp_probe", "vfp_sum" }) {
            monitor.checkCancelled();
            Function function = getFunctionAt(toAddr(labels.get(name)));
            if (function == null) {
                throw new IllegalStateException("no function at " + name);
            }
            String convention = name.equals("base_probe") ? "__stdcall_softfp" : "__stdcall";
            if (args[0].equals("curate")) {
                function.setName("curated_" + name, SourceType.USER_DEFINED);
                function.setReturnType(name.equals("vfp_sum") ? type : VoidDataType.dataType,
                    SourceType.USER_DEFINED);
                function.updateFunction(convention, function.getReturn(),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
                    new ParameterImpl("first", type, currentProgram, SourceType.USER_DEFINED),
                    new ParameterImpl("second", type, currentProgram, SourceType.USER_DEFINED));
            }
            if (function.hasCustomVariableStorage() ||
                    !function.getCallingConventionName().equals(convention)) {
                throw new IllegalStateException("fixture does not use the selected dynamic convention");
            }
            var row = new LinkedHashMap<String, Object>();
            row.put("entry", function.getEntryPoint().toString());
            row.put("name", function.getName());
            row.put("signature", function.getPrototypeString(false, false));
            row.put("signatureSource", function.getSignatureSource().name());
            row.put("callingConvention", function.getCallingConventionName());
            row.put("customStorage", function.hasCustomVariableStorage());
            row.put("returnType", function.getReturnType().getDisplayName());
            row.put("returnStorage", function.getReturn().getVariableStorage().toString());
            row.put("bodyStart", function.getBody().getMinAddress().toString());
            row.put("bodyEnd", function.getBody().getMaxAddress().add(1).toString());
            row.put("bodyRanges", function.getBody().getNumAddressRanges());
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
            var last = currentProgram.getListing().getInstructionContaining(function.getBody().getMaxAddress());
            if (last == null) {
                throw new IllegalStateException("fixture has no terminal instruction");
            }
            var terminal = new LinkedHashMap<String, Object>();
            terminal.put("address", last.getAddress().toString());
            terminal.put("instruction", last.toString());
            terminal.put("terminal", last.getFlowType().isTerminal());
            terminal.put("jump", last.getFlowType().isJump());
            terminal.put("fallThrough", last.getFallThrough() == null ? null : last.getFallThrough().toString());
            var operations = new ArrayList<Object>();
            for (var op : last.getPcode()) {
                var operation = new LinkedHashMap<String, Object>();
                operation.put("pcode", op.toString());
                if (op.getOpcode() == PcodeOp.CALLOTHER) {
                    operation.put("userop", currentProgram.getLanguage().getUserDefinedOpName(
                        Math.toIntExact(op.getInput(0).getOffset())));
                }
                operations.add(operation);
            }
            terminal.put("operations", operations);
            row.put("lastInstruction", terminal);
            records.add(row);
        }
        if (args[0].equals("curate")) {
            for (String name : new String[] { "base_first", "base_second", "vfp_first", "vfp_second", "sum_value" }) {
                var address = toAddr(labels.get(name));
                DataUtilities.createData(currentProgram, address, type, 4,
                    DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
                currentProgram.getSymbolTable().createLabel(address, name, SourceType.USER_DEFINED).setPrimary();
            }
        }
        result.put("functions", records);
        println("ARM_DYNAMIC_PCS=" + new GsonBuilder().serializeNulls().create().toJson(result));
    }
}
