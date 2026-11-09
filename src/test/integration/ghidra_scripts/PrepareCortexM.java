// Explicit source-fixture knowledge, never automatic production recovery.
// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Map;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;

public class PrepareCortexM extends HeadlessScript {
    @Override
    protected void run() throws Exception {
        if (getScriptArgs().length != 2 ||
                !currentProgram.getLanguageID().toString().equals("ARM:LE:32:Cortex") ||
                !currentProgram.getCompilerSpec().getCompilerSpecID().toString().equals("default")) {
            throw new IllegalArgumentException("expected Cortex/default plus manifest and receipt paths");
        }
        var manifest = new Gson().fromJson(Files.readString(Path.of(getScriptArgs()[0])), JsonObject.class);
        // Initial analysis has completed. Keep subsequent no-return propagation
        // from replacing analyst-selected bodies after this script's receipt.
        enableHeadlessAnalysis(false);
        var manager = currentProgram.getFunctionManager();
        // Trim known function bodies first, so the adjacent Default_Handler
        // does not remain incorrectly owned by the non-returning PSP entry.
        for (var element : manifest.getAsJsonArray("functions")) {
            var row = element.getAsJsonObject();
            var entry = toAddr(row.get("entry").getAsLong());
            var body = body(row);
            var function = manager.getFunctionAt(entry);
            if (function != null) function.setBody(body);
        }
        var integer = IntegerDataType.dataType;
        var unsigned = UnsignedIntegerDataType.dataType;
        var records = new ArrayList<Object>();
        for (var element : manifest.getAsJsonArray("functions")) {
            monitor.checkCancelled();
            var row = element.getAsJsonObject();
            String name = row.get("name").getAsString();
            var entry = toAddr(row.get("entry").getAsLong());
            var body = body(row);
            var mode = currentProgram.getProgramContext().getValue(currentProgram.getRegister("TMode"), entry, false);
            if (!java.math.BigInteger.ONE.equals(mode)) throw new AssertionError("not Thumb: " + name);
            var function = manager.getFunctionAt(entry);
            if (function == null) {
                clearListing(body.getMinAddress(), body.getMaxAddress());
                if (!new DisassembleCommand(entry, body, true).applyTo(currentProgram, monitor)) {
                    throw new AssertionError("cannot decode " + name);
                }
                function = manager.createFunction(name, entry, body, SourceType.USER_DEFINED);
            }
            if (function == null) throw new AssertionError("missing function " + name);
            function.setName(name, SourceType.USER_DEFINED);
            function.setBody(body);
            function.setThunkedFunction(null);
            // Compiler Thumb mapping regions can contain an unvisited alignment
            // NOP after a terminal branch. Decode every byte explicitly retained
            // in this fixture body; literal pools are excluded by the manifest.
            var cursor = entry;
            while (body.contains(cursor)) {
                var instruction = currentProgram.getListing().getInstructionAt(cursor);
                if (instruction == null) {
                    if (!new DisassembleCommand(cursor, body, false).applyTo(currentProgram, monitor)) {
                        throw new AssertionError("undecodable compiler Thumb mapping at " + cursor);
                    }
                    instruction = currentProgram.getListing().getInstructionAt(cursor);
                }
                if (instruction == null) throw new AssertionError("missing decoded instruction at " + cursor);
                cursor = cursor.add(instruction.getLength());
            }
            var parameters = new ArrayList<Parameter>();
            DataType result = DataType.VOID;
            if (name.equals("cortex_compute")) {
                result = integer;
                parameters.add(new ParameterImpl("input", integer, currentProgram));
            }
            if (name.equals("cortex_svc_body")) {
                parameters.add(new ParameterImpl("frame", new PointerDataType(unsigned), currentProgram));
                parameters.add(new ParameterImpl("exception_return", unsigned, currentProgram));
                parameters.add(new ParameterImpl("number", unsigned, currentProgram));
            }
            function.updateFunction(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName(),
                new ReturnParameterImpl(result, currentProgram), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                true, SourceType.USER_DEFINED, parameters.toArray(Parameter[]::new));
            function.setNoReturn(java.util.Set.of("Reset_Handler", "Default_Handler", "cortex_main",
                "cortex_psp_main", "cortex_psp_entry").contains(name));
            if (name.equals("cortex_compute")) {
                boolean localFound = false;
                for (var local : function.getLocalVariables()) {
                    if (local.isStackVariable() && local.getStackOffset() == -12) {
                        local.setName("local", SourceType.USER_DEFINED);
                        local.setDataType(integer, SourceType.USER_DEFINED);
                        localFound = true;
                    }
                }
                if (!localFound) throw new AssertionError("analysis did not retain the independently verified stack local");
            }
            if (!function.getBody().equals(body)) throw new AssertionError("body changed: " + name);
            var instructions = currentProgram.getListing().getInstructions(body, true);
            long decoded = 0;
            while (instructions.hasNext()) {
                var instruction = instructions.next();
                if (!java.math.BigInteger.ONE.equals(currentProgram.getProgramContext().getValue(
                        currentProgram.getRegister("TMode"), instruction.getAddress(), false))) {
                    throw new AssertionError("ARM state in " + name);
                }
                decoded += instruction.getLength();
            }
            if (decoded != body.getNumAddresses()) throw new AssertionError("incomplete body: " + name);
            records.add(Map.of("name", name, "entry", entry.getOffset(), "body", body.toString(),
                "decodedBytes", decoded, "signature", function.getSignature().getPrototypeString()));
        }
        var callable = new FunctionDefinitionDataType("cortex_compute_type");
        callable.setReturnType(integer);
        callable.setArguments(new ParameterDefinition[] {new ParameterDefinitionImpl("input", integer, null)});
        for (var element : manifest.getAsJsonArray("literalPools")) {
            var range = element.getAsJsonArray();
            long start = range.get(0).getAsLong();
            long end = range.get(1).getAsLong();
            if ((start & 3) != 0 || (end - start) % 4 != 0 || end <= start) {
                throw new AssertionError("invalid fixture literal pool");
            }
            clearListing(toAddr(start), toAddr(end - 1));
            createData(toAddr(start), new ArrayDataType(unsigned, Math.toIntExact((end - start) / 4), 4));
        }
        for (var element : manifest.getAsJsonArray("objects")) {
            var row = element.getAsJsonObject();
            String name = row.get("name").getAsString();
            DataType type = name.equals("cortex_function_pointer") ? new PointerDataType(callable) :
                java.util.Set.of("cortex_initialized", "cortex_result", "cortex_bss_counter").contains(name) ? integer : unsigned;
            int size = row.get("size").getAsInt();
            if (java.util.Set.of("cortex_byte_pad", "cortex_odd_byte").contains(name)) {
                if (size != 1) throw new AssertionError("unexpected byte object size");
                type = UnsignedCharDataType.dataType;
            }
            else if (size != 4) throw new AssertionError("unexpected object size");
            var address = toAddr(row.get("address").getAsLong());
            DataUtilities.createData(currentProgram, address, type, size, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
            currentProgram.getSymbolTable().createLabel(address, name, SourceType.USER_DEFINED).setPrimary();
        }
        clearListing(toAddr(0), toAddr(63));
        createData(toAddr(0), new ArrayDataType(unsigned, 16, 4));
        createLabel(toAddr(0), "cortex_vectors", true, SourceType.USER_DEFINED);
        Files.writeString(Path.of(getScriptArgs()[1]), new Gson().toJson(Map.of(
            "status", "PASS_CURATED_CORTEX_M", "language", currentProgram.getLanguageID().toString(),
            "functions", records, "objects", manifest.getAsJsonArray("objects").size())) + "\n");
        println("cortex-m-curation=PASS functions=" + records.size());
    }

    private AddressSet body(JsonObject row) {
        var result = new AddressSet();
        for (var element : row.getAsJsonArray("ranges")) {
            var range = element.getAsJsonArray();
            result.add(toAddr(range.get(0).getAsLong()), toAddr(range.get(1).getAsLong() - 1));
        }
        return result;
    }
}
