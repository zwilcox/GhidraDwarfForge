// Inspect an analyzed ARM -> Thumb -> ARM body without repairing its context.
// @category DWARF.Tests
import java.util.ArrayList;
import java.util.LinkedHashMap;
import com.google.gson.Gson;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;

public class PrepareArmMixedBody extends GhidraScript {
    @Override
    protected void run() throws Exception {
        var args = getScriptArgs();
        if (args.length != 1 && args.length != 2) {
            throw new IllegalArgumentException("mixed function link address required");
        }
        var image = ghidradwarfforge.elf.ElfImage.read(
            java.nio.file.Path.of(currentProgram.getExecutablePath()));
        if (args.length == 2) {
            currentProgram.setImageBase(toAddr(Math.addExact(image.preferredImageBase(), Long.decode(args[1]))), true);
        }
        long delta = currentProgram.getImageBase().getOffset() - image.preferredImageBase();
        var entry = toAddr(Math.addExact(Long.decode(args[0]), delta));
        Function function = getFunctionAt(entry);
        if (function == null) {
            throw new IllegalStateException("analysis did not create the mixed function");
        }
        var originalBody = function.getBody().toString();
        // Explicit analyst knowledge joins already decoded regions. Do not decode
        // bytes or infer context to make the fixture pass.
        for (int offset : new int[] {0, 4, 8, 12, 16, 18, 20, 22, 24, 28, 32, 36}) {
            var address = entry.add(offset);
            var instruction = getInstructionAt(address);
            if (instruction == null || instruction.getLength() != (offset >= 16 && offset < 24 ? 2 : 4)) {
                throw new IllegalStateException("missing independently expected instruction at " + address);
            }
            var mode = currentProgram.getProgramContext().getValue(
                currentProgram.getRegister("TMode"), address, false);
            if (!java.math.BigInteger.valueOf(offset >= 16 && offset < 24 ? 1 : 0).equals(mode)) {
                throw new IllegalStateException("analysis mode differs at " + address);
            }
        }
        function.setBody(new ghidra.program.model.address.AddressSet(entry, entry.add(39)));
        function.setName("recovered_mixed_body", SourceType.USER_DEFINED);
        var type = new IntegerDataType(currentProgram.getDataTypeManager());
        function.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);
        function.setReturnType(type, SourceType.USER_DEFINED);
        function.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
            true, SourceType.USER_DEFINED,
            new ParameterImpl("value", type, currentProgram, SourceType.USER_DEFINED));
        var memory = currentProgram.getMemory().getBlock(entry);
        var units = currentProgram.getListing().getCodeUnits(
            new ghidra.program.model.address.AddressSet(memory.getStart(), memory.getEnd()), true);
        var rows = new ArrayList<Object>();
        while (units.hasNext()) {
            monitor.checkCancelled();
            var unit = units.next();
            var row = new LinkedHashMap<String, Object>();
            row.put("address", unit.getAddress().toString());
            row.put("size", unit.getLength());
            row.put("instruction", unit instanceof Instruction);
            row.put("text", unit.toString());
            row.put("bytes", java.util.HexFormat.of().formatHex(unit.getBytes()));
            row.put("mode", currentProgram.getProgramContext().getValue(
                currentProgram.getRegister("TMode"), unit.getAddress(), false));
            row.put("inBody", function.getBody().contains(unit.getAddress()));
            rows.add(row);
        }
        var result = new LinkedHashMap<String, Object>();
        result.put("language", currentProgram.getLanguageID().toString());
        result.put("body", function.getBody().toString());
        result.put("originalBody", originalBody);
        result.put("entry", entry.toString());
        result.put("block", memory.getName());
        result.put("units", rows);
        result.put("imageBaseDelta", delta);
        println("ARM_MIXED_MODEL=" + new Gson().toJson(result));
    }
}
