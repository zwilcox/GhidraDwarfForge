// Applies only compiler-oracle signatures and globals to the stripped fixture.
// @category DWARF.Tests

import java.nio.file.Files;
import java.nio.file.Path;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.AddressNormalizer;
import ghidradwarfforge.GhidraImageBase;

public class PrepareRegisterCopy extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1 && args.length != 2) {
            throw new IllegalArgumentException("expected <preparation-labels> [function-count]");
        }
        long delta = AddressNormalizer.rebaseDelta(currentProgram.getImageBase().getOffset(),
            GhidraImageBase.originalImageBase(currentProgram));
        int count = 0;
        for (String line : Files.readAllLines(Path.of(args[0]))) {
            monitor.checkCancelled();
            String[] fields = line.split(" ");
            if (fields.length != 6) {
                throw new IllegalArgumentException("malformed fixture record");
            }
            String name = fields[0];
            var entry = toAddr(Math.addExact(Long.decode(fields[1]), delta));
            var end = toAddr(Math.addExact(Long.decode(fields[2]), delta));
            var sink = toAddr(Math.addExact(Long.decode(fields[3]), delta));
            int bytes = Integer.parseInt(fields[4]);
            DataType type = bytes == 4 ? new IntegerDataType(currentProgram.getDataTypeManager())
                : new LongLongDataType(currentProgram.getDataTypeManager());
            if (bytes != type.getLength() || (bytes != 4 && bytes != 8)) {
                throw new IllegalArgumentException("unexpected fixture width");
            }
            Function function = getFunctionAt(entry);
            if (function == null || function.getBody().getNumAddressRanges() != 1 ||
                    !function.getBody().getMinAddress().equals(entry) ||
                    !function.getBody().getMaxAddress().add(1).equals(end)) {
                throw new IllegalStateException("fixture body differs from compiler bounds: " + name);
            }
            function.setName(name, SourceType.USER_DEFINED);
            function.setReturnType(type, SourceType.USER_DEFINED);
            function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true,
                SourceType.USER_DEFINED, new ParameterImpl("value", type,
                    currentProgram.getRegister(fields[5]), currentProgram, SourceType.USER_DEFINED));
            DataUtilities.createData(currentProgram, sink, type, bytes,
                DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
            currentProgram.getSymbolTable().createLabel(sink, name + "_sink",
                SourceType.USER_DEFINED).setPrimary();
            var instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
            while (instructions.hasNext()) {
                monitor.checkCancelled();
                var instruction = instructions.next();
                println("copy-proof-instruction=" + name + " " + instruction.getAddress() +
                    " " + instruction);
                for (var operation : instruction.getPcode()) {
                    println("copy-proof-pcode=" + operation);
                }
            }
            count++;
        }
        if (count != (args.length == 2 ? Integer.parseInt(args[1]) : 4)) {
            throw new IllegalStateException("unexpected fixture function count");
        }
        println("register-copy-preparation=PASS");
    }
}
