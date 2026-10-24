// Applies measured compiler stack slots and explicit curated first-use metadata.
// @category DWARF.Tests

import java.nio.file.Files;
import java.nio.file.Path;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.AddressNormalizer;
import ghidradwarfforge.GhidraImageBase;

public class PrepareStackFirstUse extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("expected <preparation-labels>");
        }
        long delta = AddressNormalizer.rebaseDelta(currentProgram.getImageBase().getOffset(),
            GhidraImageBase.originalImageBase(currentProgram));
        var type = new IntegerDataType(currentProgram.getDataTypeManager());
        int functions = 0;
        int globals = 0;
        for (String line : Files.readAllLines(Path.of(args[0]))) {
            monitor.checkCancelled();
            String[] fields = line.split(" ");
            if (fields.length == 2 && (fields[0].equals("scope_sink") || fields[0].equals("zero_sink"))) {
                var address = toAddr(Math.addExact(Long.decode(fields[1]), delta));
                DataUtilities.createData(currentProgram, address, type, type.getLength(),
                    DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
                currentProgram.getSymbolTable().createLabel(address, fields[0],
                    SourceType.USER_DEFINED).setPrimary();
                globals++;
                continue;
            }
            if (fields.length != 5 || (!fields[0].equals("stack_scope") && !fields[0].equals("zero_stack"))) {
                throw new IllegalArgumentException("malformed fixture record");
            }
            var entry = toAddr(Math.addExact(Long.decode(fields[1]), delta));
            var end = toAddr(Math.addExact(Long.decode(fields[2]), delta));
            var live = toAddr(Math.addExact(Long.decode(fields[3]), delta));
            int offset = Integer.parseInt(fields[4]);
            Function function = getFunctionAt(entry);
            if (function == null || function.getBody().getNumAddressRanges() != 1 ||
                    !function.getBody().getMinAddress().equals(entry) ||
                    !function.getBody().getMaxAddress().add(1).equals(end) ||
                    !function.getBody().contains(live) || getInstructionAt(live) == null) {
                throw new IllegalStateException("fixture body disagrees with compiler labels");
            }
            function.setName(fields[0], SourceType.USER_DEFINED);
            function.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
            function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true,
                SourceType.USER_DEFINED, new Parameter[0]);
            for (var variable : function.getLocalVariables()) {
                if (variable.hasStackStorage()) {
                    function.removeVariable(variable);
                }
            }
            boolean later = fields[0].equals("stack_scope");
            String name = later ? "second" : "zero";
            LocalVariable local = (LocalVariable) function.addLocalVariable(
                new LocalVariableImpl(name, type, offset, currentProgram, SourceType.USER_DEFINED),
                SourceType.USER_DEFINED);
            int firstUse = later ? Math.toIntExact(live.subtract(entry)) : 0;
            if (later && firstUse <= 0) {
                throw new IllegalStateException("expected a later curated stack start");
            }
            // Insertion does not support this state; the public setter on the
            // stored local is the actual route reproduced by the research.
            local.setFirstUseOffset(firstUse);
            var stored = java.util.Arrays.stream(function.getLocalVariables())
                .filter(variable -> variable.getName().equals(name)).toList();
            if (stored.size() != 1 || stored.get(0).getFirstUseOffset() != firstUse ||
                    stored.get(0).getStackOffset() != offset) {
                throw new IllegalStateException("curated metadata did not persist");
            }
            println("stack-first-use-local=" + name + " first-use=" + firstUse + " storage=" + offset);
            functions++;
        }
        if (functions != 2 || globals != 2) {
            throw new IllegalStateException("expected two functions and two globals");
        }
        println("stack-first-use-preparation=PASS");
    }
}
