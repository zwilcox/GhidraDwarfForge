// Curates a deterministic fixture and settles analysis before its first export.
// @category DWARF.Tests

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;

public class PrepareSavedProgramTypes extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 4) {
            throw new IllegalArgumentException("expected entry, add, sink and counter addresses");
        }
        var entry = getFunctionAt(toAddr(args[0]));
        var function = getFunctionAt(toAddr(args[1]));
        if (entry == null || function == null) {
            throw new AssertionError("required fixture function was not analyzed");
        }
        entry.setName("saved_program_entry", SourceType.USER_DEFINED);
        function.setName("saved_program_add", SourceType.USER_DEFINED);
        function.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);
        var manager = currentProgram.getDataTypeManager();
        var signedInt = new IntegerDataType(manager);
        function.setReturnType(signedInt, SourceType.USER_DEFINED);
        // This fixture is compiled for the documented AMD64 SysV argument registers.
        function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE,
            true, SourceType.USER_DEFINED,
            new ParameterImpl("left", signedInt, currentProgram.getRegister("EDI"),
                currentProgram, SourceType.USER_DEFINED),
            new ParameterImpl("right", signedInt, currentProgram.getRegister("ESI"),
                currentProgram, SourceType.USER_DEFINED),
            new ParameterImpl("unused", signedInt, currentProgram.getRegister("EDX"),
                currentProgram, SourceType.USER_DEFINED),
            new ParameterImpl("register_seed", signedInt, currentProgram.getRegister("ECX"),
                currentProgram, SourceType.USER_DEFINED));
        var global = toAddr(args[2]);
        DataUtilities.createData(currentProgram, global, signedInt, 4,
            DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
        currentProgram.getSymbolTable().createLabel(global, "fixture_sink",
            SourceType.USER_DEFINED).setPrimary();
        // Apply an analyst-owned type so it remains reachable after reopening.
        // Its own UniversalID must keep its identity across every process.
        var structure = new StructureDataType(new CategoryPath("/SaveReopen"),
            "saved_identity_type", 0, manager);
        structure.add(signedInt, "value", "analyst field");
        var resolved = manager.resolve(structure, DataTypeConflictHandler.DEFAULT_HANDLER);
        var counter = toAddr(args[3]);
        DataUtilities.createData(currentProgram, counter, resolved, 4,
            DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
        currentProgram.getSymbolTable().createLabel(counter, "saved_identity_object",
            SourceType.USER_DEFINED).setPrimary();
        analyzeChanges(currentProgram);
        println("saved-program-analysis=SETTLED type-id=" + resolved.getUniversalID());
    }
}
