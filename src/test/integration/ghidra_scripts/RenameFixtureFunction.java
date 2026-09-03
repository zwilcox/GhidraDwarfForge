// Applies analyst-style names, a signature, and a recursive favorite type graph.
// @category DWARF.Tests

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.lang.Register;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class RenameFixtureFunction extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 7) {
            throw new IllegalArgumentException(
                "usage: RenameFixtureFunction <add-address> <variadic-address> " +
                    "<noreturn-address> <add-name> <global-address> <composite-address> " +
                    "<scoped-global-address>");
        }
        Function function = requireFunction(arguments[0]);
        function.setName(arguments[3], SourceType.USER_DEFINED);
        function.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);
        DataTypeManager manager = currentProgram.getDataTypeManager();
        DataType signedInt = new IntegerDataType(manager);
        function.setReturnType(signedInt, SourceType.USER_DEFINED);
        Register[] argumentRegisters = argumentRegisters();
        function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE,
            true, SourceType.USER_DEFINED,
            new ParameterImpl("left", signedInt, argumentRegisters[0], currentProgram,
                SourceType.USER_DEFINED),
            new ParameterImpl("right", signedInt, argumentRegisters[1], currentProgram,
                SourceType.USER_DEFINED));
        function.addLocalVariable(new LocalVariableImpl("analyst_local", 0, signedInt,
            VariableStorage.UNASSIGNED_STORAGE, false, currentProgram,
            SourceType.USER_DEFINED), SourceType.USER_DEFINED);
        function.addLocalVariable(new LocalVariableImpl("analyst_register", 0,
            signedInt, argumentRegisters[2], currentProgram, SourceType.USER_DEFINED),
            SourceType.USER_DEFINED);
        int stackOffset = stackLocalOffset();
        Variable existingStackLocal = function.getStackFrame()
            .getVariableContaining(stackOffset);
        if (existingStackLocal != null) {
            function.removeVariable(existingStackLocal);
        }
        function.getStackFrame().createVariable("analyst_stack", stackOffset, signedInt,
            SourceType.USER_DEFINED);

        Function variadic = requireFunction(arguments[1]);
        variadic.setName("recovered_variadic", SourceType.USER_DEFINED);
        variadic.setReturnType(signedInt, SourceType.USER_DEFINED);
        variadic.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
            true, SourceType.USER_DEFINED,
            new ParameterImpl("count", signedInt, currentProgram, SourceType.USER_DEFINED));
        variadic.setVarArgs(true);

        Function noReturn = requireFunction(arguments[2]);
        noReturn.setName("recovered_spin", SourceType.USER_DEFINED);
        noReturn.setReturnType(DataType.VOID, SourceType.USER_DEFINED);
        noReturn.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
            true, SourceType.USER_DEFINED,
            new ParameterImpl("value", signedInt, currentProgram, SourceType.USER_DEFINED));
        noReturn.setNoReturn(true);

        Function composite = requireFunction(arguments[5]);
        composite.setName("recovered_composite", SourceType.USER_DEFINED);
        composite.setReturnType(DataType.VOID, SourceType.USER_DEFINED);
        composite.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE,
            true, SourceType.USER_DEFINED);
        DataType signedLongLong = new LongLongDataType(manager);
        VariableStorage compositeStorage = new VariableStorage(currentProgram,
            compositeRegisters());
        composite.addLocalVariable(new LocalVariableImpl("analyst_composite", 0,
            signedLongLong, compositeStorage, false, currentProgram,
            SourceType.USER_DEFINED), SourceType.USER_DEFINED);

        var globalAddress = toAddr(arguments[4]);
        DataUtilities.createData(currentProgram, globalAddress, signedInt,
            signedInt.getLength(), DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
        Symbol global = currentProgram.getSymbolTable().createLabel(globalAddress,
            "fixture_sink", SourceType.USER_DEFINED);
        global.setPrimary();
        Namespace analystScope = currentProgram.getSymbolTable().getOrCreateNameSpace(
            currentProgram.getGlobalNamespace(), "analyst_scope", SourceType.USER_DEFINED);
        var scopedGlobalAddress = toAddr(arguments[6]);
        DataUtilities.createData(currentProgram, scopedGlobalAddress, signedInt,
            signedInt.getLength(), DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
        Symbol scopedGlobal = currentProgram.getSymbolTable().createLabel(
            scopedGlobalAddress, "scoped_counter", analystScope, SourceType.USER_DEFINED);
        scopedGlobal.setPrimary();
        ExternalManager externalManager = currentProgram.getExternalManager();
        String fixtureLibrary = "fixture_imports";
        if (!externalManager.contains(fixtureLibrary)) {
            externalManager.addExternalLibraryName(fixtureLibrary, SourceType.USER_DEFINED);
        }
        var externalCounter = externalManager.addExtLocation(fixtureLibrary,
            "external_counter", null, SourceType.USER_DEFINED);
        externalCounter.setDataType(signedInt);

        DataType fixtureState = buildFixtureTypes(manager, signedInt);
        manager.setFavorite(fixtureState, true);
        println("Renamed fixture function at " + arguments[0] + " to " + arguments[3]);
        println("Applied USER_DEFINED int recovered_add(int left, int right) in " +
            argumentRegisters[0].getName() + "/" + argumentRegisters[1].getName());
        println("Applied default calling convention to recovered_add");
        println("Applied USER_DEFINED locationless int analyst_local");
        println("Applied USER_DEFINED int analyst_register in " +
            argumentRegisters[2].getName());
        println("Applied USER_DEFINED int analyst_stack at Ghidra stack offset " +
            stackOffset);
        println("Applied USER_DEFINED int recovered_variadic(int count, ...)");
        println("Applied USER_DEFINED noreturn void recovered_spin(int value)");
        println("Applied USER_DEFINED long long analyst_composite in " +
            compositeStorage);
        println("Applied USER_DEFINED int fixture_sink at " + arguments[4]);
        println("Applied USER_DEFINED int analyst_scope::scoped_counter at " +
            arguments[6]);
        println("Applied USER_DEFINED extern int external_counter declaration");
        println("Applied favorite recursive fixture type " + fixtureState.getPathName());
    }

    private int stackLocalOffset() {
        String language = currentProgram.getLanguageID().toString();
        if (language.startsWith("x86:")) {
            return -12;
        }
        if (language.startsWith("AARCH64:")) {
            return -4;
        }
        if (language.startsWith("ARM:")) {
            return -12;
        }
        if (language.startsWith("MIPS:")) {
            return -12;
        }
        throw new IllegalStateException("no fixture stack-local offset for " + language);
    }

    private Function requireFunction(String address) {
        Function function = currentProgram.getFunctionManager().getFunctionAt(toAddr(address));
        if (function == null) {
            throw new IllegalStateException("fixture function not discovered at " + address);
        }
        return function;
    }

    private Register[] argumentRegisters() {
        String language = currentProgram.getLanguageID().toString();
        String[] names;
        if (language.startsWith("x86:")) {
            names = new String[] { "EDI", "ESI", "ECX" };
        }
        else if (language.startsWith("AARCH64:")) {
            names = new String[] { "w0", "w1", "w3" };
        }
        else if (language.startsWith("ARM:")) {
            names = new String[] { "r0", "r1", "r3" };
        }
        else if (language.startsWith("MIPS:")) {
            names = new String[] { "a0", "a1", "a3" };
        }
        else {
            throw new IllegalStateException("no fixture argument registers for " + language);
        }
        Register first = currentProgram.getRegister(names[0]);
        Register second = currentProgram.getRegister(names[1]);
        Register third = currentProgram.getRegister(names[2]);
        if (first == null || second == null || third == null) {
            throw new IllegalStateException("fixture argument registers are unavailable for " +
                language);
        }
        return new Register[] { first, second, third };
    }

    private Register[] compositeRegisters() {
        String language = currentProgram.getLanguageID().toString();
        String[] names;
        if (language.startsWith("x86:")) {
            names = new String[] { "EDX", "ECX" };
        }
        else if (language.startsWith("AARCH64:")) {
            names = new String[] { "w2", "w3" };
        }
        else if (language.startsWith("ARM:")) {
            names = new String[] { "r2", "r3" };
        }
        else if (language.startsWith("MIPS:")) {
            names = new String[] { "a2", "a3" };
        }
        else {
            throw new IllegalStateException("no fixture composite registers for " + language);
        }
        Register first = currentProgram.getRegister(names[0]);
        Register second = currentProgram.getRegister(names[1]);
        if (first == null || second == null) {
            throw new IllegalStateException("fixture composite registers are unavailable for " +
                language);
        }
        return new Register[] { first, second };
    }

    private DataType buildFixtureTypes(DataTypeManager manager, DataType signedInt)
            throws Exception {
        CategoryPath category = new CategoryPath("/GhidraDwarfForgeFixture");
        DataType unsignedInt = new UnsignedIntegerDataType(manager);

        EnumDataType operation = new EnumDataType(category, "operation", 4, manager);
        operation.add("OP_INVALID", -1);
        operation.add("OP_ADD", 1);
        operation.add("OP_XOR", 2);

        UnionDataType wordView = new UnionDataType(category, "word_view", manager);
        wordView.setPackingEnabled(true);
        wordView.add(unsignedInt, 4, "value", null);
        wordView.add(new ArrayDataType(ghidra.program.model.data.ByteDataType.dataType,
            4, 1, manager), 4, "bytes", null);

        StructureDataType listNode = new StructureDataType(category, "list_node", 0,
            manager);
        listNode.setPackingEnabled(true);
        listNode.add(signedInt, signedInt.getLength(), "value", null);
        listNode.add(new PointerDataType(listNode, currentProgram.getDefaultPointerSize(),
            manager), currentProgram.getDefaultPointerSize(), "next", null);
        DataType resolvedListNode = manager.resolve(listNode,
            DataTypeConflictHandler.REPLACE_HANDLER);
        manager.setFavorite(resolvedListNode, true);

        FunctionDefinitionDataType binaryFunction = new FunctionDefinitionDataType(
            category, "binary_operation_function", manager);
        binaryFunction.setReturnType(signedInt);
        binaryFunction.setArguments(
            new ParameterDefinitionImpl("left", signedInt, null),
            new ParameterDefinitionImpl("right", signedInt, null));
        TypedefDataType binaryOperation = new TypedefDataType(category,
            "binary_operation", new PointerDataType(binaryFunction,
                currentProgram.getDefaultPointerSize(), manager), manager);

        StructureDataType state = new StructureDataType(category, "fixture_state", 0,
            manager);
        state.setPackingEnabled(true);
        state.add(operation, operation.getLength(), "operation", null);
        state.add(wordView, wordView.getLength(), "word", null);
        state.add(new ArrayDataType(signedInt, 3, signedInt.getLength(), manager),
            3 * signedInt.getLength(), "values", null);
        state.add(binaryOperation, binaryOperation.getLength(), "apply", null);

        StructureDataType packedFlags = new StructureDataType(category, "packed_flags", 0,
            manager);
        packedFlags.setPackingEnabled(true);
        packedFlags.addBitField(unsignedInt, 3, "low_three", null);
        packedFlags.addBitField(unsignedInt, 5, "next_five", null);
        DataType resolvedFlags = manager.resolve(packedFlags,
            DataTypeConflictHandler.REPLACE_HANDLER);
        manager.setFavorite(resolvedFlags, true);
        println("Applied favorite bit-field fixture type " + resolvedFlags.getPathName());

        // Resolving the root recursively installs and canonicalizes every dependency.
        return manager.resolve(state, DataTypeConflictHandler.REPLACE_HANDLER);
    }
}
