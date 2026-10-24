// Curates function-owned data using independent compiler-oracle addresses.
// @category DWARF.Tests

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.AddressNormalizer;
import ghidradwarfforge.GhidraFunctionSymbols;
import ghidradwarfforge.GhidraImageBase;
import ghidradwarfforge.GhidraTypeGraph;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.nativeapi.DwarfTarget;

public class PrepareFunctionStaticScopes extends GhidraScript {
    private long delta;
    private DataType integer;

    @Override
    protected void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 7 && (arguments.length != 9 ||
                !arguments[7].equals("qualified"))) {
            throw new IllegalArgumentException("usage: PrepareFunctionStaticScopes <target> " +
                "<first-function> <second-function> <first-static> <second-static> " +
                "<global> <namespace-global> [qualified <global-function>]");
        }
        delta = AddressNormalizer.rebaseDelta(currentProgram.getImageBase().getOffset(),
            GhidraImageBase.originalImageBase(currentProgram));
        integer = new IntegerDataType(currentProgram.getDataTypeManager());
        Function first = function(arguments[1], "first_scope");
        Function second = function(arguments[2], "second_scope");
        if (arguments.length == 9) {
            qualify(first, "analysis_left");
            qualify(second, "analysis_right");
            function(arguments[8], "curated_same");
        }
        data(arguments[3], "private_count", first);
        data(arguments[4], "private_count", second);
        data(arguments[5], "private_count", currentProgram.getGlobalNamespace());
        Namespace namespace = currentProgram.getSymbolTable().getOrCreateNameSpace(
            currentProgram.getGlobalNamespace(), "analyst_scope", SourceType.USER_DEFINED);
        data(arguments[6], "scoped_value", namespace);
        var external = currentProgram.getExternalManager().addExtLocation(
            "fixture_library", "declared_external", null, SourceType.USER_DEFINED);
        external.setDataType(integer);

        // Exercise omission independently of the full export: the second owner
        // is absent from the selected definitions, so its object must be diagnosed.
        List<String> diagnostics = new ArrayList<>();
        var functions = GhidraFunctionSymbols.extract(currentProgram, monitor,
            diagnostics::add, delta);
        long omittedOwner = Long.decode(arguments[2]);
        var selected = functions.stream()
            .filter(candidate -> candidate.address() != omittedOwner).toList();
        String target = DwarfTarget.fromElf(ElfImage.read(
            Path.of(currentProgram.getExecutablePath()))).name();
        var model = GhidraTypeGraph.extract(currentProgram, selected, target, delta,
            monitor, diagnostics::add);
        if (model.functionStatics().stream().anyMatch(variable ->
                variable.ownerAddress() == omittedOwner) ||
                diagnostics.stream().noneMatch(message -> message.equals(
                    "Skipped function-owned static variable " + second.getName(true) +
                        "::private_count; " +
                        "owning function was not exported"))) {
            throw new AssertionError("missing function owner was not isolated and diagnosed");
        }
        println("function-static-scopes preparation PASS; missing owner diagnosed");
        println("fixture profile=" + arguments[0] + "; ELF target=" + target);
    }

    private void qualify(Function function, String parentName) throws Exception {
        var symbols = currentProgram.getSymbolTable();
        Namespace parent = symbols.getOrCreateNameSpace(currentProgram.getGlobalNamespace(),
            parentName, SourceType.USER_DEFINED);
        Namespace nested = symbols.getOrCreateNameSpace(parent, "nested",
            SourceType.USER_DEFINED);
        function.setParentNamespace(nested);
        function.setName("curated_same", SourceType.USER_DEFINED);
    }

    private Address address(String value) {
        return toAddr(Math.addExact(Long.decode(value), delta));
    }

    private Function function(String value, String name) throws Exception {
        Function function = getFunctionAt(address(value));
        if (function == null) {
            throw new IllegalStateException("missing fixture function " + name);
        }
        function.setName(name, SourceType.USER_DEFINED);
        function.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);
        function.setReturnType(integer, SourceType.USER_DEFINED);
        function.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
            true, SourceType.USER_DEFINED);
        return function;
    }

    private void data(String value, String name, Namespace owner) throws Exception {
        Address address = address(value);
        DataUtilities.createData(currentProgram, address, integer, integer.getLength(),
            DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
        var symbol = currentProgram.getSymbolTable().createLabel(address, name, owner,
            SourceType.USER_DEFINED);
        symbol.setPrimary();
        if (!symbol.isPrimary()) {
            throw new IllegalStateException("could not make primary data label " + name);
        }
    }
}
