// Apply independently decoded compiler evidence to an owned stripped test fixture.
// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;

import com.google.gson.JsonParser;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraClassBindings;
import ghidradwarfforge.GhidraImageBase;
import ghidradwarfforge.GhidraInheritanceBindings;
import ghidradwarfforge.targets.CxxAbiProfile;
import ghidradwarfforge.types.InheritanceModel;
import ghidradwarfforge.types.InheritanceModel.*;

public class PrepareInheritanceFixture extends GhidraScript {
    private long delta;

    @Override
    protected void run() throws Exception {
        if (getScriptArgs().length != 1) throw new IllegalArgumentException("compiler-model.json");
        var evidence = JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();
        delta = currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram);
        var manager = currentProgram.getDataTypeManager();
        var classes = new HashMap<String, GhidraClass>();
        var layouts = new HashMap<String, Structure>();
        var declarations = currentProgram.getExternalManager().addExternalLibraryName("FixtureDeclarations", SourceType.USER_DEFINED);
        var functionType = new FunctionDefinitionDataType("FixtureVirtualFunction");
        functionType.setReturnType(IntegerDataType.dataType);
        var vptr = new PointerDataType(new PointerDataType(functionType, 8, manager), 8, manager);
        for (var item : evidence.getAsJsonArray("classes")) {
            monitor.checkCancelled();
            var row = item.getAsJsonObject();
            String name = row.get("name").getAsString();
            boolean hasBody = false, hasDeclaration = false;
            for (var methodValue : evidence.getAsJsonArray("methods")) {
                var method = methodValue.getAsJsonObject();
                if (!method.get("owner").getAsString().equals(name)) continue;
                if (method.has("address")) hasBody = true;
                else hasDeclaration = true;
            }
            if (hasBody && hasDeclaration) throw new AssertionError("fixture requires mixed local/addressless class declarations");
            // Ghidra represents a class with only addressless methods beneath
            // an external library. The library is not a DWARF source namespace.
            var owner = currentProgram.getSymbolTable().createClass(
                hasDeclaration ? declarations : currentProgram.getGlobalNamespace(), name, SourceType.USER_DEFINED);
            var layout = new StructureDataType(name, row.get("size").getAsInt());
            for (var value : row.getAsJsonArray("members")) {
                var member = value.getAsJsonObject();
                DataType type = member.get("vptr").getAsBoolean() ? vptr : IntegerDataType.dataType;
                layout.replaceAtOffset(member.get("offset").getAsInt(), type, type.getLength(),
                    member.get("name").getAsString(), "Compiler fixture member evidence");
            }
            var saved = (Structure) manager.addDataType(layout, DataTypeConflictHandler.DEFAULT_HANDLER);
            classes.put(name, owner); layouts.put(name, saved);
            GhidraClassBindings.save(currentProgram, owner, saved, "Independent source-built compiler fixture", monitor);
        }
        var virtuals = new ArrayList<VirtualMethod>();
        int addressless = 0;
        for (var item : evidence.getAsJsonArray("methods")) {
            var row = item.getAsJsonObject();
            var owner = classes.get(row.get("owner").getAsString());
            Function function;
            if (!row.has("address")) {
                addressless++;
                function = currentProgram.getExternalManager().addExtFunction(owner,
                    row.get("name").getAsString(), null, SourceType.USER_DEFINED).getFunction();
            }
            else {
                function = function(row.get("name").getAsString(), row.get("address").getAsLong(), row.get("size").getAsLong());
                function.setParentNamespace(owner);
            }
            function.setCallingConvention("__thiscall");
            function.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
            virtuals.add(new VirtualMethod(function.getID(), row.get("slot").getAsInt(), Access.PUBLIC,
                Virtuality.VIRTUAL, "Independent compiler virtual slot"));
        }
        var bases = new ArrayList<Base>();
        for (var item : evidence.getAsJsonArray("bases")) {
            var row = item.getAsJsonObject();
            BaseLocation location = row.get("virtual").getAsBoolean()
                ? new VirtualBase(0, row.get("slotOffset").getAsLong())
                : new FixedBase(row.get("offset").getAsLong(), row.get("occupiedBytes").getAsLong());
            bases.add(new Base(classes.get(row.get("derived").getAsString()).getID(),
                classes.get(row.get("base").getAsString()).getID(), row.get("order").getAsInt(),
                Access.PUBLIC, location, "Independent compiler base adjustment"));
        }
        for (var item : evidence.getAsJsonArray("globals")) {
            var row = item.getAsJsonObject();
            Address address = address(row.get("address").getAsLong());
            clearListing(address, address.add(7));
            createData(address, new PointerDataType(layouts.get(row.get("type").getAsString()), 8, manager));
            createLabel(address, row.get("name").getAsString(), true, SourceType.USER_DEFINED);
        }
        var checkpoint = evidence.getAsJsonObject("checkpoint");
        function("inheritance_checkpoint", checkpoint.get("address").getAsLong(), checkpoint.get("size").getAsLong())
            .setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
        var model = new InheritanceModel(CxxAbiProfile.valueOf(evidence.get("abi").getAsString()), bases, virtuals);
        GhidraInheritanceBindings.save(currentProgram, model, monitor);
        if (!GhidraInheritanceBindings.read(currentProgram, monitor, this::println).model().equals(model)) {
            throw new AssertionError("saved inheritance differs from curated fixture");
        }
        println("inheritance-curation=PASS bases=" + bases.size() + " virtualMethods=" + virtuals.size() +
            " compilerDeclarationsWithoutBodies=" + addressless);
    }

    private Address address(long original) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(original + delta);
    }

    private Function function(String name, long original, long size) throws Exception {
        monitor.checkCancelled();
        Address entry = address(original);
        disassemble(entry);
        var function = getFunctionAt(entry);
        if (function == null) function = createFunction(entry, name);
        if (function == null) throw new AssertionError("cannot create compiler-evidenced function " + name);
        function.setName(name, SourceType.USER_DEFINED);
        function.setBody(new AddressSet(entry, entry.add(size - 1)));
        return function;
    }
}
