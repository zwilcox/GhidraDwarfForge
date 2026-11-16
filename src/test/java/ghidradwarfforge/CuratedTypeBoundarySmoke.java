package ghidradwarfforge;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;

/** Real saved types and symbols: preserve analyst layout and reject untranslatable addresses. */
public final class CuratedTypeBoundarySmoke {
    private static int checks;

    private CuratedTypeBoundarySmoke() { }

    static void run(ProgramDB program, String target, int wideBytes) throws Exception {
        checks = 0;
        var manager = program.getDataTypeManager();
        // These are the selected Ghidra profiles, not a claim about every ABI.
        // The pinned MIPS32 default specs inherit Ghidra's two-byte wchar setting.
        require(manager.getDataOrganization().getWideCharSize() == wideBytes, "pinned wide-character profile changed");
        var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x3000);
        program.getMemory().createInitializedBlock("curated_types", start, 4096, (byte) 0, TaskMonitor.DUMMY, false);
        var primitives = List.of(new WideCharDataType(manager), new WideChar16DataType(manager), new WideChar32DataType(manager));
        int offset = 0;
        for (DataType type : primitives) {
            var address = start.add(offset);
            program.getListing().createData(address, type);
            program.getSymbolTable().createLabel(address, "wide_" + offset, SourceType.USER_DEFINED);
            offset += 32;
        }
        var structure = new StructureDataType("QualifiedMembers", 0, manager);
        structure.add(new IntegerDataType(manager), null, "unnamed member retains its default name");
        structure.add(new IntegerDataType(manager), "constant_member", null);
        structure.add(new IntegerDataType(manager), "volatile_member", null);
        var data = program.getListing().createData(start.add(0x100), structure);
        program.getSymbolTable().createLabel(data.getAddress(), "qualified_object", SourceType.USER_DEFINED);
        var saved = (Structure) data.getDataType();
        MutabilitySettingsDefinition.DEF.setChoice(saved.getComponent(1).getDefaultSettings(), MutabilitySettingsDefinition.CONSTANT);
        MutabilitySettingsDefinition.DEF.setChoice(saved.getComponent(2).getDefaultSettings(), MutabilitySettingsDefinition.VOLATILE);

        var bits = new StructureDataType("AlignmentOnlyBitfield", 0, manager);
        bits.setPackingEnabled(true);
        bits.addBitField(new UnsignedIntegerDataType(manager), 3, "bits", null);
        bits.addBitField(new UnsignedIntegerDataType(manager), 0, null, "alignment only");
        bits.add(new IntegerDataType(manager), "tail", null);
        var bitData = program.getListing().createData(start.add(0x200), bits);
        program.getSymbolTable().createLabel(bitData.getAddress(), "bit_object", SourceType.USER_DEFINED);
        var savedBits = (Structure) bitData.getDataType();
        require(java.util.Arrays.stream(savedBits.getDefinedComponents()).anyMatch(component ->
            component.getDataType() instanceof BitFieldDataType bit && bit.getBitSize() == 0),
            "fixture must retain an actual zero-width component");

        var entry = start.add(0x800);
        var owner = program.getFunctionManager().createFunction("unexported_owner", entry,
            new AddressSet(entry, entry), SourceType.USER_DEFINED);
        var ownedAddress = start.add(0x500);
        program.getListing().createData(ownedAddress, new IntegerDataType(manager));
        program.getSymbolTable().createLabel(ownedAddress, "owned_static", owner, SourceType.USER_DEFINED);
        long modification = program.getModificationNumber();
        var diagnostics = new ArrayList<String>();
        ProgramTypeModel model;
        try {
            model = GhidraTypeGraph.extract(program, List.of(), target, 0, TaskMonitor.DUMMY, diagnostics::add);
        }
        catch (IllegalArgumentException rejected) {
            throw new AssertionError("valid saved type layout was rejected", rejected);
        }
        require(diagnostics.stream().anyMatch(message -> message.contains("owned_static")
            && message.contains("owning function was not exported")), "orphaned static needs a diagnostic");
        require(model.functionStatics().isEmpty() && model.globals().stream().noneMatch(global -> global.name().equals("owned_static")),
            "unexported function's static was promoted to a global");
        for (int index = 0; index < 3; index++) {
            var node = globalType(model, "wide_" + index * 32);
            require(node instanceof TypeGraph.BaseType, "wide character lost primitive identity");
            var base = (TypeGraph.BaseType) node;
            int expected = index == 0 ? wideBytes : index == 1 ? 2 : 4;
            require(base.encoding() == TypeGraph.BaseEncoding.UTF && base.byteSize() == expected
                && base.valueByteSize() == expected, "wide character encoding/width differs from saved data organization");
        }
        var aggregate = (TypeGraph.AggregateType) globalType(model, "qualified_object");
        require(aggregate.members().size() == 3 && aggregate.byteSize() == saved.getLength(), "structure layout changed");
        for (int index = 0; index < 3; index++) {
            var component = saved.getComponent(index);
            var member = aggregate.members().get(index);
            require(member.byteOffset() == component.getOffset() && member.name().equals(
                index == 0 ? component.getDefaultFieldName() : component.getFieldName()), "member name/offset changed");
            var type = model.types().byKey().get(member.type().key());
            if (index == 0) {
                require(type instanceof TypeGraph.BaseType, "unqualified member gained qualifiers");
            }
            else {
                require(type instanceof TypeGraph.QualifiedType, "member mutability was dropped");
                var qualified = (TypeGraph.QualifiedType) type;
                require(qualified.qualifiers().equals(List.of(index == 1 ? TypeGraph.Qualifier.CONST : TypeGraph.Qualifier.VOLATILE)),
                    "member mutability changed");
                require(model.types().byKey().get(qualified.target().key()) instanceof TypeGraph.BaseType,
                    "member qualifier changed the shared underlying type");
            }
        }
        var bitAggregate = (TypeGraph.AggregateType) globalType(model, "bit_object");
        require(bitAggregate.members().stream().map(TypeGraph.Member::name).toList().equals(List.of("bits", "tail")),
            "alignment-only bitfield became a readable member");
        var tail = java.util.Arrays.stream(savedBits.getDefinedComponents()).filter(component -> "tail".equals(component.getFieldName()))
            .findFirst().orElseThrow();
        require(bitAggregate.members().get(0).bitSize() == 3 && bitAggregate.members().get(1).byteOffset() == tail.getOffset(),
            "zero-width alignment effect was lost");
        require(bitAggregate.members().get(0).storageByteSize() == 1
            && bitAggregate.members().get(0).storageBitOffset() == (program.getLanguage().isBigEndian() ? 5 : 0),
            "bitfield component storage was replaced by the four-byte base integer width");
        require(model.equals(GhidraTypeGraph.extract(program, List.of(), target, 0, TaskMonitor.DUMMY, ignored -> { })),
            "curated type extraction is not deterministic");
        for (long delta : new long[] { 0x10000, Long.MIN_VALUE }) {
            diagnostics.clear();
            var rejected = GhidraTypeGraph.extract(program, List.of(), target, delta, TaskMonitor.DUMMY, diagnostics::add);
            require(rejected.globals().isEmpty() && rejected.functionStatics().isEmpty(), "untranslatable address emitted a variable");
            String reason = delta == Long.MIN_VALUE ? "Skipped untranslatable global" : "Skipped unsupported global address";
            for (String name : List.of("wide_0", "wide_32", "wide_64", "qualified_object", "bit_object")) {
                require(diagnostics.stream().anyMatch(message -> message.contains(reason) && message.contains(name)),
                    "missing address omission diagnostic for " + name);
            }
        }
        require(program.getModificationNumber() == modification, "extraction modified analyst program state");
        System.out.println("curated-type-boundaries=PASS target=" + target + " checks=" + checks);
    }

    private static TypeGraph.TypeNode globalType(ProgramTypeModel model, String name) {
        var global = model.globals().stream().filter(value -> value.name().equals(name)).findFirst().orElseThrow();
        return model.types().byKey().get(global.type().key());
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
