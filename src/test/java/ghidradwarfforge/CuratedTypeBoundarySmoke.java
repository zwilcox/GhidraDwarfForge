package ghidradwarfforge;

import java.util.ArrayList;
import java.util.List;
import java.util.HexFormat;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.locations.VariableStorageModel.Confidence;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
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
        var character = new CharDataType(manager);
        program.getListing().createData(start.add(0x80), character);
        program.getSymbolTable().createLabel(start.add(0x80), "target_character", SourceType.USER_DEFINED);
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
        program.getSymbolTable().createLabel(start.add(0x510), "untyped_static", owner, SourceType.USER_DEFINED);
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
        require(diagnostics.stream().anyMatch(message -> message.contains("untyped_static")
            && message.contains("owning function was not exported")), "untyped orphan needs an owner diagnostic");
        require(model.functionStatics().isEmpty() && model.globals().stream().noneMatch(global ->
            global.name().equals("owned_static") || global.name().equals("untyped_static")),
            "unexported function's static was promoted to a global");
        for (int index = 0; index < 3; index++) {
            var node = globalType(model, "wide_" + index * 32);
            require(node instanceof TypeGraph.BaseType, "wide character lost primitive identity");
            var base = (TypeGraph.BaseType) node;
            int expected = index == 0 ? wideBytes : index == 1 ? 2 : 4;
            require(base.encoding() == TypeGraph.BaseEncoding.UTF && base.byteSize() == expected
                && base.valueByteSize() == expected, "wide character encoding/width differs from saved data organization");
        }
        var charType = (TypeGraph.BaseType) globalType(model, "target_character");
        require(charType.encoding() == (character.isSigned() ? TypeGraph.BaseEncoding.SIGNED_CHAR
            : TypeGraph.BaseEncoding.UNSIGNED_CHAR) && charType.byteSize() == character.getLength(),
            "character signedness/width differs from target data organization");
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
            var translated = GhidraTypeGraph.extract(program, List.of(), target, delta, TaskMonitor.DUMMY, diagnostics::add);
            for (var original : model.globals()) {
                var found = translated.globals().stream().filter(variable -> variable.name().equals(original.name())).findFirst();
                if (program.getDefaultPointerSize() == 8) {
                    require(found.isPresent() && found.get().address() == original.address() - delta,
                        "upper-half global translation changed " + original.name());
                }
                else {
                    require(found.isEmpty() && diagnostics.stream().anyMatch(message ->
                        message.contains("unsupported global address extent") && message.contains(original.name())),
                        "out-of-class global escaped or lacked a diagnostic for " + original.name());
                }
            }
        }
        require(program.getModificationNumber() == modification, "extraction modified analyst program state");
        sourceEvidence(program, target, start.add(0xa00));
        System.out.println("curated-type-boundaries=PASS target=" + target + " checks=" + checks);
    }

    private static void sourceEvidence(ProgramDB program, String target, Address start) throws Exception {
        String register = switch (target) {
            case "x86" -> "EAX";
            case "x86_64" -> "EDI";
            case "aarch64" -> "w0";
            case "arm" -> "r0";
            case "mips", "mipsel" -> "a1";
            default -> throw new AssertionError("missing fixture profile " + target);
        };
        String code = switch (target) {
            case "x86", "x86_64" -> "90c3";
            case "aarch64" -> "1f2003d5c0035fd6";
            case "arm" -> "00f020e31eff2fe1";
            case "mips" -> "03e0000800000000";
            case "mipsel" -> "0800e00300000000";
            default -> throw new AssertionError("missing fixture profile " + target);
        };
        byte[] bytes = HexFormat.of().parseHex(code);
        var sources = List.of(SourceType.USER_DEFINED, SourceType.IMPORTED, SourceType.AI,
            SourceType.ANALYSIS, SourceType.DEFAULT);
        var confidences = List.of(Confidence.USER_DEFINED, Confidence.IMPORTED, Confidence.DECOMPILER,
            Confidence.ANALYSIS, Confidence.ANALYSIS);
        var symbols = new ArrayList<FunctionSymbol>();
        var functions = new ArrayList<Function>();
        for (int index = 0; index < sources.size(); index++) {
            Address entry = start.add(index * 64);
            var body = new AddressSet(entry, entry.add(bytes.length - 1));
            program.getMemory().setBytes(entry, bytes);
            if (target.equals("arm")) {
                program.getProgramContext().setValue(program.getRegister("TMode"), entry,
                    body.getMaxAddress(), java.math.BigInteger.ZERO);
            }
            require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY),
                "evidence fixture decode");
            String name = "evidence_" + index;
            var function = program.getFunctionManager().createFunction(name, entry, body, SourceType.USER_DEFINED);
            SourceType source = sources.get(index);
            function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED,
                new ParameterImpl(source == SourceType.DEFAULT ? null : "input", IntegerDataType.dataType,
                    program.getRegister(register), program, source));
            require(function.getParameter(0).getSource() == source, "saved parameter provenance changed");
            functions.add(function);
            symbols.add(new FunctionSymbol(name, entry.getOffset(), bytes.length));
        }
        symbols.add(new FunctionSymbol("missing_signature", start.add(0x300).getOffset(), 4));
        long modification = program.getModificationNumber();
        var diagnostics = new ArrayList<String>();
        var model = GhidraTypeGraph.extract(program, symbols, target, 0, TaskMonitor.DUMMY, diagnostics::add);
        require(model.functions().size() == sources.size(), "missing function gained an invented signature");
        require(diagnostics.stream().filter(message -> message.equals(
            "No Ghidra signature found for exported function missing_signature")).count() == 1,
            "missing signature must have a diagnostic");
        for (int index = 0; index < sources.size(); index++) {
            var function = functions.get(index);
            var variables = model.variableStorage().variables().stream()
                .filter(value -> value.functionAddress() == function.getEntryPoint().getOffset()).toList();
            require(variables.size() == 1, "parameter lost or duplicated");
            var variable = variables.getFirst();
            require(variable.name().equals(function.getParameter(0).getName()), "parameter name changed");
            var expected = confidences.get(index);
            String origin = sources.get(index).toString();
            require(variable.locations().stream().allMatch(location -> location.storage().available()
                && location.evidence().confidence() == expected
                && location.evidence().source().contains("(" + origin + ")")),
                "parameter provenance or proven location changed: " + origin);
        }
        require(program.getModificationNumber() == modification, "evidence extraction changed saved state");
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
