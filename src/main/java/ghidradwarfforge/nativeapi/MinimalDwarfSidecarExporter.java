package ghidradwarfforge.nativeapi;

import static ghidradwarfforge.nativeapi.DwarfConstants.DW_AT_HIGH_PC;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_AT_LANGUAGE;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_AT_LOW_PC;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_AT_STMT_LIST;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_AT_RANGES;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_AT_LOCATION;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_AT_DECL_FILE;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_AT_DECL_LINE;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_AT_DECLARATION;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_AT_ARTIFICIAL;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_AT_BIT_SIZE;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_AT_BYTE_SIZE;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_AT_CALLING_CONVENTION;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_AT_CONST_VALUE;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_AT_COUNT;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_AT_DATA_BIT_OFFSET;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_AT_DATA_MEMBER_LOCATION;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_AT_ENCODING;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_AT_EXTERNAL;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_AT_NORETURN;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_AT_PROTOTYPED;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_AT_TYPE;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLV_OK;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_FORM_STRP;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_LANG_C11;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_TAG_COMPILE_UNIT;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_TAG_SUBPROGRAM;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_TAG_ARRAY_TYPE;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_TAG_ATOMIC_TYPE;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_TAG_BASE_TYPE;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_TAG_CONST_TYPE;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_TAG_ENUMERATION_TYPE;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_TAG_ENUMERATOR;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_TAG_FORMAL_PARAMETER;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_TAG_MEMBER;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_TAG_NAMESPACE;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_TAG_POINTER_TYPE;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_TAG_REFERENCE_TYPE;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_TAG_RESTRICT_TYPE;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_TAG_RVALUE_REFERENCE_TYPE;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_TAG_STRUCTURE_TYPE;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_TAG_SUBRANGE_TYPE;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_TAG_SUBROUTINE_TYPE;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_TAG_TYPEDEF;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_TAG_UNION_TYPE;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_TAG_UNSPECIFIED_PARAMETERS;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_TAG_UNSPECIFIED_TYPE;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_TAG_VOLATILE_TYPE;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_TAG_VARIABLE;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_ATE_ADDRESS;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_ATE_BOOLEAN;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_ATE_FLOAT;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_ATE_SIGNED;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_ATE_SIGNED_CHAR;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_ATE_UNSIGNED;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_ATE_UNSIGNED_CHAR;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_ATE_UTF;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_CC_NORMAL;
import static ghidradwarfforge.nativeapi.DwarfConstants.DWARF_DRD_BUFFER_VERSION;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.LongByReference;
import com.sun.jna.ptr.PointerByReference;

import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.elf.MatchedElfSidecarWriter;
import ghidradwarfforge.dwarf.Dwarf5LineTable;
import ghidradwarfforge.dwarf.Dwarf5LocationLists;
import ghidradwarfforge.dwarf.Dwarf5RangeLists;
import ghidradwarfforge.dwarf.Dwarf32InfoRepair;
import ghidradwarfforge.dwarf.DwarfLocationExpression;
import ghidradwarfforge.dwarf.DwarfLocationExpression.AddressOperation;
import ghidradwarfforge.dwarf.DwarfLocationExpression.Expression;
import ghidradwarfforge.dwarf.DwarfLocationExpression.GenericOperation;
import ghidradwarfforge.dwarf.DwarfLocationExpression.Operation;
import ghidradwarfforge.locations.VariableStorageModel.VariableKind;
import ghidradwarfforge.locations.VariableStorageModel.VariableLocation;
import ghidradwarfforge.nativeapi.DwarfNativeTypes.Debug;
import ghidradwarfforge.nativeapi.DwarfNativeTypes.Die;
import ghidradwarfforge.nativeapi.DwarfNativeTypes.Error;
import ghidradwarfforge.nativeapi.DwarfNativeTypes.Expr;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.source.SyntheticSourceFile.FunctionLines;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.AggregateType;
import ghidradwarfforge.types.TypeGraph.ArrayType;
import ghidradwarfforge.types.TypeGraph.BaseType;
import ghidradwarfforge.types.TypeGraph.EnumType;
import ghidradwarfforge.types.TypeGraph.IndirectionType;
import ghidradwarfforge.types.TypeGraph.OpaqueType;
import ghidradwarfforge.types.TypeGraph.QualifiedType;
import ghidradwarfforge.types.TypeGraph.SubroutineType;
import ghidradwarfforge.types.TypeGraph.TypeNode;
import ghidradwarfforge.types.TypeGraph.TypeRef;
import ghidradwarfforge.types.TypeGraph.TypedefType;
import ghidradwarfforge.types.TypeGraph.VoidType;

/**
 * Production milestone: one DWARF 5 CU containing named, contiguous
 * subprograms, an optional synthetic-source line table, and an optional
 * canonical type/signature graph, discontiguous range lists, defined
 * memory-backed globals, stable variable locations, and DWARF 5 location lists
 * supplied by the canonical model. Ghidra storage extraction remains separate.
 */
public final class MinimalDwarfSidecarExporter {
    private static final String LIBDWARF_VERSION = "2.3.2";
    private static final long TEXT_SYMBOL_INDEX = 0x1001L;

    public record FunctionRange(long address, long size) {
        public FunctionRange {
            if (address < 0 || size <= 0 || Math.addExact(address, size) <= address) {
                throw new IllegalArgumentException("invalid function address range");
            }
        }

        public long endExclusive() {
            return Math.addExact(address, size);
        }

        public boolean contains(long candidate) {
            return candidate >= address && candidate < endExclusive();
        }
    }

    public record FunctionSymbol(String name, long address, List<FunctionRange> ranges) {
        public FunctionSymbol(String name, long address, long size) {
            this(name, address, List.of(new FunctionRange(address, size)));
        }

        public FunctionSymbol {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("function name is required");
            }
            if (address < 0 || ranges == null || ranges.isEmpty()) {
                throw new IllegalArgumentException("function ranges are required for " + name);
            }
            ranges = List.copyOf(ranges);
            long previousEnd = -1;
            for (FunctionRange range : ranges) {
                if (range.address() < previousEnd) {
                    throw new IllegalArgumentException(
                        "function ranges overlap or are unsorted for " + name);
                }
                previousEnd = range.endExclusive();
            }
            if (ranges.get(0).address() != address) {
                throw new IllegalArgumentException(
                    "function entry does not begin its first range for " + name);
            }
        }

        public boolean contiguous() {
            return ranges.size() == 1;
        }

        public long size() {
            if (!contiguous()) {
                throw new IllegalStateException("discontiguous function has no single size: " + name);
            }
            return ranges.get(0).size();
        }

        public boolean contains(long candidate) {
            return ranges.stream().anyMatch(range -> range.contains(candidate));
        }
    }

    public record ExportResult(DwarfTarget target, int functionCount,
            List<String> sectionNames, String libdwarfVersion) {
    }

    private record SectionRecord(String name, long symbolIndex) {
    }

    private record AllocatedType(Die primary, List<Die> related) {
    }

    private record VariableKey(long functionAddress, VariableKind kind, String name) {
    }

    @Structure.FieldOrder({ "type", "length", "offset", "symbolIndex" })
    public static final class RelocationData extends Structure {
        public byte type;
        public byte length;
        public long offset;
        public long symbolIndex;

        public RelocationData() {
        }

        public RelocationData(Pointer pointer) {
            super(pointer);
            read();
        }
    }

    public ExportResult export(Path input, Path output, Path consumerLibrary,
            Path producerLibrary, List<FunctionSymbol> functions) throws IOException {
        return export(input, output, consumerLibrary, producerLibrary, functions, null, null);
    }

    public ExportResult export(Path input, Path output, Path consumerLibrary,
            Path producerLibrary, List<FunctionSymbol> functions,
            SyntheticSourceFile syntheticSource) throws IOException {
        return export(input, output, consumerLibrary, producerLibrary, functions,
            syntheticSource, null);
    }

    public ExportResult export(Path input, Path output, Path consumerLibrary,
            Path producerLibrary, List<FunctionSymbol> functions,
            SyntheticSourceFile syntheticSource, ProgramTypeModel typeModel)
            throws IOException {
        return export(input, output, consumerLibrary, producerLibrary, functions,
            syntheticSource, typeModel,
            output.toAbsolutePath().normalize().getFileName() + ".c");
    }

    public ExportResult export(Path input, Path output, Path consumerLibrary,
            Path producerLibrary, List<FunctionSymbol> functions,
            SyntheticSourceFile syntheticSource, ProgramTypeModel typeModel,
            String sourceFileName) throws IOException {
        Path source = requireFile(input, "input ELF");
        Path consumerPath = requireFile(consumerLibrary, "libdwarf");
        Path producerPath = requireFile(producerLibrary, "libdwarfp");
        if (functions.isEmpty()) {
            throw new IllegalArgumentException("at least one function is required");
        }
        List<FunctionSymbol> ordered = new ArrayList<>(functions);
        ordered.sort(Comparator.comparingLong(FunctionSymbol::address)
            .thenComparing(FunctionSymbol::name));

        ElfImage elf = ElfImage.read(source);
        DwarfTarget target = DwarfTarget.fromElf(elf);
        LibDwarfConsumer consumer = Native.load(consumerPath.toString(), LibDwarfConsumer.class);
        LibDwarfProducer producer = Native.load(producerPath.toString(), LibDwarfProducer.class);
        String version = consumer.dwarf_package_version();
        if (!LIBDWARF_VERSION.equals(version)) {
            throw new IllegalStateException(
                "expected libdwarf " + LIBDWARF_VERSION + ", found " + version);
        }

        if (sourceFileName == null || sourceFileName.isBlank() ||
                sourceFileName.contains("/") || sourceFileName.contains("\\")) {
            throw new IllegalArgumentException("synthetic source filename is invalid");
        }
        String unitName = sourceFileName;
        byte[] lineTable = syntheticSource == null ? new byte[0] : Dwarf5LineTable.build(
            unitName, target.addressBytes(), elf.byteOrder(), ordered,
            syntheticSource.mappedLines());
        Dwarf5RangeLists.Result rangeLists = Dwarf5RangeLists.build(ordered,
            target.addressBytes(), elf.byteOrder());
        Dwarf5LocationLists.Result locationLists = Dwarf5LocationLists.build(
            typeModel == null ? List.of() : typeModel.variableStorage().variables(),
            target.addressBytes(), elf.byteOrder());
        Map<String, byte[]> sections = produce(producer, consumer, target, ordered,
            unitName, syntheticSource, typeModel, lineTable, rangeLists, locationLists,
            elf.byteOrder());
        new MatchedElfSidecarWriter().write(source, output, sections);
        return new ExportResult(target, ordered.size(), List.copyOf(sections.keySet()),
            version);
    }

    private static Map<String, byte[]> produce(LibDwarfProducer producer,
            LibDwarfConsumer consumer, DwarfTarget target, List<FunctionSymbol> functions,
            String unitName, SyntheticSourceFile syntheticSource, ProgramTypeModel typeModel,
            byte[] lineTable, Dwarf5RangeLists.Result rangeLists,
            Dwarf5LocationLists.Result locationLists,
            ByteOrder byteOrder) {
        Map<Long, SectionRecord> sections = new LinkedHashMap<>();
        long[] nextSection = { 1 };
        long[] nextSymbol = { 1 };
        LibDwarfProducer.SectionCallback callback = (name, size, type, flags, link, info,
                sectionSymbol, userData, callbackError) -> {
            long index = nextSection[0]++;
            long symbol = nextSymbol[0]++;
            sectionSymbol.setValue(symbol);
            sections.put(index, new SectionRecord(Objects.requireNonNull(name), symbol));
            return Math.toIntExact(index);
        };

        PointerByReference errorOut = new PointerByReference();
        PointerByReference debugOut = new PointerByReference();
        check(producer.dwarf_producer_init(target.producerFlags(), callback, null, null,
            null, target.producerIsa(), "V5", "", debugOut, errorOut),
            "dwarf_producer_init", errorOut, consumer);
        Debug debug = new Debug(pointer(debugOut, "producer debug"));
        boolean finished = false;
        try {
            check(producer.dwarf_pro_set_default_string_form(debug, DW_FORM_STRP, errorOut),
                "dwarf_pro_set_default_string_form", errorOut, consumer);
            Die unit = newDie(producer, consumer, debug, DW_TAG_COMPILE_UNIT, null, errorOut);
            addName(producer, consumer, unit, unitName, errorOut);
            addProducer(producer, consumer, unit, errorOut);
            addUnsigned(producer, consumer, debug, unit, DW_AT_LANGUAGE, DW_LANG_C11,
                errorOut);
            Map<String, AllocatedType> allocatedTypes = allocateTypes(producer, consumer,
                debug, unit, typeModel, errorOut);
            populateTypes(producer, consumer, debug, typeModel, allocatedTypes, byteOrder,
                errorOut);
            Map<List<String>, Die> namespaceDies = allocateNamespaces(producer, consumer,
                debug, unit, typeModel, errorOut);
            Map<FunctionKey, FunctionLines> sourceFunctions = sourceFunctions(syntheticSource);
            Map<FunctionKey, ProgramTypeModel.FunctionSignature> signatures =
                functionSignatures(typeModel);
            Map<VariableKey, VariableLocation> variableLocations =
                variableLocations(typeModel);
            long fileIndex = 0;
            if (lineTable.length != 0) {
                addSectionOffset(producer, consumer, debug, unit, DW_AT_STMT_LIST, 0,
                    errorOut);
            }
            if (!rangeLists.empty()) {
                addSectionOffset(producer, consumer, debug, unit, DW_AT_RANGES,
                    rangeLists.compilationUnitOffset(), errorOut);
            }
            for (FunctionSymbol function : functions) {
                Die die = newDie(producer, consumer, debug, DW_TAG_SUBPROGRAM, unit, errorOut);
                addName(producer, consumer, die, function.name(), errorOut);
                if (function.contiguous()) {
                    addAddress(producer, consumer, debug, die, function.address(), errorOut);
                    addUnsigned(producer, consumer, debug, die, DW_AT_HIGH_PC, function.size(),
                        errorOut);
                }
                else {
                    Long offset = rangeLists.functionOffsets().get(function);
                    if (offset == null) {
                        throw new IllegalStateException("missing range list for " + function.name());
                    }
                    addSectionOffset(producer, consumer, debug, die, DW_AT_RANGES, offset,
                        errorOut);
                }
                FunctionLines sourceFunction = sourceFunctions.get(FunctionKey.of(function));
                boolean sourceFailed = sourceFunction != null && !sourceFunction.decompiled();
                if (sourceFunction != null && sourceFunction.decompiled()) {
                    addUnsigned(producer, consumer, debug, die, DW_AT_DECL_FILE, fileIndex,
                        errorOut);
                    addUnsigned(producer, consumer, debug, die, DW_AT_DECL_LINE,
                        declarationLine(sourceFunction, syntheticSource), errorOut);
                }
                ProgramTypeModel.FunctionSignature signature = sourceFailed ? null :
                    signatures.get(FunctionKey.of(function));
                if (signature != null) {
                    addFlag(producer, consumer, debug, die, DW_AT_PROTOTYPED, true,
                        errorOut);
                    if (knownCallingConvention(signature.callingConvention())) {
                        addUnsigned(producer, consumer, debug, die,
                            DW_AT_CALLING_CONVENTION, DW_CC_NORMAL, errorOut);
                    }
                    addTypeReference(producer, consumer, debug, die,
                        signature.returnType(), typeModel.types(), allocatedTypes, errorOut);
                    if (signature.noReturn()) {
                        addFlag(producer, consumer, debug, die, DW_AT_NORETURN, true,
                            errorOut);
                    }
                    for (TypeGraph.Parameter parameter : signature.parameters()) {
                        Die parameterDie = newDie(producer, consumer, debug,
                            DW_TAG_FORMAL_PARAMETER, die, errorOut);
                        if (!parameter.name().isBlank()) {
                            addName(producer, consumer, parameterDie, parameter.name(), errorOut);
                        }
                        addTypeReference(producer, consumer, debug, parameterDie,
                            parameter.type(), typeModel.types(), allocatedTypes, errorOut);
                        if (parameter.artificial()) {
                            addFlag(producer, consumer, debug, parameterDie,
                                DW_AT_ARTIFICIAL, true, errorOut);
                        }
                        addVariableLocation(producer, consumer, debug, parameterDie,
                            variableLocations.get(new VariableKey(function.address(),
                                VariableKind.PARAMETER, parameter.name())), locationLists,
                            errorOut);
                    }
                    if (signature.variadic()) {
                        newDie(producer, consumer, debug, DW_TAG_UNSPECIFIED_PARAMETERS,
                            die, errorOut);
                    }
                    for (ProgramTypeModel.LocalVariable local : signature.locals()) {
                        Die localDie = newDie(producer, consumer, debug, DW_TAG_VARIABLE, die,
                            errorOut);
                        addName(producer, consumer, localDie, local.name(), errorOut);
                        addTypeReference(producer, consumer, debug, localDie, local.type(),
                            typeModel.types(), allocatedTypes, errorOut);
                        addVariableLocation(producer, consumer, debug, localDie,
                            variableLocations.get(new VariableKey(function.address(),
                                VariableKind.LOCAL, local.name())), locationLists, errorOut);
                    }
                }
            }
            if (typeModel != null) {
                for (ProgramTypeModel.GlobalVariable global : typeModel.globals()) {
                    Die die = newDie(producer, consumer, debug, DW_TAG_VARIABLE,
                        namespaceParent(global.namespace(), namespaceDies, unit), errorOut);
                    addName(producer, consumer, die, global.name(), errorOut);
                    addTypeReference(producer, consumer, debug, die, global.type(),
                        typeModel.types(), allocatedTypes, errorOut);
                    if (global.declaration()) {
                        addFlag(producer, consumer, debug, die, DW_AT_DECLARATION, true,
                            errorOut);
                        addFlag(producer, consumer, debug, die, DW_AT_EXTERNAL, true,
                            errorOut);
                    }
                    else {
                        addAddressLocation(producer, consumer, debug, die, global.address(),
                            errorOut);
                    }
                }
            }
            check(producer.dwarf_add_die_to_debug_a(debug, unit, errorOut),
                "dwarf_add_die_to_debug_a", errorOut, consumer);

            LongByReference bufferCount = new LongByReference();
            check(producer.dwarf_transform_to_disk_form_a(debug, bufferCount, errorOut),
                "dwarf_transform_to_disk_form_a", errorOut, consumer);
            Map<Long, byte[]> bytes = collect(producer, consumer, debug, errorOut,
                bufferCount.getValue(), sections);
            validateRelocations(producer, consumer, debug, errorOut, sections, bytes,
                functions, typeModel, target.addressBytes(), byteOrder);

            Map<String, byte[]> result = new LinkedHashMap<>();
            sections.forEach((index, section) -> {
                byte[] data = bytes.get(index);
                if (section.name().startsWith(".debug_") && data != null && data.length != 0) {
                    if (result.put(section.name(), data) != null) {
                        throw new IllegalStateException("duplicate section " + section.name());
                    }
                }
            });
            if (lineTable.length != 0 || !rangeLists.empty() || !locationLists.empty()) {
                result.put(".debug_info", Dwarf32InfoRepair.repair(
                    Objects.requireNonNull(result.get(".debug_info"), ".debug_info"),
                    Objects.requireNonNull(result.get(".debug_abbrev"), ".debug_abbrev"),
                    target.addressBytes(), byteOrder));
            }
            if (lineTable.length != 0) {
                result.put(".debug_line", lineTable.clone());
            }
            if (!rangeLists.empty()) {
                result.put(".debug_rnglists", rangeLists.section());
            }
            if (!locationLists.empty()) {
                result.put(".debug_loclists", locationLists.section());
            }
            if (!result.containsKey(".debug_info") ||
                    !result.containsKey(".debug_abbrev") ||
                    !result.containsKey(".debug_str")) {
                throw new IllegalStateException("producer omitted required DWARF sections");
            }

            check(producer.dwarf_producer_finish_a(debug, errorOut),
                "dwarf_producer_finish_a", errorOut, consumer);
            finished = true;
            return result;
        }
        finally {
            if (!finished) {
                producer.dwarf_producer_finish_a(debug, new PointerByReference());
            }
        }
    }

    private static Map<List<String>, Die> allocateNamespaces(LibDwarfProducer producer,
            LibDwarfConsumer consumer, Debug debug, Die unit, ProgramTypeModel typeModel,
            PointerByReference errorOut) {
        List<List<String>> paths = new ArrayList<>();
        if (typeModel != null) {
            for (ProgramTypeModel.GlobalVariable global : typeModel.globals()) {
                addNamespacePrefixes(paths, global.namespace());
            }
        }
        paths = paths.stream().distinct()
            .sorted(Comparator.comparing(path -> String.join("\u0000", path))).toList();
        Map<List<String>, Die> result = new LinkedHashMap<>();
        for (List<String> path : paths) {
            List<String> parentPath = path.subList(0, path.size() - 1);
            Die parent = parentPath.isEmpty() ? unit : Objects.requireNonNull(
                result.get(parentPath), "namespace parent " + parentPath);
            Die die = newDie(producer, consumer, debug, DW_TAG_NAMESPACE, parent, errorOut);
            addName(producer, consumer, die, path.get(path.size() - 1), errorOut);
            result.put(path, die);
        }
        return result;
    }

    private static void addNamespacePrefixes(List<List<String>> paths, List<String> path) {
        for (int length = 1; length <= path.size(); length++) {
            paths.add(List.copyOf(path.subList(0, length)));
        }
    }

    private static Die namespaceParent(List<String> path,
            Map<List<String>, Die> namespaceDies, Die unit) {
        return path.isEmpty() ? unit : Objects.requireNonNull(namespaceDies.get(path),
            "namespace " + path);
    }

    private static Map<FunctionKey, ProgramTypeModel.FunctionSignature>
            functionSignatures(ProgramTypeModel model) {
        if (model == null) {
            return Map.of();
        }
        Map<FunctionKey, ProgramTypeModel.FunctionSignature> result = new HashMap<>();
        for (ProgramTypeModel.FunctionSignature function : model.functions()) {
            FunctionKey key = new FunctionKey(function.name(), function.address());
            if (result.put(key, function) != null) {
                throw new IllegalArgumentException("duplicate function signature " + key);
            }
        }
        return result;
    }

    private static Map<VariableKey, VariableLocation> variableLocations(
            ProgramTypeModel model) {
        if (model == null) {
            return Map.of();
        }
        Map<VariableKey, VariableLocation> result = new HashMap<>();
        for (VariableLocation variable : model.variableStorage().variables()) {
            VariableKey key = new VariableKey(variable.functionAddress(), variable.kind(),
                variable.name());
            if (result.put(key, variable) != null) {
                throw new IllegalArgumentException("duplicate variable location " + key);
            }
        }
        return result;
    }

    private static Map<String, AllocatedType> allocateTypes(LibDwarfProducer producer,
            LibDwarfConsumer consumer, Debug debug, Die unit, ProgramTypeModel model,
            PointerByReference errorOut) {
        if (model == null) {
            return Map.of();
        }
        Map<String, AllocatedType> result = new LinkedHashMap<>();
        for (TypeNode node : model.types().nodes()) {
            if (node instanceof VoidType) {
                continue;
            }
            List<Die> related = new ArrayList<>();
            Die primary;
            if (node instanceof QualifiedType qualified) {
                for (TypeGraph.Qualifier qualifier : qualified.qualifiers()) {
                    related.add(newDie(producer, consumer, debug,
                        qualifierTag(qualifier), unit, errorOut));
                }
                primary = related.get(0);
            }
            else {
                primary = newDie(producer, consumer, debug, typeTag(node), unit, errorOut);
                if (node instanceof ArrayType) {
                    related.add(newDie(producer, consumer, debug, DW_TAG_SUBRANGE_TYPE,
                        primary, errorOut));
                }
                else if (node instanceof EnumType enumeration) {
                    for (int index = 0; index < enumeration.values().size(); index++) {
                        related.add(newDie(producer, consumer, debug, DW_TAG_ENUMERATOR,
                            primary, errorOut));
                    }
                }
                else if (node instanceof AggregateType aggregate) {
                    for (int index = 0; index < aggregate.members().size(); index++) {
                        related.add(newDie(producer, consumer, debug, DW_TAG_MEMBER,
                            primary, errorOut));
                    }
                }
                else if (node instanceof SubroutineType subroutine) {
                    for (int index = 0; index < subroutine.parameters().size(); index++) {
                        related.add(newDie(producer, consumer, debug,
                            DW_TAG_FORMAL_PARAMETER, primary, errorOut));
                    }
                    if (subroutine.variadic()) {
                        related.add(newDie(producer, consumer, debug,
                            DW_TAG_UNSPECIFIED_PARAMETERS, primary, errorOut));
                    }
                }
            }
            result.put(node.key(), new AllocatedType(primary, List.copyOf(related)));
        }
        return result;
    }

    private static void populateTypes(LibDwarfProducer producer,
            LibDwarfConsumer consumer, Debug debug, ProgramTypeModel model,
            Map<String, AllocatedType> allocated, ByteOrder byteOrder,
            PointerByReference errorOut) {
        if (model == null) {
            return;
        }
        Map<String, TypeNode> nodes = model.types().byKey();
        for (TypeNode node : model.types().nodes()) {
            if (node instanceof VoidType) {
                continue;
            }
            AllocatedType allocation = Objects.requireNonNull(allocated.get(node.key()),
                "allocated type " + node.key());
            Die die = allocation.primary();
            if (node instanceof BaseType base) {
                addName(producer, consumer, die, base.name(), errorOut);
                addUnsigned(producer, consumer, debug, die, DW_AT_BYTE_SIZE,
                    base.byteSize(), errorOut);
                addUnsigned(producer, consumer, debug, die, DW_AT_ENCODING,
                    baseEncoding(base.encoding()), errorOut);
            }
            else if (node instanceof IndirectionType indirection) {
                addUnsigned(producer, consumer, debug, die, DW_AT_BYTE_SIZE,
                    indirection.byteSize(), errorOut);
                addTypeReference(producer, consumer, debug, die, indirection.target(),
                    model.types(), allocated, errorOut);
            }
            else if (node instanceof QualifiedType qualified) {
                for (int index = 0; index < allocation.related().size(); index++) {
                    Die target = index + 1 < allocation.related().size()
                        ? allocation.related().get(index + 1) : typeDie(qualified.target(),
                            model.types(), allocated);
                    if (target != null) {
                        addReference(producer, consumer, debug,
                            allocation.related().get(index), DW_AT_TYPE, target, errorOut);
                    }
                }
            }
            else if (node instanceof ArrayType array) {
                addTypeReference(producer, consumer, debug, die, array.element(),
                    model.types(), allocated, errorOut);
                if (array.byteSize() > 0) {
                    addUnsigned(producer, consumer, debug, die, DW_AT_BYTE_SIZE,
                        array.byteSize(), errorOut);
                }
                addUnsigned(producer, consumer, debug, allocation.related().get(0),
                    DW_AT_COUNT, array.elementCount(), errorOut);
            }
            else if (node instanceof TypedefType typedef) {
                addName(producer, consumer, die, typedef.name(), errorOut);
                addTypeReference(producer, consumer, debug, die, typedef.target(),
                    model.types(), allocated, errorOut);
            }
            else if (node instanceof EnumType enumeration) {
                addName(producer, consumer, die, enumeration.name(), errorOut);
                addUnsigned(producer, consumer, debug, die, DW_AT_BYTE_SIZE,
                    enumeration.byteSize(), errorOut);
                addUnsigned(producer, consumer, debug, die, DW_AT_ENCODING,
                    enumeration.signed() ? DW_ATE_SIGNED : DW_ATE_UNSIGNED, errorOut);
                for (int index = 0; index < enumeration.values().size(); index++) {
                    TypeGraph.Enumerator value = enumeration.values().get(index);
                    Die valueDie = allocation.related().get(index);
                    addName(producer, consumer, valueDie, value.name(), errorOut);
                    if (enumeration.signed()) {
                        addSigned(producer, consumer, debug, valueDie,
                            DW_AT_CONST_VALUE, value.value(), errorOut);
                    }
                    else {
                        addUnsigned(producer, consumer, debug, valueDie,
                            DW_AT_CONST_VALUE, value.value(), errorOut);
                    }
                }
            }
            else if (node instanceof AggregateType aggregate) {
                addName(producer, consumer, die, aggregate.name(), errorOut);
                if (aggregate.byteSize() > 0) {
                    addUnsigned(producer, consumer, debug, die, DW_AT_BYTE_SIZE,
                        aggregate.byteSize(), errorOut);
                }
                for (int index = 0; index < aggregate.members().size(); index++) {
                    TypeGraph.Member member = aggregate.members().get(index);
                    Die memberDie = allocation.related().get(index);
                    addName(producer, consumer, memberDie, member.name(), errorOut);
                    addTypeReference(producer, consumer, debug, memberDie, member.type(),
                        model.types(), allocated, errorOut);
                    addUnsigned(producer, consumer, debug, memberDie,
                        DW_AT_DATA_MEMBER_LOCATION, member.byteOffset(), errorOut);
                    if (member.bitSize() > 0) {
                        addUnsigned(producer, consumer, debug, memberDie, DW_AT_BIT_SIZE,
                            member.bitSize(), errorOut);
                        addUleb(producer, consumer, memberDie,
                            DW_AT_DATA_BIT_OFFSET,
                            dataBitOffset(member, nodes, byteOrder), errorOut);
                    }
                }
            }
            else if (node instanceof SubroutineType subroutine) {
                addName(producer, consumer, die, subroutine.name(), errorOut);
                addFlag(producer, consumer, debug, die, DW_AT_PROTOTYPED, true,
                    errorOut);
                addTypeReference(producer, consumer, debug, die, subroutine.returnType(),
                    model.types(), allocated, errorOut);
                for (int index = 0; index < subroutine.parameters().size(); index++) {
                    TypeGraph.Parameter parameter = subroutine.parameters().get(index);
                    Die parameterDie = allocation.related().get(index);
                    if (!parameter.name().isBlank()) {
                        addName(producer, consumer, parameterDie, parameter.name(), errorOut);
                    }
                    addTypeReference(producer, consumer, debug, parameterDie,
                        parameter.type(), model.types(), allocated, errorOut);
                }
            }
            else if (node instanceof OpaqueType opaque) {
                addName(producer, consumer, die, opaque.name(), errorOut);
            }
        }
    }

    private static long typeTag(TypeNode node) {
        if (node instanceof BaseType) {
            return DW_TAG_BASE_TYPE;
        }
        if (node instanceof IndirectionType indirection) {
            return switch (indirection.kind()) {
                case POINTER -> DW_TAG_POINTER_TYPE;
                case LVALUE_REFERENCE -> DW_TAG_REFERENCE_TYPE;
                case RVALUE_REFERENCE -> DW_TAG_RVALUE_REFERENCE_TYPE;
            };
        }
        if (node instanceof ArrayType) {
            return DW_TAG_ARRAY_TYPE;
        }
        if (node instanceof TypedefType) {
            return DW_TAG_TYPEDEF;
        }
        if (node instanceof EnumType) {
            return DW_TAG_ENUMERATION_TYPE;
        }
        if (node instanceof AggregateType aggregate) {
            return aggregate.kind() == TypeGraph.AggregateKind.STRUCTURE
                ? DW_TAG_STRUCTURE_TYPE : DW_TAG_UNION_TYPE;
        }
        if (node instanceof SubroutineType) {
            return DW_TAG_SUBROUTINE_TYPE;
        }
        if (node instanceof OpaqueType) {
            return DW_TAG_UNSPECIFIED_TYPE;
        }
        throw new IllegalArgumentException("unsupported type node " + node.getClass());
    }

    private static long qualifierTag(TypeGraph.Qualifier qualifier) {
        return switch (qualifier) {
            case ATOMIC -> DW_TAG_ATOMIC_TYPE;
            case CONST -> DW_TAG_CONST_TYPE;
            case RESTRICT -> DW_TAG_RESTRICT_TYPE;
            case VOLATILE -> DW_TAG_VOLATILE_TYPE;
        };
    }

    private static long baseEncoding(TypeGraph.BaseEncoding encoding) {
        return switch (encoding) {
            case ADDRESS -> DW_ATE_ADDRESS;
            case BOOLEAN -> DW_ATE_BOOLEAN;
            case FLOAT -> DW_ATE_FLOAT;
            case SIGNED -> DW_ATE_SIGNED;
            case SIGNED_CHAR -> DW_ATE_SIGNED_CHAR;
            case UNSIGNED -> DW_ATE_UNSIGNED;
            case UNSIGNED_CHAR -> DW_ATE_UNSIGNED_CHAR;
            case UTF -> DW_ATE_UTF;
        };
    }

    private static boolean knownCallingConvention(String callingConvention) {
        return callingConvention != null && !callingConvention.isBlank() &&
            !callingConvention.equals("unknown");
    }

    private static long dataBitOffset(TypeGraph.Member member,
            Map<String, TypeNode> nodes, ByteOrder byteOrder) {
        long memberStart = Math.multiplyExact(member.byteOffset(), 8L);
        if (byteOrder == ByteOrder.LITTLE_ENDIAN) {
            return Math.addExact(memberStart, member.storageBitOffset());
        }
        TypeNode storageType = Objects.requireNonNull(nodes.get(member.type().key()),
            "bit-field storage type");
        long storageBits = Math.multiplyExact(storageType.byteSize(), 8L);
        long fromHighEnd = Math.addExact(member.storageBitOffset(), member.bitSize());
        if (fromHighEnd > storageBits) {
            throw new IllegalArgumentException("bit field exceeds its storage type");
        }
        return Math.addExact(memberStart, storageBits - fromHighEnd);
    }

    private static void addTypeReference(LibDwarfProducer producer,
            LibDwarfConsumer consumer, Debug debug, Die owner, TypeRef reference,
            TypeGraph graph, Map<String, AllocatedType> allocated,
            PointerByReference errorOut) {
        Die target = typeDie(reference, graph, allocated);
        if (target != null) {
            addReference(producer, consumer, debug, owner, DW_AT_TYPE, target, errorOut);
        }
    }

    private static Die typeDie(TypeRef reference, TypeGraph graph,
            Map<String, AllocatedType> allocated) {
        TypeNode targetNode = graph.byKey().get(reference.key());
        if (targetNode == null) {
            throw new IllegalArgumentException("missing referenced type " + reference.key());
        }
        if (targetNode instanceof VoidType) {
            return null;
        }
        AllocatedType target = allocated.get(reference.key());
        if (target == null) {
            throw new IllegalArgumentException("unallocated referenced type " + reference.key());
        }
        return target.primary();
    }

    private static Map<Long, byte[]> collect(LibDwarfProducer producer,
            LibDwarfConsumer consumer, Debug debug, PointerByReference errorOut,
            long bufferCount, Map<Long, SectionRecord> sections) {
        if (bufferCount <= 0 || bufferCount > 100_000) {
            throw new IllegalStateException("invalid producer buffer count " + bufferCount);
        }
        Map<Long, ByteArrayOutputStream> accumulated = new HashMap<>();
        for (long index = 0; index < bufferCount; index++) {
            LongByReference sectionIndex = new LongByReference();
            LongByReference length = new LongByReference();
            PointerByReference data = new PointerByReference();
            check(producer.dwarf_get_section_bytes_a(debug, index, sectionIndex, length, data,
                errorOut), "dwarf_get_section_bytes_a", errorOut, consumer);
            if (!sections.containsKey(sectionIndex.getValue()) || length.getValue() < 0 ||
                    length.getValue() > Integer.MAX_VALUE) {
                throw new IllegalStateException("invalid producer section buffer");
            }
            accumulated.computeIfAbsent(sectionIndex.getValue(), ignored ->
                new ByteArrayOutputStream()).writeBytes(pointer(data, "section bytes")
                    .getByteArray(0, Math.toIntExact(length.getValue())));
        }
        Map<Long, byte[]> result = new HashMap<>();
        accumulated.forEach((index, data) -> result.put(index, data.toByteArray()));
        return result;
    }

    private static void validateRelocations(LibDwarfProducer producer,
            LibDwarfConsumer consumer, Debug debug, PointerByReference errorOut,
            Map<Long, SectionRecord> sections, Map<Long, byte[]> sectionData,
            List<FunctionSymbol> functions, ProgramTypeModel typeModel, int addressBytes,
            ByteOrder byteOrder) {
        LongByReference groupCount = new LongByReference();
        IntByReference version = new IntByReference();
        check(producer.dwarf_get_relocation_info_count(debug, groupCount, version, errorOut),
            "dwarf_get_relocation_info_count", errorOut, consumer);
        if (version.getValue() != DWARF_DRD_BUFFER_VERSION || groupCount.getValue() <= 0) {
            throw new IllegalStateException("invalid symbolic relocation metadata");
        }
        List<Long> sectionSymbols = sections.values().stream()
            .map(SectionRecord::symbolIndex).toList();
        List<Long> relocatedAddresses = new ArrayList<>();
        int recordSize = new RelocationData().size();
        for (long group = 0; group < groupCount.getValue(); group++) {
            LongByReference relocationSection = new LongByReference();
            LongByReference targetSection = new LongByReference();
            LongByReference count = new LongByReference();
            PointerByReference records = new PointerByReference();
            check(producer.dwarf_get_relocation_info(debug, relocationSection, targetSection,
                count, records, errorOut), "dwarf_get_relocation_info", errorOut, consumer);
            byte[] target = sectionData.get(targetSection.getValue());
            if (!sections.containsKey(relocationSection.getValue()) || target == null ||
                    count.getValue() <= 0) {
                throw new IllegalStateException("invalid relocation group");
            }
            Pointer base = pointer(records, "relocation records");
            for (long index = 0; index < count.getValue(); index++) {
                RelocationData relocation = new RelocationData(
                    base.share(Math.multiplyExact(index, recordSize)));
                int width = Byte.toUnsignedInt(relocation.length);
                if (relocation.offset < 0 || width <= 0 ||
                        relocation.offset + width > target.length) {
                    throw new IllegalStateException("relocation outside target section");
                }
                if (relocation.symbolIndex == TEXT_SYMBOL_INDEX) {
                    if (width != addressBytes) {
                        throw new IllegalStateException("address relocation width mismatch");
                    }
                    relocatedAddresses.add(readAddress(target,
                        Math.toIntExact(relocation.offset), width, byteOrder));
                }
                else if (!sectionSymbols.contains(relocation.symbolIndex)) {
                    throw new IllegalStateException(
                        "unknown producer relocation symbol " + relocation.symbolIndex);
                }
            }
        }
        Set<Long> expected = new java.util.HashSet<>(functions.stream()
            .filter(FunctionSymbol::contiguous)
            .map(FunctionSymbol::address)
            .collect(java.util.stream.Collectors.toSet()));
        if (typeModel != null) {
            typeModel.globals().stream().filter(global -> !global.declaration())
                .map(ProgramTypeModel.GlobalVariable::address).forEach(expected::add);
        }
        if (!expected.containsAll(relocatedAddresses) ||
                expected.stream().anyMatch(address -> !relocatedAddresses.contains(address))) {
            throw new IllegalStateException(
                "producer address relocations do not match requested functions");
        }
    }

    private record FunctionKey(String name, long address) {
        private static FunctionKey of(FunctionSymbol function) {
            return new FunctionKey(function.name(), function.address());
        }
    }

    private static Map<FunctionKey, FunctionLines> sourceFunctions(
            SyntheticSourceFile source) {
        if (source == null) {
            return Map.of();
        }
        Map<FunctionKey, FunctionLines> result = new HashMap<>();
        for (FunctionLines function : source.functions()) {
            FunctionKey key = new FunctionKey(function.name(), function.address());
            if (result.put(key, function) != null) {
                throw new IllegalArgumentException("duplicate source function " + key);
            }
        }
        return result;
    }

    private static int declarationLine(FunctionLines function,
            SyntheticSourceFile source) {
        return source.mappedLines().stream()
            .filter(line -> line.line() >= function.startLine() &&
                line.line() <= function.endLine() &&
                line.addresses().contains(function.address()))
            .mapToInt(ghidradwarfforge.source.SyntheticSourceFile.SourceLine::line)
            .min().orElse(function.startLine());
    }

    private static void addSectionOffset(LibDwarfProducer producer,
            LibDwarfConsumer consumer, Debug debug, Die die, short attribute, long value,
            PointerByReference errorOut) {
        PointerByReference result = new PointerByReference();
        check(producer.dwarf_add_AT_dataref_a(debug, die, attribute, value, 0, result,
            errorOut), "dwarf_add_AT_dataref_a", errorOut, consumer);
        pointer(result, "section-offset attribute");
    }

    private static void addAddressLocation(LibDwarfProducer producer,
            LibDwarfConsumer consumer, Debug debug, Die die, long address,
            PointerByReference errorOut) {
        PointerByReference expressionOut = new PointerByReference();
        check(producer.dwarf_new_expr_a(debug, expressionOut, errorOut),
            "dwarf_new_expr_a", errorOut, consumer);
        Expr expression = new Expr(pointer(expressionOut, "location expression"));
        LongByReference nextOffset = new LongByReference();
        check(producer.dwarf_add_expr_addr_c(expression, address, TEXT_SYMBOL_INDEX,
            nextOffset, errorOut), "dwarf_add_expr_addr_c", errorOut, consumer);
        if (nextOffset.getValue() <= 0) {
            throw new IllegalStateException("empty address location expression");
        }
        PointerByReference attributeOut = new PointerByReference();
        check(producer.dwarf_add_AT_location_expr_a(debug, die, DW_AT_LOCATION,
            expression, attributeOut, errorOut), "dwarf_add_AT_location_expr_a",
            errorOut, consumer);
        pointer(attributeOut, "location attribute");
    }

    private static void addStableLocation(LibDwarfProducer producer,
            LibDwarfConsumer consumer, Debug debug, Die die, VariableLocation variable,
            PointerByReference errorOut) {
        if (variable == null ||
                !(DwarfLocationExpression.planStable(variable) instanceof Expression plan)) {
            return;
        }
        addExpressionAttribute(producer, consumer, debug, die, DW_AT_LOCATION, plan,
            errorOut);
    }

    private static void addVariableLocation(LibDwarfProducer producer,
            LibDwarfConsumer consumer, Debug debug, Die die, VariableLocation variable,
            Dwarf5LocationLists.Result locationLists, PointerByReference errorOut) {
        if (variable == null) {
            return;
        }
        Long offset = locationLists.offsets().get(variable);
        if (offset != null) {
            addSectionOffset(producer, consumer, debug, die, DW_AT_LOCATION, offset,
                errorOut);
            return;
        }
        addStableLocation(producer, consumer, debug, die, variable, errorOut);
    }

    private static void addExpressionAttribute(LibDwarfProducer producer,
            LibDwarfConsumer consumer, Debug debug, Die die, short attribute,
            Expression plan, PointerByReference errorOut) {
        PointerByReference expressionOut = new PointerByReference();
        check(producer.dwarf_new_expr_a(debug, expressionOut, errorOut),
            "dwarf_new_expr_a", errorOut, consumer);
        Expr expression = new Expr(pointer(expressionOut, "variable location expression"));
        long previousOffset = 0;
        for (Operation operation : plan.operations()) {
            LongByReference nextOffset = new LongByReference();
            if (operation instanceof GenericOperation generic) {
                check(producer.dwarf_add_expr_gen_a(expression, (byte) generic.opcode(),
                    generic.operand1(), generic.operand2(), nextOffset, errorOut),
                    "dwarf_add_expr_gen_a", errorOut, consumer);
            }
            else if (operation instanceof AddressOperation address) {
                check(producer.dwarf_add_expr_addr_c(expression, address.address(),
                    TEXT_SYMBOL_INDEX, nextOffset, errorOut), "dwarf_add_expr_addr_c",
                    errorOut, consumer);
            }
            else {
                throw new IllegalStateException("unsupported location operation " + operation);
            }
            if (nextOffset.getValue() <= previousOffset) {
                throw new IllegalStateException("location expression did not advance");
            }
            previousOffset = nextOffset.getValue();
        }
        PointerByReference attributeOut = new PointerByReference();
        check(producer.dwarf_add_AT_location_expr_a(debug, die, attribute,
            expression, attributeOut, errorOut), "dwarf_add_AT_location_expr_a",
            errorOut, consumer);
        pointer(attributeOut, "variable location attribute");
    }

    private static long readAddress(byte[] data, int offset, int width, ByteOrder order) {
        ByteBuffer buffer = ByteBuffer.wrap(data, offset, width).order(order);
        return width == 8 ? buffer.getLong() : Integer.toUnsignedLong(buffer.getInt());
    }

    private static Die newDie(LibDwarfProducer producer, LibDwarfConsumer consumer,
            Debug debug, long tag, Die parent, PointerByReference errorOut) {
        PointerByReference result = new PointerByReference();
        check(producer.dwarf_new_die_a(debug, tag, parent, null, null, null, result,
            errorOut), "dwarf_new_die_a", errorOut, consumer);
        return new Die(pointer(result, "DIE"));
    }

    private static void addName(LibDwarfProducer producer, LibDwarfConsumer consumer,
            Die die, String name, PointerByReference errorOut) {
        PointerByReference result = new PointerByReference();
        check(producer.dwarf_add_AT_name_a(die, name, result, errorOut),
            "dwarf_add_AT_name_a", errorOut, consumer);
        pointer(result, "name attribute");
    }

    private static void addProducer(LibDwarfProducer producer, LibDwarfConsumer consumer,
            Die die, PointerByReference errorOut) {
        PointerByReference result = new PointerByReference();
        check(producer.dwarf_add_AT_producer_a(die,
            "GhidraDwarfForge range/global milestone", result, errorOut),
            "dwarf_add_AT_producer_a", errorOut, consumer);
        pointer(result, "producer attribute");
    }

    private static void addUnsigned(LibDwarfProducer producer, LibDwarfConsumer consumer,
            Debug debug, Die die, short attribute, long value,
            PointerByReference errorOut) {
        PointerByReference result = new PointerByReference();
        check(producer.dwarf_add_AT_unsigned_const_a(debug, die, attribute, value, result,
            errorOut), "dwarf_add_AT_unsigned_const_a", errorOut, consumer);
        pointer(result, "unsigned attribute");
    }

    private static void addSigned(LibDwarfProducer producer, LibDwarfConsumer consumer,
            Debug debug, Die die, short attribute, long value,
            PointerByReference errorOut) {
        PointerByReference result = new PointerByReference();
        check(producer.dwarf_add_AT_any_value_sleb_a(die, attribute, value, result,
            errorOut), "dwarf_add_AT_any_value_sleb_a", errorOut, consumer);
        pointer(result, "signed attribute");
    }

    private static void addUleb(LibDwarfProducer producer, LibDwarfConsumer consumer,
            Die die, short attribute, long value, PointerByReference errorOut) {
        PointerByReference result = new PointerByReference();
        check(producer.dwarf_add_AT_any_value_uleb_a(die, attribute, value, result,
            errorOut), "dwarf_add_AT_any_value_uleb_a", errorOut, consumer);
        pointer(result, "unsigned LEB128 attribute");
    }

    private static void addReference(LibDwarfProducer producer, LibDwarfConsumer consumer,
            Debug debug, Die die, short attribute, Die target,
            PointerByReference errorOut) {
        PointerByReference result = new PointerByReference();
        check(producer.dwarf_add_AT_reference_c(debug, die, attribute, target, result,
            errorOut), "dwarf_add_AT_reference_c", errorOut, consumer);
        pointer(result, "reference attribute");
    }

    private static void addFlag(LibDwarfProducer producer, LibDwarfConsumer consumer,
            Debug debug, Die die, short attribute, boolean value,
            PointerByReference errorOut) {
        PointerByReference result = new PointerByReference();
        check(producer.dwarf_add_AT_flag_a(debug, die, attribute,
            (byte) (value ? 1 : 0), result, errorOut), "dwarf_add_AT_flag_a", errorOut,
            consumer);
        pointer(result, "flag attribute");
    }

    private static void addAddress(LibDwarfProducer producer, LibDwarfConsumer consumer,
            Debug debug, Die die, long address, PointerByReference errorOut) {
        PointerByReference result = new PointerByReference();
        check(producer.dwarf_add_AT_targ_address_c(debug, die, DW_AT_LOW_PC, address,
            TEXT_SYMBOL_INDEX, result, errorOut), "dwarf_add_AT_targ_address_c", errorOut,
            consumer);
        pointer(result, "address attribute");
    }

    private static void check(int status, String operation, PointerByReference errorOut,
            LibDwarfConsumer consumer) {
        if (status != DW_DLV_OK) {
            Pointer value = errorOut.getValue();
            long number = value == null ? -1 : consumer.dwarf_errno(new Error(value));
            String detail = value == null ? "without Dwarf_Error" :
                "error=" + number + " message=" +
                    consumer.dwarf_errmsg_by_number(number);
            throw new IllegalStateException(operation + " failed " + detail +
                " status=" + status);
        }
        errorOut.setValue(null);
    }

    private static Pointer pointer(PointerByReference reference, String description) {
        Pointer value = reference.getValue();
        if (value == null) {
            throw new IllegalStateException(description + " was null");
        }
        return value;
    }

    private static Path requireFile(Path value, String description) {
        Path path = value.toAbsolutePath().normalize();
        if (!Files.isRegularFile(path)) {
            throw new IllegalArgumentException(description + " does not exist: " + path);
        }
        return path;
    }
}
