// Seed and independently read a private annotation fixture; not an exporter.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.pcode.DynamicHash;
import ghidra.program.database.symbol.EquateManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.SourceType;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParser;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class PrepareAnalystAnnotations extends GhidraScript {
    private static final String PREFIX = "FORGE_ANNOTATION:";

    private Address address(com.google.gson.JsonObject labels, String name) {
        long delta = Math.subtractExact(currentProgram.getImageBase().getOffset(),
            labels.getAsJsonObject("_imageBase").get("address").getAsLong());
        return toAddr(Math.addExact(labels.getAsJsonObject(name).get("address").getAsLong(), delta));
    }

    private void seedDynamicEquate(ghidra.program.model.listing.Function function) throws Exception {
        var decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) throw new AssertionError(decompiler.getLastMessage());
            var result = decompiler.decompileFunction(function, 30, monitor);
            if (!result.decompileCompleted() || result.getHighFunction() == null) {
                throw new AssertionError("dynamic-equate seed decompilation unavailable");
            }
            var high = result.getHighFunction();
            record Candidate(Address address, long hash, long value, int bytes) { }
            var candidates = new ArrayList<Candidate>();
            for (var nodes = high.getVarnodes(currentProgram.getAddressFactory().getConstantSpace()); nodes.hasNext();) {
                monitor.checkCancelled();
                var node = nodes.next();
                // The fixture adds 19 + 23 + 11; the decompiler folds these to 53.
                if (!node.isConstant() || node.getOffset() != 53) continue;
                var dynamic = new DynamicHash(node, high);
                if (dynamic.getHash() == 0 || dynamic.getAddress() == null) continue;
                var resolved = DynamicHash.findVarnode(high, dynamic.getAddress(), dynamic.getHash());
                var instruction = getInstructionAt(dynamic.getAddress());
                if (resolved == null || !resolved.isConstant() || resolved.getOffset() != node.getOffset() ||
                        resolved.getSize() != node.getSize() || instruction == null) continue;
                boolean raw = false;
                for (long hash : DynamicHash.calcConstantHash(instruction, node.getOffset())) {
                    raw |= hash == dynamic.getHash();
                }
                if (!raw) candidates.add(new Candidate(dynamic.getAddress(), dynamic.getHash(),
                    node.getOffset(), node.getSize()));
            }
            candidates.sort(Comparator.comparing(Candidate::address).thenComparingLong(Candidate::hash)
                .thenComparingLong(Candidate::value).thenComparingInt(Candidate::bytes));
            if (candidates.isEmpty()) throw new AssertionError("no resolved dynamic-only equate candidate");
            var chosen = candidates.getFirst();
            var equate = currentProgram.getEquateTable().createEquate("ANNOTATION_DYNAMIC_ONLY", chosen.value());
            equate.addReference(chosen.hash(), chosen.address());
            if (equate.getReferences().length != 1 || equate.getReferences()[0].getOpIndex() != -1) {
                throw new AssertionError("dynamic reference was converted to an operand reference");
            }
        }
        finally {
            decompiler.dispose();
        }
    }

    @Override
    protected void run() throws Exception {
        var args = getScriptArgs();
        if (args.length != 3 || !List.of("setup", "read").contains(args[0])) {
            throw new IllegalArgumentException("setup|read labels.json observations.json");
        }
        var labels = JsonParser.parseString(Files.readString(Path.of(args[1]))).getAsJsonObject();
        var storage = JsonParser.parseString(Files.readString(Path.of(args[1]).resolveSibling(
            "compiler-storage.json"))).getAsJsonObject();
        if (!storage.get("function").getAsString().equals("annotation_conflicts") ||
                !storage.get("local").getAsString().equals("ANNOTATION_LOCAL") ||
                storage.get("bytes").getAsInt() != 4) throw new AssertionError("unexpected compiler storage");
        var factory = currentProgram.getAddressFactory();
        Address entry = address(labels, "annotation_probe");
        var function = getFunctionAt(entry);
        if (function == null) throw new AssertionError("fixture function missing");
        var listing = currentProgram.getListing();
        var table = currentProgram.getEquateTable();
        if (args[0].equals("setup")) {
            for (String name : labels.keySet()) {
                if (name.startsWith("_")) continue;
                Address address = address(labels, name);
                var at = getFunctionAt(address);
                if (at != null && (name.equals("annotation_probe") || name.equals("annotation_failure") ||
                        name.equals("annotation_conflicts"))) {
                    at.setName(name, SourceType.USER_DEFINED);
                }
                else {
                    createLabel(address, name, true, SourceType.USER_DEFINED);
                }
            }
            seedDynamicEquate(function);
            var conflictFunction = getFunctionAt(address(labels, "annotation_conflicts"));
            if (conflictFunction == null) throw new AssertionError("conflict function missing");
            for (var variable : conflictFunction.getLocalVariables()) conflictFunction.removeVariable(variable);
            var local = (LocalVariable) conflictFunction.addLocalVariable(new LocalVariableImpl(
                "ANNOTATION_LOCAL", new IntegerDataType(currentProgram.getDataTypeManager()),
                storage.get("stackOffset").getAsInt(), currentProgram, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
            local.setFirstUseOffset(storage.get("firstUseOffset").getAsInt());
            var integer = new IntegerDataType(currentProgram.getDataTypeManager());
            DataUtilities.createData(currentProgram, address(labels, "ANNOTATION_COLLISION"), integer, 4,
                DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
            var structure = new StructureDataType("ANNOTATION_TYPE", 0, currentProgram.getDataTypeManager());
            structure.add(integer, "member", null);
            DataUtilities.createData(currentProgram, address(labels, "annotation_object"), structure, 4,
                DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
            var originalEnum = new EnumDataType(ghidra.program.model.data.CategoryPath.ROOT,
                "annotation_enum", 4, currentProgram.getDataTypeManager());
            originalEnum.add("ANNOTATION_ENUM_COLLISION", 3);
            DataUtilities.createData(currentProgram, address(labels, "annotation_enum_object"), originalEnum, 4,
                DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
            Address live = address(labels, "annotation_live");
            Address interior = null;
            for (var instructions = listing.getInstructions(function.getBody(), true); instructions.hasNext();) {
                var instruction = instructions.next();
                if (instruction.getLength() > 1) {
                    interior = instruction.getAddress().add(1);
                    break;
                }
            }
            if (interior == null) throw new AssertionError("no instruction interior");
            Address unmapped = toAddr(0x70000000L);
            if (currentProgram.getMemory().contains(unmapped)) throw new AssertionError("unmapped test address occupied");
            var overlay = currentProgram.getMemory().createInitializedBlock("ANNOTATION_OVERLAY",
                live, 16, (byte) 0, monitor, true);
            var external = currentProgram.getExternalManager().addExtFunction("ANNOTATION_LIBRARY",
                "annotation_external", null, SourceType.USER_DEFINED);
            var points = new LinkedHashMap<String, Address>();
            points.put("instruction", live);
            points.put("interior", interior);
            points.put("data", address(labels, "annotation_data"));
            points.put("unmapped", unmapped);
            points.put("overlay", overlay.getStart());
            points.put("external", external.getExternalSpaceAddress());
            points.put("register", currentProgram.getCompilerSpec().getStackPointer().getAddress());
            points.put("stack", factory.getStackSpace().getAddress(-8));
            points.put("failed-function", address(labels, "annotation_failure"));
            points.put("body-gap", address(labels, "annotation_gap_begin"));
            if (new java.util.HashSet<>(points.values()).size() != points.size()) {
                throw new AssertionError("fixture annotation addresses collide: " + points);
            }
            for (var point : points.entrySet()) {
                for (var category : CommentType.values()) {
                    monitor.checkCancelled();
                    listing.setComment(point.getValue(), category, PREFIX + point.getKey() + ":" + category +
                        " λ */ literal\\n\r\nsecond line\tend");
                }
            }
            Address gapEnd = address(labels, "annotation_gap_end");
            var body = new AddressSet(function.getBody());
            body.deleteRange(points.get("body-gap"), gapEnd.subtract(1));
            function.setBody(body);
            table.createEquate("ANNOTATION_UNREFERENCED", 99);
            table.createEquate("ANNOTATION_λ", 100);
            table.createEquate("ANNOTATION_COLLISION", 17);
            table.createEquate("ANNOTATION_LOCAL", 18);
            table.createEquate("ANNOTATION_TYPE", 20);
            table.createEquate("ANNOTATION_ENUM_COLLISION", 21);
            table.createEquate("ANNOTATION_STORED_MIN", Long.MIN_VALUE);
            table.createEquate("ANNOTATION_STORED_MAX", Long.MAX_VALUE);
            table.createEquate("ANNOTATION_ALL_BITS", -1);
            table.createEquate("dtID:not-a-number:16", 16);
            for (long value : new long[] {19, 23, -7}) {
                var proposed = new EnumDataType("AnnotationEnum" + (value < 0 ? "Negative" : value), 1);
                proposed.add(value < 0 ? "ANNOTATION_NEGATIVE" : "ANNOTATION_SHARED_DISPLAY", value);
                var saved = currentProgram.getDataTypeManager().addDataType(proposed,
                    DataTypeConflictHandler.DEFAULT_HANDLER);
                var equate = table.createEquate(EquateManager.formatNameForEquate(saved.getUniversalID(), value), value);
                if (value < 0) continue;
                boolean attached = false;
                for (var instructions = listing.getInstructions(function.getBody(), true); instructions.hasNext() && !attached;) {
                    var instruction = instructions.next();
                    for (int operand = 0; operand < instruction.getNumOperands() && !attached; operand++) {
                        for (Object object : instruction.getOpObjects(operand)) {
                            if (object instanceof Scalar scalar && scalar.getValue() == value) {
                                equate.addReference(instruction.getAddress(), operand);
                                attached = true;
                                break;
                            }
                        }
                    }
                }
                if (!attached) throw new AssertionError("no actual operand for " + value);
            }
        }
        var all = new AddressSet();
        var scans = new ArrayList<AddressSet>();
        scans.add(all);
        for (var space : factory.getAllAddressSpaces()) {
            boolean encodable = switch (space.getType()) {
                case AddressSpace.TYPE_UNKNOWN, AddressSpace.TYPE_RAM, AddressSpace.TYPE_CODE,
                    AddressSpace.TYPE_DELETED, AddressSpace.TYPE_OTHER, AddressSpace.TYPE_VARIABLE,
                    AddressSpace.TYPE_REGISTER, AddressSpace.TYPE_STACK, AddressSpace.TYPE_EXTERNAL -> true;
                default -> false;
            };
            if (encodable && space.isStackSpace()) {
                // AddressMapDB encodes stack offsets with an unsigned 32-bit mask.
                // A single signed min..max interval reverses the database keys.
                // Separate scans must remain separate: AddressSet would merge them.
                long minimum = Math.max(space.getMinAddress().getOffset(), Integer.MIN_VALUE);
                long maximum = Math.min(space.getMaxAddress().getOffset(), Integer.MAX_VALUE);
                scans.add(new AddressSet(space.getAddress(minimum), space.getAddress(-1)));
                scans.add(new AddressSet(space.getAddress(0), space.getAddress(maximum)));
            }
            else if (encodable) {
                all.addRange(space.getMinAddress(), space.getMaxAddress());
            }
        }
        var comments = new ArrayList<Map<String, Object>>();
        long scanned = 0;
        for (var scan : scans) {
            for (var addresses = listing.getCommentAddressIterator(scan, true); addresses.hasNext();) {
                monitor.checkCancelled();
                var address = addresses.next();
                scanned++;
                for (var category : CommentType.values()) {
                    var text = listing.getComment(category, address);
                    if (text == null || !text.startsWith(PREFIX)) continue;
                    var row = new LinkedHashMap<String, Object>();
                    row.put("space", address.getAddressSpace().getName());
                    row.put("offset", Long.toUnsignedString(address.getOffset(), 16));
                    row.put("category", category.name());
                    row.put("text", text);
                    var owner = getFunctionContaining(address);
                    row.put("function", owner == null ? null : owner.getName(true));
                    row.put("memory", currentProgram.getMemory().contains(address));
                    row.put("codeUnitStart", listing.getCodeUnitAt(address) != null);
                    comments.add(row);
                }
            }
        }
        if (comments.size() != 50 || scanned != listing.getCommentAddressCount()) {
            Files.writeString(Path.of(args[2] + ".incomplete.json"),
                new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(comments));
            println("stack-space=" + factory.getStackSpace() + " min=" + factory.getStackSpace().getMinAddress() +
                " max=" + factory.getStackSpace().getMaxAddress() + " direct=" +
                listing.getComment(CommentType.EOL, factory.getStackSpace().getAddress(-8)));
            println("all-ranges=" + all);
            throw new AssertionError("comment inventory incomplete: " + comments.size());
        }
        comments.sort(Comparator.comparing(row -> row.get("space") + ":" + row.get("offset") + ":" + row.get("category")));
        var equates = new ArrayList<Map<String, Object>>();
        for (var iterator = table.getEquates(); iterator.hasNext();) {
            monitor.checkCancelled();
            var equate = iterator.next();
            var row = new LinkedHashMap<String, Object>();
            row.put("storedName", equate.getName());
            row.put("storedValue", Long.toString(equate.getValue()));
            row.put("storedBits", Long.toUnsignedString(equate.getValue()));
            try {
                row.put("displayName", equate.getDisplayName());
                var id = equate.getEnumUUID();
                var type = id == null ? null : currentProgram.getDataTypeManager().findDataTypeForID(id);
                if (type instanceof ghidra.program.model.data.Enum enumType) {
                    row.put("enumBytes", enumType.getLength());
                    row.put("enumSigned", enumType.isSigned());
                }
            }
            catch (RuntimeException malformed) {
                row.put("helperFailure", malformed.getClass().getName());
            }
            var references = new ArrayList<Map<String, Object>>();
            for (var reference : equate.getReferences()) {
                var ref = new LinkedHashMap<String, Object>();
                ref.put("space", reference.getAddress().getAddressSpace().getName());
                ref.put("offset", Long.toUnsignedString(reference.getAddress().getOffset(), 16));
                ref.put("operand", reference.getOpIndex());
                ref.put("dynamicHash", Long.toUnsignedString(reference.getDynamicHashValue()));
                references.add(ref);
            }
            row.put("references", references);
            equates.add(row);
        }
        equates.sort(Comparator.comparing(row -> (String) row.get("storedName")));
        if (equates.size() != 14) throw new AssertionError("equate inventory differs: " + equates.size());
        var decompiler = new DecompInterface();
        var dynamicObservation = new LinkedHashMap<String, Object>();
        try {
            if (!decompiler.openProgram(currentProgram)) throw new AssertionError(decompiler.getLastMessage());
            var result = decompiler.decompileFunction(function, 30, monitor);
            if (!result.decompileCompleted() || result.getHighFunction() == null) {
                throw new AssertionError("dynamic-equate readback decompilation unavailable");
            }
            var dynamic = table.getEquate("ANNOTATION_DYNAMIC_ONLY");
            var references = dynamic.getReferences();
            if (references.length != 1 || references[0].getOpIndex() != -1) {
                throw new AssertionError("dynamic-only reference ownership changed");
            }
            var ref = references[0];
            var node = DynamicHash.findVarnode(result.getHighFunction(), ref.getAddress(), ref.getDynamicHashValue());
            if (node == null || !node.isConstant() || node.getOffset() != dynamic.getValue() || node.getOffset() != 53 || node.getSize() != 4) {
                throw new AssertionError("saved dynamic reference no longer resolves to its constant");
            }
            dynamicObservation.put("value", Long.toString(node.getOffset()));
            dynamicObservation.put("bytes", node.getSize());
            dynamicObservation.put("operand", ref.getOpIndex());
            dynamicObservation.put("hash", Long.toUnsignedString(ref.getDynamicHashValue()));
            dynamicObservation.put("address", ref.getAddress().toString());
        }
        finally {
            decompiler.dispose();
        }
        var ranges = new ArrayList<String>();
        function.getBody().getAddressRanges().forEach(range -> ranges.add(range.toString()));
        if (ranges.size() < 2) throw new AssertionError("discontiguous fixture body missing");
        var result = new LinkedHashMap<String, Object>();
        result.put("language", currentProgram.getLanguageID().toString());
        result.put("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        result.put("comments", comments);
        result.put("equates", equates);
        result.put("resolvedDynamicEquate", dynamicObservation);
        var conflicts = new LinkedHashMap<String, Object>();
        var conflictFunction = getFunctionAt(address(labels, "annotation_conflicts"));
        var locals = java.util.Arrays.stream(conflictFunction.getLocalVariables())
            .filter(variable -> variable.getName().equals("ANNOTATION_LOCAL")).toList();
        if (locals.size() != 1) throw new AssertionError("saved local conflict missing");
        var local = locals.getFirst();
        if (!local.isStackVariable() || local.getStackOffset() != storage.get("stackOffset").getAsInt() ||
                local.getLength() != 4 || local.getFirstUseOffset() != storage.get("firstUseOffset").getAsInt() ||
                local.getSource() != SourceType.USER_DEFINED) throw new AssertionError("saved local evidence changed");
        conflicts.put("local", new java.util.TreeMap<>(Map.of("name", local.getName(), "stackOffset", local.getStackOffset(),
            "bytes", local.getLength(), "firstUseOffset", local.getFirstUseOffset(), "source", local.getSource().toString())));
        var object = listing.getDataAt(address(labels, "annotation_object"));
        if (!(object.getDataType() instanceof Structure structure) || !structure.getName().equals("ANNOTATION_TYPE") ||
                structure.getLength() != 4 || !structure.getComponent(0).getFieldName().equals("member") ||
                structure.getComponent(0).getOffset() != 0) throw new AssertionError("saved type conflict missing");
        conflicts.put("type", new java.util.TreeMap<>(Map.of("name", structure.getName(), "bytes", structure.getLength(), "member", "member")));
        var enumObject = listing.getDataAt(address(labels, "annotation_enum_object"));
        if (!(enumObject.getDataType() instanceof ghidra.program.model.data.Enum enumeration) ||
                enumeration.getLength() != 4 || enumeration.getValue("ANNOTATION_ENUM_COLLISION") != 3) {
            throw new AssertionError("saved enum conflict missing");
        }
        conflicts.put("enum", new java.util.TreeMap<>(Map.of("name", "ANNOTATION_ENUM_COLLISION", "value", 3, "bytes", 4)));
        var global = listing.getDataAt(address(labels, "ANNOTATION_COLLISION"));
        if (global.getLength() != 4 || !global.getLabel().equals("ANNOTATION_COLLISION") ||
                global.getInt(0) != 101) throw new AssertionError("saved global conflict missing");
        conflicts.put("global", new java.util.TreeMap<>(Map.of("name", global.getLabel(), "value", global.getInt(0), "bytes", 4)));
        result.put("savedConflicts", conflicts);
        result.put("functionRanges", ranges);
        result.put("scannedCommentAddresses", scanned);
        Files.writeString(Path.of(args[2]), new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(result) + "\n");
        println("analyst-annotations-preparation=PASS comments=50 equates=14");
    }
}
