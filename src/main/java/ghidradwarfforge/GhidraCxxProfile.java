package ghidradwarfforge;

import java.math.BigInteger;
import java.util.*;

import ghidra.framework.options.OptionType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.output.CxxSelection;
import ghidradwarfforge.types.InheritanceModel;
import ghidradwarfforge.types.InheritanceModel.*;

/** Transactional analyst configuration; checks current program evidence, not consumer behavior. */
public final class GhidraCxxProfile {
    private static final int MAX_RECORDS = 4096;
    private static final int MAX_INVENTORY = 1024;
    public record Result(boolean saved, int classes, int declarations, int bases, int virtualMethods, int vtables) { }

    private GhidraCxxProfile() { }

    /**
     * All changes participate in one transaction (including an enclosing caller transaction).
     * Callers must isolate this operation from unrelated uncommitted work. Preview rolls back.
     */
    public static Result configure(Program program, CxxSelection selection, boolean save, TaskMonitor monitor)
            throws CancelledException {
        monitor.checkCancelled();
        if (selection.programId() != program.getUniqueProgramID() ||
                !selection.language().equals(program.getLanguageID().toString()) ||
                !selection.compiler().equals(program.getCompilerSpec().getCompilerSpecID().toString())) {
            throw invalid("selection belongs to a different program, language or compiler specification");
        }
        int tx = program.startTransaction("Configure explicit C++ relationships");
        boolean commit = false;
        try {
            for (long id : selection.remove().vtables()) GhidraVtableBindings.remove(program, id, monitor);
            for (long id : selection.remove().declarations()) GhidraDeclarationBindings.remove(program, id, monitor);
            for (long id : selection.remove().classes()) GhidraClassBindings.remove(program, id, monitor);
            for (var row : selection.classes()) {
                monitor.checkCancelled();
                var symbol = program.getSymbolTable().getSymbol(row.classId());
                var type = program.getDataTypeManager().getDataType(row.typeId());
                if (symbol == null || !(symbol.getObject() instanceof GhidraClass owner) || !(type instanceof Structure structure)) {
                    throw invalid("selected class or structure identity is absent");
                }
                GhidraClassBindings.save(program, owner, structure, row.evidence(), monitor);
            }
            for (var row : selection.declarations()) GhidraDeclarationBindings.save(program, row, monitor);
            GhidraInheritanceBindings.save(program, selection.inheritance(), monitor);
            for (var table : selection.vtables()) GhidraVtableBindings.save(program, table, monitor);
            requireConsistent(program, monitor);
            monitor.checkCancelled();
            commit = save;
            return new Result(save, selection.classes().size(), selection.declarations().size(), selection.inheritance().bases().size(),
                selection.inheritance().virtualMethods().size(), selection.vtables().size());
        }
        finally { program.endTransaction(tx, commit); }
    }

    /** Retained records must remain valid; explicitly remove or reselect stale records. */
    private static void requireConsistent(Program program, TaskMonitor monitor) throws CancelledException {
        var types = new HashSet<Long>();
        for (long id : ids(program, GhidraClassBindings.OPTIONS_NAME, "class-", monitor)) {
            var result = GhidraClassBindings.read(program, id, monitor, ignored -> { });
            if (result.status() != GhidraClassBindings.Status.VALID || !types.add(result.binding().typeId())) {
                throw invalid("retained class binding is stale or shares a canonical type; remove or reselect it explicitly");
            }
        }
        for (long id : ids(program, GhidraDeclarationBindings.OPTIONS_NAME, "method-", monitor)) {
            if (GhidraDeclarationBindings.read(program, id, monitor, ignored -> { }).status() != GhidraDeclarationBindings.Status.VALID) {
                throw invalid("retained declaration binding is stale; remove or reselect it explicitly");
            }
        }
        if (GhidraInheritanceBindings.read(program, monitor, ignored -> { }).status() != GhidraInheritanceBindings.Status.VALID) {
            throw invalid("selected inheritance snapshot is invalid");
        }
        var spans = new TreeMap<BigInteger, BigInteger>();
        var mangled = new HashSet<String>(); var lookups = new HashMap<String, Long>();
        long bytes = 0;
        for (long id : ids(program, GhidraVtableBindings.OPTIONS_NAME, "symbol-", monitor)) {
            var result = GhidraVtableBindings.read(program, id, monitor, ignored -> { });
            if (result.status() != GhidraVtableBindings.Status.VALID) {
                throw invalid("retained vtable binding is stale; remove or reselect it explicitly");
            }
            var snapshot = result.snapshot(); var table = snapshot.request();
            bytes += table.byteSize();
            if (bytes > 64L * 1024 * 1024) throw invalid("retained table bytes exceed 64 MiB");
            var start = new BigInteger(Long.toUnsignedString(snapshot.originalAddress()));
            var end = start.add(BigInteger.valueOf(table.byteSize()));
            var lower = spans.floorEntry(start); var upper = spans.ceilingEntry(start);
            if (end.compareTo(BigInteger.ONE.shiftLeft(64)) > 0 || lower != null && lower.getValue().compareTo(start) > 0 ||
                    upper != null && upper.getKey().compareTo(end) < 0 || !mangled.add(table.mangledName())) {
                throw invalid("conflicting or overlapping selected vtable identities");
            }
            Long prior = lookups.putIfAbsent(table.lookupName(), table.classId());
            if (prior != null && prior != table.classId()) throw invalid("vtable lookup name denotes multiple classes");
            spans.put(start, end);
        }
    }

    /** Bounded saved-ID inventory. A filter limits candidates, never the recorded configuration. */
    public static Map<String, Object> inspect(Program program, String filter, TaskMonitor monitor) throws CancelledException {
        if (filter == null || filter.length() > 1024) throw invalid("inventory filter exceeds bound");
        var classes = new ArrayList<Object>(); var methods = new ArrayList<Object>(); var labels = new ArrayList<Object>();
        boolean[] truncated = new boolean[1];
        // Address-ordered symbol iteration excludes NO_ADDRESS class namespaces.
        var owners = program.getSymbolTable().getClassNamespaces();
        while (owners.hasNext()) {
            monitor.checkCancelled();
            var owner = owners.next();
            if (!owner.getName(true).contains(filter)) continue;
            if (classes.size() == MAX_INVENTORY) { truncated[0] = true; continue; }
            classes.add(Map.of("id", Long.toString(owner.getID()), "name", owner.getName(true),
                "parent_id", Long.toString(owner.getParentNamespace().getID())));
        }
        var symbols = program.getSymbolTable().getAllSymbols(true);
        while (symbols.hasNext()) {
            monitor.checkCancelled();
            var symbol = symbols.next();
            if (!symbol.getName(true).contains(filter)) continue;
            List<Object> target;
            if (symbol.getSymbolType() == SymbolType.FUNCTION) target = methods;
            else if (symbol.getSymbolType() == SymbolType.LABEL && symbol.getAddress().isMemoryAddress()) target = labels;
            else continue;
            if (target.size() == MAX_INVENTORY) { truncated[0] = true; continue; }
            var row = new LinkedHashMap<String, Object>();
            row.put("id", Long.toString(symbol.getID())); row.put("name", symbol.getName(true));
            row.put("parent_id", Long.toString(symbol.getParentNamespace().getID()));
            if (symbol.getObject() instanceof Function function) row.put("external", function.isExternal());
            if (target == labels) row.put("address", symbol.getAddress().toString());
            target.add(row);
        }
        var structures = new ArrayList<Object>();
        var types = program.getDataTypeManager().getAllStructures();
        while (types.hasNext()) {
            monitor.checkCancelled();
            var type = types.next();
            if (!type.getPathName().contains(filter)) continue;
            if (structures.size() == MAX_INVENTORY) { truncated[0] = true; continue; }
            structures.add(Map.of("id", Long.toString(program.getDataTypeManager().getID(type)), "path", type.getPathName(), "byte_size", type.getLength()));
        }
        var diagnostics = new ArrayList<String>();
        var result = new LinkedHashMap<String, Object>();
        result.put("kind", "ghidra-cxx-inventory"); result.put("candidate_filter", filter); result.put("candidates_truncated", truncated[0]);
        result.put("classes", classes); result.put("methods", methods); result.put("structures", structures); result.put("labels", labels);
        result.put("selection", selection(program, monitor, diagnostics)); result.put("diagnostics", diagnostics);
        return result;
    }

    /** Template includes valid current records. Rejected records remain saved and are diagnosed. */
    private static Map<String, Object> selection(Program program, TaskMonitor monitor, List<String> diagnostics)
            throws CancelledException {
        var result = new LinkedHashMap<String, Object>();
        result.put("schema", 1); result.put("program_id", Long.toString(program.getUniqueProgramID()));
        result.put("language", program.getLanguageID().toString()); result.put("compiler", program.getCompilerSpec().getCompilerSpecID().toString());
        var inheritance = GhidraInheritanceBindings.read(program, monitor, diagnostics::add);
        var model = inheritance.status() == GhidraInheritanceBindings.Status.VALID ? inheritance.model() : InheritanceModel.empty();
        result.put("abi", model.abi().name()); result.put("inheritance_mode", "replace");
        var classes = new ArrayList<Object>(); var declarations = new ArrayList<Object>(); var tables = new ArrayList<Object>();
        for (long id : ids(program, GhidraClassBindings.OPTIONS_NAME, "class-", monitor)) {
            var saved = GhidraClassBindings.read(program, id, monitor, diagnostics::add);
            if (saved.status() == GhidraClassBindings.Status.VALID) {
                classes.add(Map.of("class_id", Long.toString(id), "type_id", Long.toString(saved.binding().typeId()), "evidence", saved.binding().evidence()));
            }
        }
        for (long id : ids(program, GhidraDeclarationBindings.OPTIONS_NAME, "method-", monitor)) {
            var saved = GhidraDeclarationBindings.read(program, id, monitor, diagnostics::add);
            if (saved.status() == GhidraDeclarationBindings.Status.VALID) {
                declarations.add(Map.of("method_id", Long.toString(id), "class_id", Long.toString(saved.binding().classId()), "evidence", saved.binding().evidence()));
            }
        }
        long bytes = 0;
        for (long id : ids(program, GhidraVtableBindings.OPTIONS_NAME, "symbol-", monitor)) {
            var saved = GhidraVtableBindings.read(program, id, monitor, diagnostics::add);
            if (saved.status() != GhidraVtableBindings.Status.VALID) continue;
            var request = saved.snapshot().request();
            bytes += request.byteSize();
            if (bytes > 64L * 1024 * 1024) throw invalid("inventory table bytes exceed 64 MiB");
            tables.add(Map.of("symbol_id", Long.toString(id), "class_id", Long.toString(request.classId()), "mangled_name", request.mangledName(),
                "lookup_name", request.lookupName(), "byte_size", request.byteSize(), "evidence", request.evidence(), "points", request.points().stream().map(point ->
                    Map.of("table_offset", point.tableOffset(), "subobject_offset", Long.toString(point.subobjectOffset()), "evidence", point.evidence())).toList()));
        }
        result.put("classes", classes); result.put("declarations", declarations);
        result.put("bases", model.bases().stream().map(base -> {
            Map<String, Object> location = base.location() instanceof FixedBase fixed ?
                Map.of("kind", "fixed", "offset", Long.toString(fixed.offset()), "occupied_bytes", Long.toString(fixed.occupiedBytes())) :
                Map.of("kind", "virtual", "vptr_offset", Long.toString(((VirtualBase) base.location()).vptrOffset()), "slot_offset", Long.toString(((VirtualBase) base.location()).slotOffset()));
            return Map.of("derived_class_id", Long.toString(base.derivedClassId()), "base_class_id", Long.toString(base.baseClassId()),
                "order", base.order(), "access", base.access().name(), "location", location, "evidence", base.evidence());
        }).toList());
        result.put("virtual_methods", model.virtualMethods().stream().map(method -> Map.of("method_id", Long.toString(method.methodId()),
            "slot", method.slot(), "access", method.access().name(), "virtuality", method.virtuality().name(), "evidence", method.evidence())).toList());
        result.put("vtables", tables); result.put("remove", Map.of("classes", List.of(), "declarations", List.of(), "vtables", List.of()));
        return result;
    }

    private static List<Long> ids(Program program, String group, String prefix, TaskMonitor monitor) throws CancelledException {
        if (!program.getOptionsNames().contains(group)) return List.of();
        var options = program.getOptions(group); var keys = options.getOptionNames();
        if (keys.size() > MAX_RECORDS) throw invalid("saved C++ record inventory exceeds bound");
        var result = new ArrayList<Long>(); long chars = 0;
        for (String key : keys.stream().sorted().toList()) {
            monitor.checkCancelled();
            if (!key.startsWith(prefix) || !key.substring(prefix.length()).matches("[1-9][0-9]{0,18}")) throw invalid("unexpected saved C++ record key");
            long id;
            try { id = Long.parseLong(key.substring(prefix.length())); }
            catch (NumberFormatException failure) { throw invalid("saved C++ record identity exceeds range"); }
            if (options.getType(key) != OptionType.STRING_TYPE) throw invalid("saved C++ record has incompatible option type");
            String text = options.getString(key, "");
            chars += text == null ? 0 : text.length();
            if (chars > 16L * 1024 * 1024) throw invalid("saved C++ record inventory exceeds 16 MiB text bound");
            result.add(id);
        }
        return result;
    }

    private static IllegalArgumentException invalid(String message) { return new IllegalArgumentException(message); }
}
