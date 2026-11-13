package ghidradwarfforge.output;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.function.BooleanSupplier;

import ghidradwarfforge.GhidraDeclarationBindings;
import ghidradwarfforge.GhidraVtableBindings;
import ghidradwarfforge.targets.CxxAbiProfile;
import ghidradwarfforge.types.InheritanceModel;
import ghidradwarfforge.types.InheritanceModel.*;

/** Closed, bounded analyst selection. IDs/offsets are decimal strings, never JSON doubles. */
public record CxxSelection(long programId, String language, String compiler,
        List<ClassBinding> classes, List<GhidraDeclarationBindings.Binding> declarations,
        InheritanceModel inheritance, List<GhidraVtableBindings.Request> vtables, Removals remove) {
    private static final ReportJsonReader.Limits LIMITS = new ReportJsonReader.Limits(
        1024 * 1024, 8192, 10, 100000, 4096);
    public record ClassBinding(long classId, long typeId, String evidence) {
        public ClassBinding {
            if (classId <= 0 || typeId <= 0 || evidence == null || evidence.isBlank() || evidence.length() > 8192 ||
                    evidence.indexOf('\0') >= 0) throw new IllegalArgumentException("invalid explicit class selection");
        }
    }
    public record Removals(List<Long> classes, List<Long> declarations, List<Long> vtables) {
        public Removals {
            classes = identities(classes); declarations = identities(declarations); vtables = identities(vtables);
        }
    }

    public CxxSelection {
        if (language == null || language.isBlank() || compiler == null || compiler.isBlank() || inheritance == null ||
                inheritance.abi() == CxxAbiProfile.UNSPECIFIED || remove == null) throw new IllegalArgumentException("explicit C++ target/ABI required");
        classes = List.copyOf(classes); declarations = List.copyOf(declarations); vtables = List.copyOf(vtables);
        var classIds = identities(classes.stream().map(ClassBinding::classId).toList());
        identities(classes.stream().map(ClassBinding::typeId).toList());
        var declarationIds = identities(declarations.stream().map(GhidraDeclarationBindings.Binding::methodId).toList());
        var tableIds = identities(vtables.stream().map(GhidraVtableBindings.Request::symbolId).toList());
        if (!Collections.disjoint(classIds, remove.classes()) || !Collections.disjoint(declarationIds, remove.declarations()) ||
                !Collections.disjoint(tableIds, remove.vtables())) throw new IllegalArgumentException("selection both removes and applies an identity");
        if (vtables.stream().mapToLong(GhidraVtableBindings.Request::byteSize).sum() > 64L * 1024 * 1024) {
            throw new IllegalArgumentException("selected table bytes exceed 64 MiB");
        }
    }

    private static List<Long> identities(List<Long> ids) {
        if (ids == null || ids.size() > 4096 || new HashSet<>(ids).size() != ids.size() ||
                ids.stream().anyMatch(id -> id == null || id <= 0)) throw new IllegalArgumentException("invalid or duplicate selected identity");
        return List.copyOf(ids);
    }

    public static CxxSelection read(Path path, BooleanSupplier cancelled) throws IOException {
        try (var input = new ReportJsonReader(Files.newInputStream(path), cancelled, LIMITS); var json = new JsonReader(input)) {
            try { return new Reader(json, cancelled).read(); }
            catch (IllegalArgumentException failure) { throw new IOException("Invalid C++ selection: " + failure.getMessage(), failure); }
        }
    }

    private static final class Reader extends ReportValueReader {
        Reader(JsonReader json, BooleanSupplier cancelled) { super(json, cancelled, LIMITS); }

        CxxSelection read() throws IOException {
            var words = new HashMap<String, String>();
            long[] program = new long[1];
            var classes = new ArrayList<ClassBinding>();
            var declarations = new ArrayList<GhidraDeclarationBindings.Binding>();
            var bases = new ArrayList<Base>();
            var methods = new ArrayList<VirtualMethod>();
            var tables = new ArrayList<GhidraVtableBindings.Request>();
            var removals = new Removals[1];
            object("C++ selection", Set.of("schema", "program_id", "language", "compiler", "abi", "inheritance_mode",
                    "classes", "declarations", "bases", "virtual_methods", "vtables", "remove"), field -> {
                switch (field) {
                    case "schema" -> { if (integer() != 1) throw invalid("unsupported C++ selection schema"); }
                    case "program_id" -> program[0] = decimal();
                    case "inheritance_mode" -> { if (!text(true).equals("replace")) throw invalid("explicit inheritance replacement required"); }
                    case "classes" -> array(() -> classes.add(classBinding()));
                    case "declarations" -> array(() -> declarations.add(declaration()));
                    case "bases" -> array(() -> bases.add(base()));
                    case "virtual_methods" -> array(() -> methods.add(method()));
                    case "vtables" -> array(() -> tables.add(table()));
                    case "remove" -> removals[0] = removals();
                    default -> words.put(field, text(true));
                }
            });
            value(JsonToken.END_DOCUMENT);
            return new CxxSelection(program[0], words.get("language"), words.get("compiler"), classes, declarations,
                new InheritanceModel(CxxAbiProfile.valueOf(words.get("abi")), bases, methods), tables, removals[0]);
        }

        long decimal() throws IOException {
            String spelling = text(true);
            if (!spelling.matches("0|-?[1-9][0-9]{0,18}")) throw invalid("expected canonical signed decimal string");
            try { return Long.parseLong(spelling); }
            catch (NumberFormatException failure) { throw invalid("decimal string exceeds signed 64-bit range"); }
        }

        ClassBinding classBinding() throws IOException {
            long[] ids = new long[2]; String[] evidence = new String[1];
            object("class selection", Set.of("class_id", "type_id", "evidence"), field -> {
                if (field.equals("evidence")) evidence[0] = text(true);
                else ids[field.equals("class_id") ? 0 : 1] = decimal();
            });
            return new ClassBinding(ids[0], ids[1], evidence[0]);
        }

        GhidraDeclarationBindings.Binding declaration() throws IOException {
            long[] ids = new long[2]; String[] evidence = new String[1];
            object("declaration selection", Set.of("method_id", "class_id", "evidence"), field -> {
                if (field.equals("evidence")) evidence[0] = text(true);
                else ids[field.equals("method_id") ? 0 : 1] = decimal();
            });
            return new GhidraDeclarationBindings.Binding(ids[0], ids[1], evidence[0]);
        }

        Base base() throws IOException {
            long[] ids = new long[2]; int[] order = new int[1];
            var words = new HashMap<String, String>(); var location = new BaseLocation[1];
            object("base selection", Set.of("derived_class_id", "base_class_id", "order", "access", "location", "evidence"), field -> {
                switch (field) {
                    case "derived_class_id" -> ids[0] = decimal();
                    case "base_class_id" -> ids[1] = decimal();
                    case "order" -> order[0] = integer();
                    case "location" -> location[0] = location();
                    default -> words.put(field, text(true));
                }
            });
            return new Base(ids[0], ids[1], order[0], Access.valueOf(words.get("access")), location[0], words.get("evidence"));
        }

        BaseLocation location() throws IOException {
            String[] kind = new String[1]; var numbers = new HashMap<String, Long>();
            object("base location", Set.of("kind"), Set.of("offset", "occupied_bytes", "vptr_offset", "slot_offset"), field -> {
                if (field.equals("kind")) kind[0] = text(true);
                else numbers.put(field, decimal());
            });
            if (kind[0].equals("fixed") && numbers.keySet().equals(Set.of("offset", "occupied_bytes"))) {
                return new FixedBase(numbers.get("offset"), numbers.get("occupied_bytes"));
            }
            if (kind[0].equals("virtual") && numbers.keySet().equals(Set.of("vptr_offset", "slot_offset"))) {
                return new VirtualBase(numbers.get("vptr_offset"), numbers.get("slot_offset"));
            }
            throw invalid("base location requires exactly its selected kind's offsets");
        }

        VirtualMethod method() throws IOException {
            long[] id = new long[1]; int[] slot = new int[1]; var words = new HashMap<String, String>();
            object("virtual method", Set.of("method_id", "slot", "access", "virtuality", "evidence"), field -> {
                if (field.equals("method_id")) id[0] = decimal();
                else if (field.equals("slot")) slot[0] = integer();
                else words.put(field, text(true));
            });
            return new VirtualMethod(id[0], slot[0], Access.valueOf(words.get("access")), Virtuality.valueOf(words.get("virtuality")), words.get("evidence"));
        }

        GhidraVtableBindings.Request table() throws IOException {
            long[] ids = new long[2]; int[] size = new int[1]; var words = new HashMap<String, String>();
            var points = new ArrayList<GhidraVtableBindings.AddressPoint>();
            object("vtable selection", Set.of("symbol_id", "class_id", "mangled_name", "lookup_name", "byte_size", "points", "evidence"), field -> {
                switch (field) {
                    case "symbol_id" -> ids[0] = decimal();
                    case "class_id" -> ids[1] = decimal();
                    case "byte_size" -> size[0] = integer();
                    case "points" -> array(() -> points.add(point()));
                    default -> words.put(field, text(true));
                }
            });
            return new GhidraVtableBindings.Request(ids[0], ids[1], words.get("mangled_name"), words.get("lookup_name"), size[0], points, words.get("evidence"));
        }

        GhidraVtableBindings.AddressPoint point() throws IOException {
            int[] offset = new int[1]; long[] subobject = new long[1]; String[] evidence = new String[1];
            object("vtable address point", Set.of("table_offset", "subobject_offset", "evidence"), field -> {
                if (field.equals("table_offset")) offset[0] = integer();
                else if (field.equals("subobject_offset")) subobject[0] = decimal();
                else evidence[0] = text(true);
            });
            return new GhidraVtableBindings.AddressPoint(offset[0], subobject[0], evidence[0]);
        }

        Removals removals() throws IOException {
            var classes = new ArrayList<Long>(); var declarations = new ArrayList<Long>(); var tables = new ArrayList<Long>();
            object("explicit removals", Set.of("classes", "declarations", "vtables"), field -> {
                var ids = field.equals("classes") ? classes : field.equals("declarations") ? declarations : tables;
                array(() -> ids.add(decimal()));
            });
            return new Removals(classes, declarations, tables);
        }
    }
}
