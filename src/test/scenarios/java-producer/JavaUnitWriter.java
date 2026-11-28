package evaluation;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/** A single DWARF 5 compilation unit. All mutable layout state belongs to one write. */
final class JavaUnitWriter {
    enum Tag {
        UNIT(0x11), FUNCTION(0x2e), BASE(0x24), STRUCT(0x13), MEMBER(0x0d), POINTER(0x0f), LOCAL(0x34);
        final int code;
        Tag(int code) { this.code = code; }
    }

    enum Field {
        NAME(0x03, 0x0e), COMP_DIR(0x1b, 0x0e), PRODUCER(0x25, 0x0e),
        LANGUAGE(0x13, 0x0f), SIZE(0x0b, 0x0f), ENCODING(0x3e, 0x0f),
        MEMBER_OFFSET(0x38, 0x0f), FILE(0x3a, 0x0f), LINE(0x3b, 0x0f),
        HIGH_PC(0x12, 0x0f), LOW_PC(0x11, 0x01), ENTRY_PC(0x52, 0x01),
        TYPE(0x49, 0x13), EXTERNAL(0x3f, 0x19),
        STMT_LIST(0x10, 0x17, ".debug_line"), LOCATION(0x02, 0x17, ".debug_loclists"),
        RANGES(0x55, 0x17, ".debug_rnglists");

        final int attribute;
        final int form;
        final String section;

        Field(int attribute, int form) { this(attribute, form, null); }

        Field(int attribute, int form, String section) {
            this.attribute = attribute;
            this.form = form;
            this.section = section;
        }
    }

    /** An ID can be referenced before its DIE is emitted. Its scope is this CU. */
    record Id(String key) {
        Id {
            if (key == null || key.isEmpty()) throw new IllegalArgumentException("empty DIE identity");
        }
    }

    record Die(Id id, Tag tag, Map<Field, Object> attributes, List<Die> children) {
        Die {
            Objects.requireNonNull(id);
            Objects.requireNonNull(tag);
            // Enum order fixes the abbreviation and value order independently of the caller's map.
            var sorted = new java.util.EnumMap<Field, Object>(Field.class);
            sorted.putAll(attributes);
            attributes = java.util.Collections.unmodifiableMap(sorted);
            children = List.copyOf(children);
            Set<Field> allowed = switch (tag) {
                case UNIT -> Set.of(Field.NAME, Field.COMP_DIR, Field.PRODUCER, Field.LANGUAGE,
                    Field.LOW_PC, Field.HIGH_PC, Field.STMT_LIST, Field.RANGES);
                case FUNCTION -> Set.of(Field.NAME, Field.LOW_PC, Field.HIGH_PC, Field.TYPE,
                    Field.EXTERNAL, Field.FILE, Field.LINE, Field.ENTRY_PC, Field.RANGES);
                case BASE -> Set.of(Field.NAME, Field.SIZE, Field.ENCODING);
                case STRUCT -> Set.of(Field.NAME, Field.SIZE);
                case MEMBER -> Set.of(Field.NAME, Field.TYPE, Field.MEMBER_OFFSET);
                case POINTER -> Set.of(Field.TYPE, Field.SIZE);
                case LOCAL -> Set.of(Field.NAME, Field.TYPE, Field.LOCATION);
            };
            if (!allowed.containsAll(attributes.keySet())) throw new IllegalArgumentException("invalid attribute on " + tag);
            boolean low = attributes.containsKey(Field.LOW_PC);
            boolean high = attributes.containsKey(Field.HIGH_PC);
            if (low != high || (low && attributes.containsKey(Field.RANGES))) {
                throw new IllegalArgumentException("invalid address range on " + tag);
            }
            for (Die child : children) {
                boolean valid = switch (tag) {
                    case UNIT -> Set.of(Tag.FUNCTION, Tag.STRUCT, Tag.BASE, Tag.POINTER).contains(child.tag());
                    case FUNCTION -> child.tag() == Tag.LOCAL;
                    case STRUCT -> child.tag() == Tag.MEMBER;
                    default -> false;
                };
                if (!valid) throw new IllegalArgumentException("invalid child " + child.tag() + " of " + tag);
            }
        }
    }

    private record Shape(Tag tag, boolean children, List<Field> fields) { }
    private record Fixup(int offset, Id target) { }

    static Map<String, byte[]> write(Die unit, int addressBytes, ByteOrder order,
            Map<String, byte[]> supplemental, BooleanSupplier cancelled) {
        if (unit.tag() != Tag.UNIT) throw new IllegalArgumentException("expected compilation unit");
        var writer = new JavaUnitWriter(addressBytes, order, supplemental, cancelled);
        writer.info.fixed(0, 4); // Unit length, filled after its last child.
        writer.info.fixed(5, 2);
        writer.info.fixed(1, 1); // DW_UT_compile
        writer.info.fixed(addressBytes, 1);
        writer.info.offset(0); // This unit owns the first abbreviation table.
        writer.emit(unit);
        byte[] info = writer.info.toByteArray();
        var buffer = ByteBuffer.wrap(info).order(order);
        var length = new DwarfOutput(addressBytes, order);
        length.unitLength(info.length - 4L);
        buffer.put(0, length.toByteArray());
        for (Fixup fixup : writer.fixups) {
            writer.checkCancelled();
            Integer offset = writer.offsets.get(fixup.target());
            if (offset == null) throw new IllegalArgumentException("unresolved DIE " + fixup.target().key());
            if (!writer.types.contains(fixup.target())) throw new IllegalArgumentException("reference to a non-type DIE");
            buffer.putInt(fixup.offset(), offset);
        }
        writer.abbreviations.uleb(0);
        var sections = new LinkedHashMap<String, byte[]>(supplemental);
        sections.put(".debug_info", info);
        sections.put(".debug_abbrev", writer.abbreviations.toByteArray());
        sections.put(".debug_str", writer.strings.toByteArray());
        return sections;
    }

    private final Map<String, byte[]> supplemental;
    private final BooleanSupplier cancelled;
    private final DwarfOutput info;
    private final DwarfOutput strings;
    private final DwarfOutput abbreviations;
    private final Map<Shape, Integer> abbreviationsByShape = new HashMap<>();
    private final Map<String, Integer> stringsByValue = new HashMap<>();
    private final Map<Id, Integer> offsets = new HashMap<>();
    private final Set<Id> types = new java.util.HashSet<>();
    private final List<Fixup> fixups = new ArrayList<>();

    private JavaUnitWriter(int addressBytes, ByteOrder order, Map<String, byte[]> supplemental,
            BooleanSupplier cancelled) {
        this.supplemental = Map.copyOf(supplemental);
        for (String name : supplemental.keySet()) {
            if (!List.of(".debug_line", ".debug_rnglists", ".debug_loclists", ".debug_frame", ".debug_aranges").contains(name)) {
                throw new IllegalArgumentException("unsupported supplemental section " + name);
            }
        }
        this.cancelled = Objects.requireNonNull(cancelled);
        info = new DwarfOutput(addressBytes, order);
        strings = new DwarfOutput(addressBytes, order);
        abbreviations = new DwarfOutput(addressBytes, order);
    }

    private void checkCancelled() {
        if (cancelled.getAsBoolean()) throw new CancellationException("Java producer cancelled");
    }

    private void emit(Die die) {
        checkCancelled();
        if (!offsets.isEmpty() && die.tag() == Tag.UNIT) throw new IllegalArgumentException("nested unit");
        if (offsets.putIfAbsent(die.id(), info.size()) != null) {
            throw new IllegalArgumentException("duplicate DIE " + die.id().key());
        }
        if (die.tag() == Tag.BASE || die.tag() == Tag.POINTER || die.tag() == Tag.STRUCT) types.add(die.id());
        var shape = new Shape(die.tag(), !die.children().isEmpty(), List.copyOf(die.attributes().keySet()));
        info.uleb(abbreviationsByShape.computeIfAbsent(shape, this::defineAbbreviation));
        die.attributes().forEach(this::attribute);
        for (Die child : die.children()) emit(child);
        if (shape.children()) info.uleb(0);
    }

    private int defineAbbreviation(Shape shape) {
        int code = abbreviationsByShape.size() + 1;
        abbreviations.uleb(code);
        abbreviations.uleb(shape.tag().code);
        abbreviations.fixed(shape.children() ? 1 : 0, 1);
        for (Field field : shape.fields()) {
            abbreviations.uleb(field.attribute);
            abbreviations.uleb(field.form);
        }
        abbreviations.uleb(0);
        abbreviations.uleb(0);
        return code;
    }

    private int intern(String string) {
        int offset = strings.size();
        strings.writeBytes(DwarfOutput.stringBytes(string));
        strings.write(0);
        return offset;
    }

    private void attribute(Field field, Object value) {
        switch (field) {
            case NAME, PRODUCER, COMP_DIR -> {
                if (!(value instanceof String string)) throw new IllegalArgumentException("expected string for " + field);
                info.offset(stringsByValue.computeIfAbsent(string, this::intern));
            }
            case TYPE -> {
                if (!(value instanceof Id id)) throw new IllegalArgumentException("expected CU reference");
                fixups.add(new Fixup(info.size(), id));
                info.offset(0);
            }
            case EXTERNAL -> {
                if (!Boolean.TRUE.equals(value)) throw new IllegalArgumentException("expected a present flag");
            }
            case STMT_LIST, LOCATION, RANGES -> {
                long offset = number(field, value);
                byte[] target = supplemental.get(field.section);
                if (target == null || offset < 0 || offset >= target.length) {
                    throw new IllegalArgumentException("invalid offset into " + field.section);
                }
                info.offset(offset);
            }
            case LOW_PC, ENTRY_PC -> info.address(number(field, value));
            case LANGUAGE, SIZE, ENCODING, MEMBER_OFFSET, FILE, LINE, HIGH_PC -> {
                long number = number(field, value);
                if (number < 0) throw new IllegalArgumentException("negative " + field);
                info.uleb(number);
            }
        }
    }

    private static long number(Field field, Object value) {
        if (value instanceof Integer n) return n.longValue();
        if (value instanceof Long n) return n;
        throw new IllegalArgumentException("expected integer for " + field);
    }
}
