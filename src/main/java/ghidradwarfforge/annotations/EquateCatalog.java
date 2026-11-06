package ghidradwarfforge.annotations;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;
import java.util.function.Predicate;

import ghidradwarfforge.GhidraEquateEvidence.Evidence;
import ghidradwarfforge.GhidraEquateEvidence.Status;
import ghidradwarfforge.GhidraEquateEvidence.Value;

/** Synthetic constant views of stored knowledge; no location, macro or lexical lifetime. */
public record EquateCatalog(List<Entry> entries) {
    public record Constant(String name, String view, Value value, boolean direct) { }
    public record Entry(Evidence evidence, List<Constant> constants, String directReason) {
        public Entry { constants = List.copyOf(constants); }
    }
    public EquateCatalog { entries = List.copyOf(entries); }

    private static final Set<String> KEYWORDS = Set.of((
        "alignas alignof and and_eq asm atomic_cancel atomic_commit atomic_noexcept auto bitand bitor bool break " +
        "case catch char char8_t char16_t char32_t class compl concept const consteval constexpr constinit " +
        "const_cast continue co_await co_return co_yield decltype default delete do double dynamic_cast else " +
        "enum explicit export extern false float for friend goto if inline int long mutable namespace new " +
        "noexcept not not_eq nullptr operator or or_eq private protected public reflexpr register reinterpret_cast " +
        "requires return short signed sizeof static static_assert static_cast struct switch synchronized template " +
        "this thread_local throw true try typedef typeid typename union unsigned using virtual void volatile wchar_t " +
        "while xor xor_eq restrict typeof typeof_unqual").split(" "));

    /** The predicate must represent a finite reserved-name set; bound names prevents unbounded suffix search. */
    public static EquateCatalog plan(List<Evidence> input, Predicate<String> reserved, long reservedNames,
            BooleanSupplier cancelled) {
        if (reservedNames < 0) throw new IllegalArgumentException("negative reserved-name count");
        var ordered = new ArrayList<>(input);
        // The identity prefix is common; the encoded length precedes exact UTF-16 units.
        ordered.sort((left, right) -> {
            check(cancelled);
            int length = Integer.compare(left.stored().storedName().length(), right.stored().storedName().length());
            return length != 0 ? length : left.stored().storedName().compareTo(right.stored().storedName());
        });
        var displays = new HashMap<String, Integer>();
        var identities = new HashSet<String>();
        for (var item : ordered) {
            check(cancelled);
            if (!identities.add(item.stored().storedName())) throw new IllegalArgumentException("duplicate stored equate name");
            displays.merge(display(item), 1, Integer::sum);
        }
        var directValues = new HashMap<String, Value>();
        var reasons = new HashMap<String, String>();
        var occupied = new HashSet<String>();
        for (var item : ordered) {
            check(cancelled);
            String name = display(item);
            Value typed = directValue(item, cancelled);
            String reason = !safeIdentifier(name) ? "UNSAFE_IDENTIFIER" : displays.get(name) != 1 ? "DUPLICATE_DISPLAY" :
                reserved.test(name) ? "REAL_NAME_CONFLICT" : typed == null ? "NO_UNAMBIGUOUS_TYPED_VALUE" : "DIRECT_TYPED_VALUE";
            reasons.put(item.stored().storedName(), reason);
            if (reason.equals("DIRECT_TYPED_VALUE")) {
                occupied.add(name);
                directValues.put(item.stored().storedName(), typed);
            }
        }
        var result = new ArrayList<Entry>();
        for (var item : ordered) {
            check(cancelled);
            String stored = item.stored().storedName();
            var views = new TreeMap<String, Value>();
            views.put("stored", new Value(64, true, item.stored().storedValue()));
            views.put("bits", new Value(64, false, item.stored().storedValue()));
            if (item.enumeration().value() != null) views.put("enum", item.enumeration().value());
            for (var reference : item.references()) {
                check(cancelled);
                if (reference.scalar().value() != null) {
                    var value = reference.scalar().value();
                    putView(views, "operand_" + (value.signed() ? "s" : "u") + value.bits(), value);
                }
                if (reference.dynamic().value() != null) {
                    var value = reference.dynamic().value();
                    putView(views, "dynamic_bits" + value.bits(), value);
                }
            }
            String base = aliasBase(stored, cancelled);
            var constants = new ArrayList<Constant>();
            for (var view : views.entrySet()) {
                check(cancelled);
                String candidate = base + "_" + view.getKey();
                String name = candidate;
                long attempt = 0;
                long bound = Math.addExact(reservedNames, occupied.size());
                while (reserved.test(name) || occupied.contains(name)) {
                    check(cancelled);
                    if (++attempt > bound) throw new IllegalArgumentException("incomplete reserved-name bound");
                    name = candidate + "_" + attempt;
                }
                occupied.add(name);
                constants.add(new Constant(name, view.getKey(), view.getValue(), false));
            }
            Value direct = directValues.get(stored);
            if (direct != null) constants.add(new Constant(display(item), "typed", direct, true));
            result.add(new Entry(item, constants, reasons.get(stored)));
        }
        check(cancelled);
        return new EquateCatalog(result);
    }

    private static void putView(TreeMap<String, Value> views, String key, Value value) {
        var previous = views.putIfAbsent(key, value);
        if (previous != null && !previous.equals(value)) throw new IllegalArgumentException("conflicting equate values for one view");
    }

    public static boolean safeIdentifier(String name) {
        return name != null && name.matches("[A-Za-z][A-Za-z0-9_]*") && !KEYWORDS.contains(name);
    }

    public static String display(Evidence item) {
        return item.enumeration().status() == Status.RESOLVED ? item.enumeration().memberNames().getFirst()
            : item.stored().storedName();
    }

    private static Value directValue(Evidence item, BooleanSupplier cancelled) {
        if (item.enumeration().status() == Status.RESOLVED) return item.enumeration().value();
        if (item.enumeration().status() != Status.NOT_ENUM || item.references().isEmpty()) return null;
        Value value = null;
        for (var reference : item.references()) {
            check(cancelled);
            if (reference.scalar().status() != Status.RESOLVED) return null;
            var scalar = reference.scalar().value();
            if (value != null && !value.equals(scalar)) return null;
            value = scalar;
            if (reference.dynamic().status() != Status.NOT_REQUESTED) {
                if (reference.dynamic().status() != Status.RESOLVED || reference.dynamic().value().bits() != value.bits()) return null;
                long mask = value.bits() == 64 ? -1L : -1L >>> (64 - value.bits());
                if ((value.value() & mask) != reference.dynamic().value().value()) return null;
            }
        }
        return value;
    }

    /** Value/reference edits do not rename aliases; malformed surrogate units remain distinct. */
    public static String aliasBase(String name, BooleanSupplier cancelled) {
        try {
            var hash = MessageDigest.getInstance("SHA-256");
            hash.update("GhidraDwarfForge:equate-name:v1\0".getBytes(StandardCharsets.US_ASCII));
            hash.update(ByteBuffer.allocate(8).putLong(name.length()).array());
            var stem = new StringBuilder();
            for (int index = 0; index < name.length(); index++) {
                check(cancelled);
                char unit = name.charAt(index);
                hash.update((byte) (unit >>> 8));
                hash.update((byte) unit);
                if (index < 24) stem.append((unit >= 'A' && unit <= 'Z') || (unit >= 'a' && unit <= 'z') ||
                    (unit >= '0' && unit <= '9') || unit == '_' ? unit : '_');
            }
            return "forge_equate_" + stem + "_" + HexFormat.of().formatHex(hash.digest()).substring(0, 20);
        }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("equate name allocation cancelled");
    }
}
