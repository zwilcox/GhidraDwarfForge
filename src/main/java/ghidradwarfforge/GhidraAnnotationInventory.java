package ghidradwarfforge;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CancellationException;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Read-only snapshot of listing annotations, without inferring authorship or C semantics. */
public final class GhidraAnnotationInventory {
    public record ListingComment(Address address, CommentType category, String text) { }

    /** The hash and operand are independent reference fields, including dynamic-only operand -1. */
    public record EquateReference(Address address, int operand, long dynamicHash) { }

    /** Stored name/value are exact database representations, not a validated display name or C type. */
    public record EquateValue(String storedName, long storedValue, List<EquateReference> references) {
        public EquateValue {
            references = List.copyOf(references);
        }
    }

    public record Snapshot(List<ListingComment> comments, List<EquateValue> equates,
            long commentAddresses, long records, long textUnits) {
        public Snapshot {
            comments = List.copyOf(comments);
            equates = List.copyOf(equates);
        }
    }

    /** Count each comment, equate and equate reference; count exact UTF-16 name/comment units. */
    public record Limits(long records, long textUnits) {
        public Limits {
            if (records < 0 || textUnits < 0) throw new IllegalArgumentException("negative annotation inventory limit");
        }
    }

    private static final Comparator<Address> ADDRESSES = Comparator
        .comparing((Address address) -> address.getAddressSpace().getName())
        .thenComparingInt(address -> address.getAddressSpace().getSpaceID())
        .thenComparing(Address::compareTo);

    private GhidraAnnotationInventory() { }

    public static Snapshot read(Program program, Limits limits, TaskMonitor monitor) throws CancelledException {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(monitor, "monitor");
        monitor.checkCancelled();
        var budget = new Budget(limits);
        var listing = program.getListing();
        long expectedAddresses = listing.getCommentAddressCount();
        budget.requireRecords(expectedAddresses);
        var seen = new HashSet<Address>();
        var comments = new ArrayList<ListingComment>();
        for (var scan : commentScans(program, monitor)) {
            var addresses = listing.getCommentAddressIterator(scan, true);
            while (addresses.hasNext()) {
                monitor.checkCancelled();
                Address address = addresses.next();
                if (!seen.add(address)) throw new IllegalStateException("Duplicate annotation address during inventory: " + address);
                int before = comments.size();
                for (CommentType category : CommentType.values()) {
                    monitor.checkCancelled();
                    String text = listing.getComment(category, address);
                    if (text != null) {
                        budget.add(text.length());
                        comments.add(new ListingComment(address, category, text));
                    }
                }
                if (comments.size() == before) throw new IllegalStateException("Comment address lost all categories during inventory");
            }
        }
        if (seen.size() != expectedAddresses || listing.getCommentAddressCount() != expectedAddresses) {
            throw new IllegalStateException("Incomplete or changing Ghidra comment inventory: expected " +
                expectedAddresses + " addresses, read " + seen.size());
        }
        var equates = new ArrayList<EquateValue>();
        var names = new HashSet<String>();
        for (var iterator = program.getEquateTable().getEquates(); iterator.hasNext();) {
            monitor.checkCancelled();
            var equate = iterator.next();
            String name = equate.getName();
            budget.add(name.length());
            if (!names.add(name)) throw new IllegalStateException("Duplicate stored equate name during inventory");
            var references = new ArrayList<EquateReference>();
            int referenceCount = equate.getReferenceCount();
            budget.requireRecords(referenceCount);
            var storedReferences = equate.getReferences();
            if (storedReferences.length != referenceCount) throw new IllegalStateException("Changing equate references during inventory");
            for (var reference : storedReferences) {
                monitor.checkCancelled();
                budget.add(0);
                references.add(new EquateReference(reference.getAddress(), reference.getOpIndex(),
                    reference.getDynamicHashValue()));
            }
            sort(references, Comparator.comparing(EquateReference::address, ADDRESSES)
                .thenComparingInt(EquateReference::operand).thenComparingLong(EquateReference::dynamicHash), monitor);
            equates.add(new EquateValue(name, equate.getValue(), references));
        }
        sort(comments, Comparator.comparing(ListingComment::address, ADDRESSES)
            .thenComparing(comment -> comment.category().name()), monitor);
        sort(equates, Comparator.comparing(EquateValue::storedName), monitor);
        monitor.checkCancelled();
        return new Snapshot(comments, equates, expectedAddresses, budget.records, budget.textUnits);
    }

    private static List<AddressSet> commentScans(Program program, TaskMonitor monitor) throws CancelledException {
        var combined = new AddressSet();
        var scans = new ArrayList<AddressSet>();
        scans.add(combined);
        for (AddressSpace space : program.getAddressFactory().getAllAddressSpaces()) {
            monitor.checkCancelled();
            boolean encodable = switch (space.getType()) {
                case AddressSpace.TYPE_UNKNOWN, AddressSpace.TYPE_RAM, AddressSpace.TYPE_CODE,
                    AddressSpace.TYPE_DELETED, AddressSpace.TYPE_OTHER, AddressSpace.TYPE_VARIABLE,
                    AddressSpace.TYPE_REGISTER, AddressSpace.TYPE_STACK, AddressSpace.TYPE_EXTERNAL -> true;
                default -> false;
            };
            if (!encodable) continue;
            if (space.isStackSpace()) {
                // Ghidra 12.0.3 AddressMapDB stores stack keys as unsigned 32-bit offsets.
                // This is a database encoding constraint, not a target pointer/ABI width.
                // Combining these signed halves would reverse the DB interval on MIPS32.
                long minimum = Math.max(space.getMinAddress().getOffset(), Integer.MIN_VALUE);
                long maximum = Math.min(space.getMaxAddress().getOffset(), Integer.MAX_VALUE);
                if (minimum < 0) scans.add(new AddressSet(space.getAddress(minimum), space.getAddress(-1)));
                if (maximum >= 0) scans.add(new AddressSet(space.getAddress(0), space.getAddress(maximum)));
            }
            else combined.addRange(space.getMinAddress(), space.getMaxAddress());
        }
        return scans;
    }

    private static <T> void sort(List<T> values, Comparator<T> comparator, TaskMonitor monitor)
            throws CancelledException {
        monitor.checkCancelled();
        try {
            values.sort((left, right) -> {
                if (monitor.isCancelled()) throw new CancellationException();
                return comparator.compare(left, right);
            });
        }
        catch (CancellationException cancelled) {
            throw new CancelledException();
        }
        monitor.checkCancelled();
    }

    private static final class Budget {
        private final Limits limits;
        private long records;
        private long textUnits;

        private Budget(Limits limits) {
            this.limits = limits;
        }

        private void add(int units) {
            if (records >= limits.records() || units > limits.textUnits() - textUnits) {
                throw new IllegalArgumentException("Ghidra annotation inventory exceeds its record or UTF-16 text limit; " +
                    "increase the explicit limit to preserve all annotations (nothing was truncated)");
            }
            records++;
            textUnits += units;
        }

        private void requireRecords(long count) {
            if (count < 0 || count > limits.records() - records) {
                throw new IllegalArgumentException("Ghidra annotation inventory exceeds its explicit record limit; " +
                    "increase the limit to preserve all annotations (nothing was truncated)");
            }
        }
    }
}
