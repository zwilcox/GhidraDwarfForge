package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Original declared frame coverage protected against selected ordinary loader
 * writes. Coverage is precedence evidence, not a certificate of CFI semantics.
 * Unknown metadata fails inspection and must never be converted to empty coverage.
 */
public final class OriginalUnwindCoverage {
    public record Interval(long address, long end) { }
    private final OriginalFrameSources.Inventory sources;
    private final ElfRelocationEffects effects;
    private final List<Interval> intervals;

    private OriginalUnwindCoverage(OriginalFrameSources.Inventory sources, ElfRelocationEffects effects,
            List<Interval> intervals) {
        this.sources = sources;
        this.effects = effects;
        this.intervals = List.copyOf(intervals);
    }
    public OriginalFrameSources.Inventory sources() { return sources; }
    public ElfRelocationEffects effects() { return effects; }
    public List<Interval> intervals() { return intervals; }

    public static OriginalUnwindCoverage inspect(ElfImage image, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        var effects = ElfRelocationEffects.inspect(image, cancelled);
        var sources = OriginalFrameSources.inspect(image, cancelled);
        effects.requireUnchanged(sources, cancelled);
        // Discovery/search metadata is evidence too, even though it is not a
        // frame instruction stream and therefore not a Source in the inventory.
        for (var segment : image.segments()) {
            check(cancelled);
            if (segment.type == 0x6474e550L) effects.requireFileUnchanged(segment.offset, segment.fileSize, cancelled);
        }
        for (var section : image.sections()) {
            check(cancelled);
            if (section.name.equals(".eh_frame_hdr")) effects.requireFileUnchanged(section.offset, section.size, cancelled);
        }
        var sorted = new ArrayList<Interval>();
        for (var source : sources.sources()) for (var frame : source.records().frames()) {
            check(cancelled);
            if (frame.size() != 0) sorted.add(new Interval(frame.address(), Math.addExact(frame.address(), frame.size())));
        }
        sorted.sort(Comparator.comparingLong(Interval::address).thenComparingLong(Interval::end));
        var merged = new ArrayList<Interval>();
        for (var range : sorted) {
            check(cancelled);
            if (!merged.isEmpty() && range.address() <= merged.getLast().end()) {
                var last = merged.removeLast();
                merged.add(new Interval(last.address(), Math.max(last.end(), range.end())));
            }
            else merged.add(range);
        }
        check(cancelled);
        try (var channel = FileChannel.open(image.sourcePath(), StandardOpenOption.READ)) { image.requireUnchanged(channel); }
        return new OriginalUnwindCoverage(sources, effects, merged);
    }

    /** Half-open original link-time VA interval; any overlap suppresses a whole instruction. */
    public boolean overlaps(long address, long size) {
        if (address < 0 || size <= 0) throw new IllegalArgumentException("invalid original coverage query");
        long end = Math.addExact(address, size);
        int low = 0, high = intervals.size();
        while (low < high) {
            int middle = (low + high) >>> 1;
            if (intervals.get(middle).address() < end) low = middle + 1; else high = middle;
        }
        return low != 0 && intervals.get(low - 1).end() > address;
    }
    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("original unwind coverage cancelled");
    }
}
