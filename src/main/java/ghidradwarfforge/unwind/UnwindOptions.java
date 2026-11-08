package ghidradwarfforge.unwind;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;

import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.elf.ElfRelocatedPointers;

/** Explicit export policy. No ELF metadata silently opts an export into assumptions. */
public record UnwindOptions(Mode mode, List<UnwindStackSeparation.Region> ranges, boolean fixedRelocatedPointers) {
    public enum Mode { OFF, STRICT, CONDITIONED }

    public UnwindOptions {
        java.util.Objects.requireNonNull(mode);
        ranges = List.copyOf(ranges);
        if (ranges.size() > 64 || (mode == Mode.CONDITIONED) != !ranges.isEmpty() ||
                (fixedRelocatedPointers && mode != Mode.CONDITIONED)) {
            throw new IllegalArgumentException("conditioned synthesis requires explicit stack separation ranges; other modes forbid conditions");
        }
    }

    public static UnwindOptions parse(Map<String, String> options) {
        Mode mode = switch (options.getOrDefault("synthesize-unwind", "off")) {
            case "off" -> Mode.OFF;
            case "strict" -> Mode.STRICT;
            case "conditioned" -> Mode.CONDITIONED;
            default -> throw new IllegalArgumentException("--synthesize-unwind must be off, strict or conditioned");
        };
        boolean fixed = switch (options.getOrDefault("unwind-relocated-pointers", "off")) {
            case "off" -> false;
            case "fixed" -> true;
            default -> throw new IllegalArgumentException("--unwind-relocated-pointers must be off or fixed");
        };
        var ranges = new ArrayList<UnwindStackSeparation.Region>();
        String text = options.get("unwind-stack-separation");
        if (text != null) {
            if (text.isEmpty() || text.length() > 4096) throw new IllegalArgumentException("invalid stack separation range list");
            for (String part : text.split(",", -1)) {
                String[] ends = part.split(":", -1);
                if (ends.length != 2) throw new IllegalArgumentException("stack separation requires hexadecimal first:last ranges");
                ranges.add(new UnwindStackSeparation.Region(address(ends[0]), address(ends[1])));
                if (ranges.size() > 64) throw new IllegalArgumentException("too many stack separation ranges");
            }
        }
        return new UnwindOptions(mode, ranges, fixed);
    }

    public UnwindStackSeparation condition(ElfImage image, long delta, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        return condition(image.is64Bit() ? 8 : 4, delta,
            fixedRelocatedPointers ? ElfRelocatedPointers.inspect(image, cancelled) : List.of());
    }

    UnwindStackSeparation condition(int width, long delta, List<ElfRelocatedPointers.Pointer> candidates) {
        if (mode != Mode.CONDITIONED) return UnwindStackSeparation.NONE;
        var all = new ArrayList<>(ranges);
        var pointers = new ArrayList<UnwindStackSeparation.Pointer>();
        for (var pointer : candidates) {
            if (!fixedRelocatedPointers) throw new IllegalArgumentException("pointer candidates require explicit fixed-pointer mode");
            all.add(new UnwindStackSeparation.Region(pointer.address(), Math.addExact(pointer.address(), width - 1)));
            pointers.add(new UnwindStackSeparation.Pointer(pointer.address() + delta, pointer.value() + delta));
        }
        all.sort((left, right) -> Long.compareUnsigned(left.first(), right.first()));
        var merged = new ArrayList<UnwindStackSeparation.Region>();
        for (var range : all) {
            if (width == 4 && Long.compareUnsigned(range.last(), 0xffff_ffffL) > 0) {
                throw new IllegalArgumentException("stack separation exceeds original address width");
            }
            if (!merged.isEmpty()) {
                var previous = merged.getLast();
                if (Long.compareUnsigned(range.first(), previous.last()) <= 0) {
                    merged.set(merged.size() - 1, new UnwindStackSeparation.Region(previous.first(),
                        Long.compareUnsigned(previous.last(), range.last()) >= 0 ? previous.last() : range.last()));
                    continue;
                }
            }
            merged.add(range);
        }
        var rebased = new ArrayList<UnwindStackSeparation.Region>();
        for (var range : merged) rebased.add(new UnwindStackSeparation.Region(range.first() + delta, range.last() + delta));
        rebased.sort((left, right) -> Long.compareUnsigned(left.first(), right.first()));
        pointers.sort((left, right) -> Long.compareUnsigned(left.address(), right.address()));
        String basis = "Explicit export condition: these original ELF ranges never overlap live stack storage of the analyzed call groups or their callers";
        if (fixedRelocatedPointers) basis += "; after ordinary relocation each listed pointer retains its recorded value throughout execution and all stack-relative accesses remain disjoint from its slot";
        return new UnwindStackSeparation(width, rebased, basis, pointers);
    }

    private static long address(String value) {
        if (!value.matches("(?:0x)?[0-9a-fA-F]{1,16}")) throw new IllegalArgumentException("invalid hexadecimal stack separation address");
        return Long.parseUnsignedLong(value.startsWith("0x") ? value.substring(2) : value, 16);
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new java.util.concurrent.CancellationException("unwind options cancelled");
    }
}
