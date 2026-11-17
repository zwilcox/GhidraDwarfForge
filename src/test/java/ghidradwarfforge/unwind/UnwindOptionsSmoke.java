package ghidradwarfforge.unwind;

import java.util.List;
import java.util.Map;
import ghidradwarfforge.elf.ElfRelocatedPointers;

public final class UnwindOptionsSmoke {
    public static void main(String[] args) {
        optionBounds();
        require(UnwindOptions.parse(Map.of()).mode() == UnwindOptions.Mode.OFF);
        require(UnwindOptions.parse(Map.of("synthesize-unwind", "strict")).condition(8, 0, List.of()).equals(UnwindStackSeparation.NONE));
        for (var options : List.of(
                Map.of("synthesize-unwind", "yes"),
                Map.of("synthesize-unwind", "conditioned"),
                Map.of("unwind-stack-separation", "100:200"),
                Map.of("synthesize-unwind", "strict", "unwind-stack-separation", "100:200"),
                Map.of("synthesize-unwind", "strict", "unwind-relocated-pointers", "fixed"),
                Map.of("unwind-relocated-pointers", "yes"))) {
            reject(() -> UnwindOptions.parse(options));
        }
        for (String range : List.of("", "100", "100:ff", "100:200,", "-1:2", "0x:2", "1:10000000000000000")) {
            reject(() -> UnwindOptions.parse(Map.of("synthesize-unwind", "conditioned", "unwind-stack-separation", range)));
        }
        var options = UnwindOptions.parse(Map.of("synthesize-unwind", "conditioned",
            "unwind-stack-separation", "0x100:11f,110:127,200:207", "unwind-relocated-pointers", "fixed"));
        var pointers = List.of(new ElfRelocatedPointers.Pointer(0x108, 0x200, 0, 0, "unused"));
        var condition = options.condition(8, 0x1000, pointers);
        require(condition.regions().equals(List.of(new UnwindStackSeparation.Region(0x1100, 0x1127),
            new UnwindStackSeparation.Region(0x1200, 0x1207))));
        require(condition.fixedPointers().equals(List.of(new UnwindStackSeparation.Pointer(0x1108, 0x1200))));
        require(condition.readPointer(new UnwindFlow.Constant(0x1108, 8), 8).value() == 0x1200);
        require(!UnwindStackSeparation.NONE.admits(condition));
        require(condition.basis().contains("throughout execution"));
        var large = UnwindOptions.parse(Map.of("synthesize-unwind", "conditioned", "unwind-stack-separation", "ffffffff:100000001"));
        reject(() -> large.condition(4, 0, List.of()));
        var wrapping = UnwindOptions.parse(Map.of("synthesize-unwind", "conditioned", "unwind-stack-separation", "ffffffffffffff00:fffffffffffffffe"));
        reject(() -> wrapping.condition(8, 0x10, List.of()));
        System.out.println("unwind-options-smoke=PASS");
    }

    private static void require(boolean value) { if (!value) throw new AssertionError(); }

    private static void optionBounds() {
        var ranges = new java.util.ArrayList<UnwindStackSeparation.Region>();
        var text = new java.util.ArrayList<String>();
        for (int index = 0; index < 64; index++) {
            long start = index * 16L;
            ranges.add(new UnwindStackSeparation.Region(start, start + 7));
            text.add(Long.toHexString(start) + ":" + Long.toHexString(start + 7));
        }
        var exact = new UnwindOptions(UnwindOptions.Mode.CONDITIONED, ranges, false);
        var parsed = UnwindOptions.parse(Map.of("synthesize-unwind", "conditioned",
            "unwind-stack-separation", String.join(",", text)));
        require(parsed.equals(exact));
        require(exact.condition(4, 0, List.of()).regions().equals(ranges));
        ranges.add(new UnwindStackSeparation.Region(0x1000, 0x1007));
        reject(() -> new UnwindOptions(UnwindOptions.Mode.CONDITIONED, ranges, false));
        reject(() -> UnwindOptions.parse(Map.of("synthesize-unwind", "conditioned",
            "unwind-stack-separation", String.join(",", text) + ",1000:1007")));
        reject(() -> UnwindOptions.parse(Map.of("synthesize-unwind", "conditioned",
            "unwind-stack-separation", "0".repeat(4097))));
        ranges.clear();
        require(exact.ranges().size() == 64);
        reject(() -> exact.condition(8, 0, List.of(new ElfRelocatedPointers.Pointer(0, 0, 0, 0, "unapproved"))));
        for (var mode : List.of(UnwindOptions.Mode.OFF, UnwindOptions.Mode.STRICT)) {
            reject(() -> new UnwindOptions(mode, List.of(), true));
        }
        var merged = UnwindOptions.parse(Map.of("synthesize-unwind", "conditioned",
            "unwind-stack-separation", "8000000000000010:8000000000000017,100:1ff,110:11f,100:1ff"));
        require(merged.condition(8, 0x1000, List.of()).regions().equals(List.of(
            new UnwindStackSeparation.Region(0x1100, 0x11ff),
            new UnwindStackSeparation.Region(0x8000000000001010L, 0x8000000000001017L))));
        require(!merged.condition(8, 0, List.of()).basis().contains("pointer retains"));
        var fixed = new UnwindOptions(UnwindOptions.Mode.CONDITIONED,
            List.of(new UnwindStackSeparation.Region(0x100, 0x1ff)), true);
        var sorted = fixed.condition(8, 0x1000, List.of(
            new ElfRelocatedPointers.Pointer(0x180, 0x300, 0, 0, "last"),
            new ElfRelocatedPointers.Pointer(0x110, 0x200, 0, 0, "first")));
        require(sorted.fixedPointers().equals(List.of(new UnwindStackSeparation.Pointer(0x1110, 0x1200),
            new UnwindStackSeparation.Pointer(0x1180, 0x1300))));
    }

    private static void reject(Runnable body) {
        try { body.run(); }
        catch (IllegalArgumentException expected) { return; }
        throw new AssertionError("invalid condition accepted");
    }
}
