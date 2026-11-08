package ghidradwarfforge.unwind;

import java.util.List;
import java.util.Map;
import ghidradwarfforge.elf.ElfRelocatedPointers;

public final class UnwindOptionsSmoke {
    public static void main(String[] args) {
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
    private static void reject(Runnable body) {
        try { body.run(); }
        catch (IllegalArgumentException expected) { return; }
        throw new AssertionError("invalid condition accepted");
    }
}
