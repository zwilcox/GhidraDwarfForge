package ghidradwarfforge.elf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

import ghidradwarfforge.calls.CallSitePlan;
import ghidradwarfforge.nativeapi.DwarfTarget;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** Exact entry, lossless body, collision and admission controls without native code. */
public final class CallOriginSymbolsSmoke {
    private static int checks;
    private static final FunctionSymbol CALLEE = new FunctionSymbol("recovered", 0x1044,
        List.of(new FunctionRange(0x1040, 8), new FunctionRange(0x1050, 8)));
    private static final FunctionSymbol CALLER = new FunctionSymbol("caller", 0x1060, 8);
    private static final List<FunctionSymbol> FUNCTIONS = List.of(CALLEE, CALLER);
    private static final CallSitePlan CALLS = new CallSitePlan(List.of(new CallSitePlan.FunctionCalls(
        CALLER.address(), CallSitePlan.Completeness.PARTIAL,
        List.of(new CallSitePlan.Site(0x1060, 0x1065, false, CALLEE.address(), List.of())))));

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-call-origin-");
        for (boolean wide : List.of(false, true)) for (var order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
            byte[] bytes = LocalSymbolMergeSmoke.fixture(wide, order, false, false);
            Path input = root.resolve("input");
            Files.write(input, bytes);
            ElfImage image = ElfImage.read(input);
            var symbols = plan(image, FUNCTIONS, Set.of());
            require(symbols.size() == 1, "missing exact entry symbol");
            var symbol = symbols.getFirst();
            require(symbol.value() == CALLEE.address() && symbol.size() == 4 && symbol.sectionIndex() == 1,
                "symbol must cover only entry range suffix, never padding or pre-entry code");
            require(symbol.name().matches("forge_call_entry_[0-9a-f]{64}_1044"), "unidentified synthetic name");
            require(symbols.equals(plan(image, FUNCTIONS, Set.of())), "nondeterministic symbols");
            require(plan(image, FUNCTIONS, Set.of(symbol.name())).getFirst().name().equals(symbol.name() + "_1"),
                "reserved name reused");
            require(plan(image, FUNCTIONS, Set.of(symbol.name(), symbol.name() + "_1")).getFirst().name().equals(symbol.name() + "_2"),
                "reserved suffix reused");
            var renamed = new FunctionSymbol("analyst::renamed", CALLEE.address(), CALLEE.ranges());
            require(symbols.equals(plan(image, List.of(renamed, CALLER), Set.of())), "entry depends on recovered spelling");
            require(plan(image, List.of(CALLEE, CALLER, new FunctionSymbol("overlap", 0x1046, 2)), Set.of()).isEmpty(),
                "overlapping function acquired exact symbol");
            require(plan(image, List.of(CALLEE, CALLEE, CALLER), Set.of()).isEmpty(), "duplicate entry accepted");
            require(CallOriginSymbols.plan(image, CallSitePlan.EMPTY, FUNCTIONS, null, List.of(), Set.of(),
                () -> false, ignored -> { }).isEmpty(), "unreferenced function acquired lookup symbol");
            var diagnostics = new java.util.ArrayList<String>();
            require(CallOriginSymbols.plan(image, CALLS, java.util.Collections.nCopies(65537, CALLEE),
                null, List.of(), Set.of(), () -> false, diagnostics::add).isEmpty() &&
                diagnostics.toString().contains("budget"), "candidate budget ignored");
            if (!wide) require(DwarfTarget.fromElf(image).planCallOriginSymbols(image, CALLS, FUNCTIONS,
                null, List.of(), Set.of(), () -> false, ignored -> { }).isEmpty(), "unaudited target symbol policy enabled");
            var count = new AtomicInteger();
            CallOriginSymbols.plan(image, CALLS, FUNCTIONS, null, List.of(), Set.of(),
                () -> { count.incrementAndGet(); return false; }, ignored -> { });
            for (int stop = 1; stop <= count.get(); stop++) {
                int at = stop;
                var polls = new AtomicInteger();
                try {
                    CallOriginSymbols.plan(image, CALLS, FUNCTIONS, null, List.of(), Set.of(),
                        () -> polls.incrementAndGet() >= at, ignored -> { });
                    throw new AssertionError("cancel ignored at " + at);
                }
                catch (CancellationException expected) { checks++; }
            }
            for (String field : List.of("flags", "type", "size")) {
                byte[] altered = bytes.clone();
                LocalSymbolMergeSmoke.field(altered, 1, field, field.equals("flags") ? 2 : field.equals("type") ? 8 : 0x46);
                Files.write(input, altered);
                require(plan(ElfImage.read(input), FUNCTIONS, Set.of()).isEmpty(), "non-executable/non-file-backed range accepted");
            }
            byte[] overlap = bytes.clone();
            LocalSymbolMergeSmoke.field(overlap, 4, "flags", 2);
            LocalSymbolMergeSmoke.field(overlap, 4, "address", 0x1044);
            LocalSymbolMergeSmoke.field(overlap, 4, "size", 4);
            Files.write(input, overlap);
            require(plan(ElfImage.read(input), FUNCTIONS, Set.of()).isEmpty(), "overlapping allocation accepted");
            byte[] changed = bytes.clone();
            changed[0x140] = 1;
            Files.write(input, changed);
            require(!plan(ElfImage.read(input), FUNCTIONS, Set.of()).getFirst().name().equals(symbol.name()),
                "different ELF image reused lookup namespace");
            try {
                plan(image, FUNCTIONS, Set.of());
                throw new AssertionError("changed original image accepted");
            }
            catch (java.io.IOException expected) { checks++; }
            byte[] sectionless = bytes.clone();
            var raw = ByteBuffer.wrap(sectionless).order(order);
            int ph = wide ? 64 : 52;
            if (wide) {
                raw.putLong(32, ph).putLong(40, 0);
                raw.putShort(54, (short) 56).putShort(56, (short) 1);
                raw.putShort(58, (short) 0).putShort(60, (short) 0).putShort(62, (short) 0);
                raw.putInt(ph, 1).putInt(ph + 4, 5).putLong(ph + 8, 0x100).putLong(ph + 16, 0x1000);
                raw.putLong(ph + 24, 0x1000).putLong(ph + 32, 128).putLong(ph + 40, 128).putLong(ph + 48, 0x100);
            }
            else {
                raw.putInt(28, ph).putInt(32, 0);
                raw.putShort(42, (short) 32).putShort(44, (short) 1);
                raw.putShort(46, (short) 0).putShort(48, (short) 0).putShort(50, (short) 0);
                raw.putInt(ph, 1).putInt(ph + 4, 0x100).putInt(ph + 8, 0x1000).putInt(ph + 12, 0x1000);
                raw.putInt(ph + 16, 128).putInt(ph + 20, 128).putInt(ph + 24, 5).putInt(ph + 28, 0x100);
            }
            Files.write(input, sectionless);
            require(plan(ElfImage.read(input), FUNCTIONS, Set.of()).getFirst().sectionIndex() == 1,
                "sectionless load allocation lost");
            raw.putInt(ph + (wide ? 4 : 24), 4);
            Files.write(input, sectionless);
            require(plan(ElfImage.read(input), FUNCTIONS, Set.of()).isEmpty(), "non-executable sectionless load accepted");
            if (wide && order == ByteOrder.LITTLE_ENDIAN) for (int machine : List.of(62, 183)) {
                ByteBuffer.wrap(bytes).order(order).putShort(18, (short) machine);
                Files.write(input, bytes);
                var targetImage = ElfImage.read(input);
                require(DwarfTarget.fromElf(targetImage).planCallOriginSymbols(targetImage, CALLS, FUNCTIONS,
                    null, List.of(), Set.of(), () -> false, ignored -> { }).size() == 1, "audited direct-address target rejected");
            }
        }
        System.out.println("call-origin-symbols=PASS checks=" + checks);
    }

    private static List<ElfLocalFunctionSymbol> plan(ElfImage image, List<FunctionSymbol> functions,
            Set<String> reserved) throws Exception {
        return CallOriginSymbols.plan(image, CALLS, functions, null, List.of(), reserved, () -> false, ignored -> { });
    }

    private static void require(boolean value, String reason) {
        checks++;
        if (!value) throw new AssertionError(reason);
    }
}
