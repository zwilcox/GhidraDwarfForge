package ghidradwarfforge;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.concurrent.CancellationException;

import ghidra.app.decompiler.ClangCommentToken;
import ghidra.app.decompiler.ClangOpToken;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.source.AnnotatedSourceFile;
import ghidradwarfforge.source.AnnotationText;
import ghidradwarfforge.source.SourceContextMode;
import ghidradwarfforge.source.SyntheticSourceFile;

/** Per-export native diagnostic observations; retained text is bounded before source composition. */
public final class GhidraSourceContext {
    public record Limits(int triggersPerFunction, int functionBytes, int exportBytes) {
        public static final Limits DEFAULT = new Limits(8, 65536, 4 * 1024 * 1024);
        public Limits {
            if (triggersPerFunction < 1 || functionBytes < 1024 || exportBytes < 1024) {
                throw new IllegalArgumentException("context limits require positive triggers and at least 1024 bytes");
            }
        }
    }

    private record Trigger(String kind, Address evidence, int relativeLine, String text, long ordinal) { }
    private record Block(Address function, Trigger trigger, String label, String payload) { }
    private static final int MARKER_RESERVE = 512;
    private static final Comparator<Trigger> ORDER = Comparator
        .comparing(Trigger::evidence, Comparator.nullsLast(Comparator.naturalOrder()))
        .thenComparing(Trigger::kind).thenComparingInt(Trigger::relativeLine).thenComparingLong(Trigger::ordinal);

    private final Program program;
    private final SourceContextMode mode;
    private final Limits limits;
    private final List<Block> blocks = new ArrayList<>();
    private int bytes;
    private long skippedFunctions;
    private Address lastFunction;
    private boolean exportExhausted;

    public GhidraSourceContext(Program program, SourceContextMode mode, Limits limits) {
        this.program = java.util.Objects.requireNonNull(program);
        this.mode = java.util.Objects.requireNonNull(mode);
        this.limits = java.util.Objects.requireNonNull(limits);
    }

    /** Called once per selected function in address order, while native markup is still live. */
    public void accept(Function function, DecompileResults result, TaskMonitor monitor) throws CancelledException {
        monitor.checkCancelled();
        if (mode == SourceContextMode.OFF) return;
        checkOrder(function);
        if (exportExhausted || bytes >= limits.exportBytes() - 2 * MARKER_RESERVE) { skippedFunctions++; return; }
        if (result == null || !result.decompileCompleted() || result.getDecompiledFunction() == null) {
            render(function, List.of(new Trigger("DECOMPILATION_FAILURE_ENTRY_SAMPLE", null, 0,
                result == null ? "no native result" : clip(result.getErrorMessage()), 0)), 1, monitor);
            return;
        }
        if (result.getCCodeMarkup() == null) return;
        var selected = new TreeSet<Trigger>(ORDER);
        long total = 0;
        for (var line : DecompilerUtils.toLines(result.getCCodeMarkup())) {
            monitor.checkCancelled();
            boolean warning = false;
            var comment = new StringBuilder();
            boolean clipped = false;
            for (var token : line.getAllTokens()) {
                monitor.checkCancelled();
                String text = token.getText();
                if (token instanceof ClangCommentToken) {
                    // Ghidra 12.0.3 toLines() supplies the whole native comment,
                    // including delimiters, rather than one token per word.
                    if (text != null && text.startsWith("/* WARNING:")) warning = true;
                    if (text != null) {
                        if (comment.length() < 1024) {
                            String part = clip(text);
                            int remaining = 1024 - comment.length();
                            comment.append(part, 0, Math.min(part.length(), remaining)).append(' ');
                            clipped |= part.length() > remaining;
                        }
                        else clipped = true;
                    }
                    continue;
                }
                var operation = token.getPcodeOp();
                if (operation == null) continue;
                String kind;
                if (operation.getOpcode() == PcodeOp.CALLOTHER) kind = "INTRINSIC_CALLOTHER";
                else if (token instanceof ClangOpToken && operation.getOpcode() == PcodeOp.RETURN &&
                        "halt_baddata".equals(text)) kind = "BAD_INSTRUCTION_RETURN";
                else continue;
                add(selected, new Trigger(kind, operation.getSeqnum().getTarget(), line.getLineNumber(),
                    clip(text), total++));
            }
            if (warning) add(selected, new Trigger("NATIVE_WARNING_UNMAPPED", null, line.getLineNumber(),
                comment + (clipped ? " [warning excerpt clipped; full warning remains in synthetic source]" : ""), total++));
        }
        render(function, new ArrayList<>(selected), total, monitor);
    }

    private void checkOrder(Function function) {
        if (function.getProgram() != program || (lastFunction != null &&
                function.getEntryPoint().compareTo(lastFunction) <= 0)) {
            throw new IllegalArgumentException("context requires distinct functions in program address order");
        }
        lastFunction = function.getEntryPoint();
    }

    private void add(TreeSet<Trigger> selected, Trigger trigger) {
        selected.add(trigger);
        if (selected.size() > limits.triggersPerFunction()) selected.pollLast();
    }

    private void render(Function function, List<Trigger> triggers, long total, TaskMonitor monitor)
            throws CancelledException {
        var budget = new GhidraInstructionContext.Budget(function, GhidraInstructionContext.Limits.DEFAULT);
        int functionBytes = 0;
        int emitted = 0;
        String exhausted = null;
        for (var trigger : triggers) {
            monitor.checkCancelled();
            int allowed = Math.min(limits.functionBytes() - functionBytes - MARKER_RESERVE,
                limits.exportBytes() - bytes - 2 * MARKER_RESERVE);
            String label = "Ghidra instruction context " + trigger.kind() + " for " + function.getEntryPoint().toString(true);
            var text = new BoundedText(label, Math.max(0, allowed), monitor);
            text.row("Diagnostic context, not original source or executable line evidence.");
            text.row("language=" + program.getLanguageID() + " compiler=" + program.getCompilerSpec().getCompilerSpecID());
            text.row("trigger=" + trigger.text());
            Address focus = trigger.evidence();
            if (trigger.kind().equals("DECOMPILATION_FAILURE_ENTRY_SAMPLE")) {
                focus = function.getEntryPoint();
                text.row("Entry-region sample; native failure did not identify its cause address.");
            }
            if (focus == null) {
                text.row("No causal instruction address supplied; warning location is not treated as its cause.");
            }
            else {
                var snapshot = GhidraInstructionContext.read(program, function, focus, mode, budget, monitor);
                text.row("focus=" + focus.toString(true) + " body-range=" + snapshot.rangeStart() + ".." + snapshot.rangeEnd());
                for (var item : snapshot.instructions()) {
                    monitor.checkCancelled();
                    text.row("instruction=" + item.start().toString(true) + " listing-length=" + item.listingLength() +
                        " parsed-length=" + item.parsedLength() + " bytes=" + java.util.HexFormat.of().formatHex(item.bytes()) +
                        " status=" + item.byteStatus());
                    if (item.context() != null) text.row("context-register=" + item.context().name() + " bits=" + item.context().bits() +
                        " mask=" + item.context().mask() + " value=" + item.context().value());
                    text.row("in-delay-slot=" + item.inDelaySlot() + " delay-slot-depth=" + item.delaySlotDepth() +
                        " flow-override=" + item.flowOverride());
                    if (item.assembly() != null) text.row("assembly: " + clip(item.assembly()));
                    operations(text, "raw instruction p-code", item.pcode().raw(), monitor);
                    operations(text, "effective flow-override p-code", item.pcode().effective(), monitor);
                    for (String diagnostic : item.pcode().diagnostics()) text.row(diagnostic);
                }
                for (Address reused : snapshot.reused()) text.row("instruction context already shown: " + reused.toString(true));
                for (String diagnostic : snapshot.diagnostics()) text.row(diagnostic);
            }
            if (text.exhausted) {
                exhausted = allowed == limits.exportBytes() - bytes - 2 * MARKER_RESERVE ? "EXPORT_TEXT_LIMIT" : "FUNCTION_TEXT_LIMIT";
                // A partial block is useful, but the marker below makes its incompleteness explicit.
            }
            if (!text.rows.isEmpty()) {
                blocks.add(new Block(function.getEntryPoint(), trigger, label, String.join("\n", text.rows)));
                bytes += text.cost();
                functionBytes += text.cost();
                emitted++;
            }
            if (exhausted != null) break;
        }
        if (total > emitted || exhausted != null) {
            String dimension = exhausted == null ? "FUNCTION_TRIGGER_LIMIT" : exhausted;
            String label = "Ghidra instruction context limit for " + function.getEntryPoint().toString(true);
            String payload = dimension + "; " + (total - emitted) + " trigger blocks omitted" +
                (exhausted == null ? "" : "; last block may be partial") + "; unvisited instruction count unknown.";
            var marker = new BoundedText(label, MARKER_RESERVE, monitor);
            marker.row(payload);
            if (marker.exhausted || marker.rows.isEmpty()) throw new AssertionError("context marker reserve insufficient");
            blocks.add(new Block(function.getEntryPoint(), new Trigger("LIMIT", null, 0, "", Long.MAX_VALUE), label, payload));
            bytes += marker.cost();
            if ("EXPORT_TEXT_LIMIT".equals(exhausted)) exportExhausted = true;
        }
    }

    private static void operations(BoundedText text, String label, List<GhidraInstructionContext.Operation> operations,
            TaskMonitor monitor) throws CancelledException {
        for (var operation : operations) {
            monitor.checkCancelled();
            text.row(label + " " + operation.address().toString(true) + ":" + operation.sequence() + " " +
                operation.mnemonic() + " " + operation.output() + " <- " + String.join(", ", operation.inputs()));
        }
    }

    /** Place only operation-backed tokens beside matching executable evidence; other diagnostics form a catalog. */
    public SyntheticSourceFile compose(SyntheticSourceFile source, long rebaseDelta, int sourceLimit, TaskMonitor monitor)
            throws CancelledException {
        monitor.checkCancelled();
        if (mode == SourceContextMode.OFF || (blocks.isEmpty() && skippedFunctions == 0)) return source;
        Map<Long, SyntheticSourceFile.FunctionLines> functions = new HashMap<>();
        Map<Long, List<SyntheticSourceFile.SourceLine>> tokens = new HashMap<>();
        for (var function : source.functions()) { monitor.checkCancelled(); functions.put(function.address(), function); }
        for (var function : source.functionTokens()) { monitor.checkCancelled(); tokens.put(function.address(), function.lines()); }
        var insertions = new ArrayList<AnnotatedSourceFile.Insertion>();
        for (var block : blocks) {
            monitor.checkCancelled();
            int line = 0;
            Long address = null;
            var trigger = block.trigger();
            try {
                long entry = AddressNormalizer.toElfAddress(block.function().getOffset(), rebaseDelta);
                var function = functions.get(entry);
                if (function != null && trigger.evidence() != null && trigger.relativeLine() > 0 &&
                        trigger.evidence().getAddressSpace().equals(program.getAddressFactory().getDefaultAddressSpace())) {
                    long candidate = AddressNormalizer.toElfAddress(trigger.evidence().getOffset(), rebaseDelta);
                    int proposed = Math.addExact(function.startLine(), trigger.relativeLine() - 1);
                    for (var token : tokens.getOrDefault(entry, List.of())) {
                        monitor.checkCancelled();
                        if (token.line() == proposed && token.addresses().contains(candidate)) { line = proposed; address = candidate; break; }
                    }
                }
            }
            catch (ArithmeticException outsideModel) { /* Preserve diagnostic in the catalog. */ }
            insertions.add(new AnnotatedSourceFile.Insertion(String.format(java.util.Locale.ROOT, "context:%08d", insertions.size()),
                block.label(), block.payload(), line, address));
        }
        if (skippedFunctions > 0) insertions.add(new AnnotatedSourceFile.Insertion("context:export-limit", "Ghidra instruction context limit",
            "EXPORT_TEXT_LIMIT; " + skippedFunctions + " later functions not inspected for context; trigger/instruction counts unknown.", 0, null));
        try { return AnnotatedSourceFile.compose(source, insertions, sourceLimit, monitor::isCancelled).source(); }
        catch (CancellationException cancelled) { throw new CancelledException(); }
    }

    private static String clip(String value) {
        if (value == null) return "";
        if (value.length() <= 1024) return value;
        return value.substring(0, 1024) + " [excerpt clipped; " + (value.length() - 1024) + " UTF-16 units omitted]";
    }

    /** Counts the actual reversible comment framing, including row separators. */
    private static final class BoundedText {
        final List<String> rows = new ArrayList<>();
        final TaskMonitor monitor;
        final int limit;
        int bytes;
        boolean exhausted;
        BoundedText(String label, int limit, TaskMonitor monitor) throws CancelledException {
            this.monitor = monitor;
            this.limit = limit;
            bytes = 7 + encodedBytes(label);
        }
        void row(String value) throws CancelledException {
            monitor.checkCancelled();
            if (exhausted) return;
            // Embedded newlines are preserved by the compositor as additional payload rows.
            int cost = 0;
            String[] parts = value.split("\n", -1);
            for (String part : parts) cost = Math.addExact(cost, 7 + encodedBytes(part));
            cost = Math.addExact(cost, 2 * (parts.length - 1) + (rows.isEmpty() ? 0 : 2));
            if (cost > limit - bytes) { exhausted = true; return; }
            rows.add(value);
            bytes += cost;
        }
        int cost() { return bytes; }
        int encodedBytes(String value) throws CancelledException {
            try { return AnnotationText.encode(value, Integer.MAX_VALUE, monitor::isCancelled).getBytes(StandardCharsets.UTF_8).length; }
            catch (CancellationException cancelled) { throw new CancelledException(); }
        }
    }
}
