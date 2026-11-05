package ghidradwarfforge;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.concurrent.CancellationException;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.source.AnnotatedSourceFile;
import ghidradwarfforge.source.SyntheticSourceFile;

/** Associates stored comments with existing token evidence, or preserves them in a catalog. */
public final class GhidraListingAnnotationSource {
    public enum Reason {
        TOKEN_LINE, NON_DEFAULT_SPACE, NO_INSTRUCTION, OUTSIDE_EXPORTED_FUNCTION,
        INSTRUCTION_OUTSIDE_BODY, NO_TOKEN_LINE, AMBIGUOUS_TOKEN_LINES, UNTRANSLATABLE_ADDRESS
    }

    /** The line is in the original source, before comment insertion; zero means catalog. */
    public record Placement(GhidraAnnotationInventory.ListingComment comment, Reason reason,
            int beforeLine, Address instruction, Long elfInstruction) { }

    public record Result(SyntheticSourceFile source, List<Integer> annotationLines,
            List<Placement> placements) {
        public Result {
            annotationLines = List.copyOf(annotationLines);
            placements = List.copyOf(placements);
        }
    }

    private GhidraListingAnnotationSource() { }

    public static Result compose(Program program, GhidraAnnotationInventory.Snapshot inventory,
            SyntheticSourceFile source, long rebaseDelta, int maxUtf8Bytes, TaskMonitor monitor)
            throws CancelledException {
        monitor.checkCancelled();
        Map<Long, Map<Long, TreeSet<Integer>>> tokens = new HashMap<>();
        for (var function : source.functionTokens()) {
            var byAddress = tokens.computeIfAbsent(function.address(), ignored -> new HashMap<>());
            for (var line : function.lines()) {
                monitor.checkCancelled();
                for (long address : line.addresses()) {
                    monitor.checkCancelled();
                    byAddress.computeIfAbsent(address, ignored -> new TreeSet<>()).add(line.line());
                }
            }
        }
        var insertions = new ArrayList<AnnotatedSourceFile.Insertion>();
        var placements = new ArrayList<Placement>();
        for (var comment : inventory.comments()) {
            monitor.checkCancelled();
            Placement placement = locate(program, comment, tokens, rebaseDelta);
            placements.add(placement);
            var address = comment.address();
            var space = address.getAddressSpace();
            String identity = "listing:" + space.getName().length() + ":" + space.getName() + ":" +
                space.getSpaceID() + ":" + Long.toUnsignedString(address.getOffset(), 16) + ":" + comment.category().name();
            String label = "Ghidra listing comment " + comment.category().name() + " at " +
                space.getName() + ":0x" + Long.toUnsignedString(address.getOffset(), 16) +
                " [" + placement.reason().name() + "]";
            insertions.add(new AnnotatedSourceFile.Insertion(identity, label, comment.text(),
                placement.beforeLine(), placement.beforeLine() == 0 ? null : placement.elfInstruction()));
        }
        if (!insertions.isEmpty()) {
            insertions.add(new AnnotatedSourceFile.Insertion("listing-encoding", "Ghidra listing comment encoding",
                "Payloads preserve stored text: backslash escapes encode backslashes, controls and unsafe comment delimiters. " +
                    "Each displayed payload row retains its original LF as an explicit escape. " +
                    "Addresses identify Ghidra spaces; catalog rows are not executable source. Authorship is unknown.", 0, null));
        }
        try {
            var composed = AnnotatedSourceFile.compose(source, insertions, maxUtf8Bytes, monitor::isCancelled);
            monitor.checkCancelled();
            return new Result(composed.source(), composed.annotationLines(), placements);
        }
        catch (CancellationException cancelled) {
            throw new CancelledException();
        }
    }

    private static Placement locate(Program program, GhidraAnnotationInventory.ListingComment comment,
            Map<Long, Map<Long, TreeSet<Integer>>> tokens, long rebaseDelta) {
        Address address = comment.address();
        if (!address.getAddressSpace().equals(program.getAddressFactory().getDefaultAddressSpace())) {
            return catalog(comment, Reason.NON_DEFAULT_SPACE);
        }
        var instruction = program.getListing().getInstructionContaining(address);
        if (instruction == null) return catalog(comment, Reason.NO_INSTRUCTION);
        var function = program.getFunctionManager().getFunctionContaining(address);
        if (function == null) return catalog(comment, Reason.OUTSIDE_EXPORTED_FUNCTION);
        if (!function.getEntryPoint().getAddressSpace().equals(address.getAddressSpace()) ||
                !function.getBody().contains(instruction.getMinAddress(), instruction.getMaxAddress())) {
            return catalog(comment, Reason.INSTRUCTION_OUTSIDE_BODY);
        }
        long entry;
        long pc;
        try {
            entry = AddressNormalizer.toElfAddress(function.getEntryPoint().getOffset(), rebaseDelta);
            pc = AddressNormalizer.toElfAddress(instruction.getMinAddress().getOffset(), rebaseDelta);
        }
        catch (ArithmeticException overflow) {
            return catalog(comment, Reason.UNTRANSLATABLE_ADDRESS);
        }
        var byAddress = tokens.get(entry);
        if (byAddress == null) return catalog(comment, Reason.OUTSIDE_EXPORTED_FUNCTION);
        var lines = byAddress.get(pc);
        if (lines == null || lines.isEmpty()) return catalog(comment, Reason.NO_TOKEN_LINE);
        if (lines.size() != 1) return catalog(comment, Reason.AMBIGUOUS_TOKEN_LINES);
        return new Placement(comment, Reason.TOKEN_LINE, lines.first(), instruction.getMinAddress(), pc);
    }

    private static Placement catalog(GhidraAnnotationInventory.ListingComment comment, Reason reason) {
        return new Placement(comment, reason, 0, null, null);
    }
}
