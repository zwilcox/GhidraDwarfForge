package ghidradwarfforge;

import java.util.ArrayList;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.annotations.EquateCatalog;
import ghidradwarfforge.source.AnnotatedSourceFile;
import ghidradwarfforge.source.SyntheticSourceFile;

/** A non-executable, reversible lookup catalog; values are recovered knowledge, not C macros. */
public final class GhidraEquateSource {
    private GhidraEquateSource() { }

    public static SyntheticSourceFile compose(SyntheticSourceFile source, EquateCatalog catalog,
            int maxUtf8Bytes, TaskMonitor monitor) throws CancelledException {
        var insertions = new ArrayList<AnnotatedSourceFile.Insertion>();
        long[] remaining = { maxUtf8Bytes };
        for (var entry : catalog.entries()) {
            monitor.checkCancelled();
            var text = new StringBuilder();
            var evidence = entry.evidence();
            append(text, "Stored name: " + evidence.stored().storedName(), remaining, monitor);
            append(text, "Database signed 64-bit value: " + evidence.stored().storedValue(), remaining, monitor);
            append(text, "Database 64-bit pattern: 0x" + Long.toUnsignedString(evidence.stored().storedValue(), 16), remaining, monitor);
            append(text, "Direct lookup: " + entry.directReason(), remaining, monitor);
            append(text, "Enum evidence: " + evidence.enumeration().status(), remaining, monitor);
            if (evidence.enumeration().typePath() != null) {
                append(text, "Enum type: " + evidence.enumeration().typePath(), remaining, monitor);
            }
            for (String member : evidence.enumeration().memberNames()) append(text, "Enum member: " + member, remaining, monitor);
            for (var constant : entry.constants()) {
                monitor.checkCancelled();
                var value = constant.value();
                append(text, "Lookup " + constant.name() + " [" + constant.view() + "; " +
                    (value.signed() ? "signed " : "unsigned ") + value.bits() + " bits] = " +
                    (value.signed() ? Long.toString(value.value()) : Long.toUnsignedString(value.value())), remaining, monitor);
            }
            for (var reference : evidence.references()) {
                monitor.checkCancelled();
                var stored = reference.reference();
                append(text, "Reference " + stored.address().getAddressSpace().getName() + ":0x" +
                    Long.toUnsignedString(stored.address().getOffset(), 16) + " operand=" + stored.operand() +
                    " dynamicHash=0x" + Long.toUnsignedString(stored.dynamicHash(), 16), remaining, monitor);
                append(text, "Operand evidence: " + reference.scalar().status() +
                    "; high-p-code evidence: " + reference.dynamic().status(), remaining, monitor);
            }
            String name = evidence.stored().storedName();
            insertions.add(new AnnotatedSourceFile.Insertion("equate:" + name.length() + ":" + name,
                "Ghidra equate (synthetic lookup; no storage or lifetime)", text.toString(), 0, null));
        }
        monitor.checkCancelled();
        try {
            return AnnotatedSourceFile.compose(source, insertions, maxUtf8Bytes, monitor::isCancelled).source();
        }
        catch (java.util.concurrent.CancellationException cancelled) { throw new CancelledException(); }
    }

    private static void append(StringBuilder text, String line, long[] remaining, TaskMonitor monitor)
            throws CancelledException {
        monitor.checkCancelled();
        long units = (long) line.length() + 1;
        if (units > remaining[0]) throw new IllegalArgumentException("equate catalog exceeds source byte budget");
        remaining[0] -= units;
        text.append(line).append('\n');
    }
}
