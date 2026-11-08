package ghidradwarfforge.source;

import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.TreeMap;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/** Composes non-executable comments and all existing source-line evidence together. */
public final class AnnotatedSourceFile {
    /**
     * Zero beforeLine selects the trailing catalog. A positive line requires an
     * address already present in that line's executable token evidence. Callers
     * must establish the annotation's association with that token; an arbitrary
     * function entry or a decompiler warning address is insufficient evidence.
     */
    public record Insertion(String key, String label, String text, int beforeLine, Long tokenAddress) {
        public Insertion {
            Objects.requireNonNull(key, "key");
            Objects.requireNonNull(label, "label");
            Objects.requireNonNull(text, "text");
            if (key.isBlank() || label.isBlank() || beforeLine < 0 || (beforeLine == 0) != (tokenAddress == null)) {
                throw new IllegalArgumentException("invalid annotation placement");
            }
        }
    }

    public record Result(SyntheticSourceFile source, List<Integer> annotationLines) {
        public Result {
            annotationLines = List.copyOf(annotationLines);
        }
    }

    private AnnotatedSourceFile() {
    }

    public static Result compose(SyntheticSourceFile input, List<Insertion> insertions,
            int maxUtf8Bytes, BooleanSupplier cancelled) {
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(insertions, "insertions");
        Objects.requireNonNull(cancelled, "cancelled");
        checkCancelled(cancelled);
        byte[] original = input.utf8();
        if (maxUtf8Bytes < 0 || original.length > maxUtf8Bytes) {
            throw new IllegalArgumentException("synthetic source exceeds annotation composition byte budget");
        }
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(original)).toString();
        }
        catch (java.nio.charset.CharacterCodingException invalid) {
            throw new IllegalArgumentException("synthetic source is not valid UTF-8", invalid);
        }
        if ((!text.isEmpty() && !text.endsWith("\n")) || text.indexOf('\r') >= 0) {
            throw new IllegalArgumentException("annotation composition requires LF-terminated source");
        }
        int originalLines = 0;
        for (int offset = 0; offset < text.length(); offset++) {
            checkCancelled(cancelled);
            if (text.charAt(offset) == '\n') originalLines = Math.incrementExact(originalLines);
        }
        int catalogLine = Math.incrementExact(originalLines);
        var placements = new TreeMap<Integer, List<Insertion>>();
        var keys = new HashSet<String>();
        var missingAnchors = new HashMap<Integer, HashSet<Long>>();
        for (Insertion insertion : insertions) {
            checkCancelled(cancelled);
            if (!keys.add(insertion.key())) throw new IllegalArgumentException("duplicate annotation identity");
            int line = insertion.beforeLine() == 0 ? catalogLine : insertion.beforeLine();
            if (insertion.beforeLine() != 0) {
                if (line > originalLines) {
                    throw new IllegalArgumentException("annotation placement lacks executable token evidence");
                }
                missingAnchors.computeIfAbsent(line, ignored -> new HashSet<>()).add(insertion.tokenAddress());
            }
            placements.computeIfAbsent(line, ignored -> new ArrayList<>()).add(insertion);
        }
        for (var function : input.functionTokens()) {
            for (var token : function.lines()) {
                checkCancelled(cancelled);
                var wanted = missingAnchors.get(token.line());
                if (wanted != null) {
                    for (long address : token.addresses()) {
                        checkCancelled(cancelled);
                        wanted.remove(address);
                    }
                    if (wanted.isEmpty()) missingAnchors.remove(token.line());
                }
            }
        }
        if (!missingAnchors.isEmpty()) throw new IllegalArgumentException("annotation placement lacks executable token evidence");
        var output = new StringBuilder(Math.min(text.length(), 4096));
        var annotationLines = new ArrayList<Integer>();
        var shifts = new TreeMap<Integer, Integer>();
        int added = 0;
        int offset = 0;
        int remaining = maxUtf8Bytes - original.length;
        for (int line = 1;; line++) {
            checkCancelled(cancelled);
            var at = placements.get(line);
            if (at != null) {
                at.sort((left, right) -> {
                    checkCancelled(cancelled);
                    return left.key().compareTo(right.key());
                });
                for (Insertion insertion : at) {
                    // Each original LF ends a displayed payload row. Its explicit
                    // escape preserves the original separator independently of C formatting.
                    String heading = "/* " + AnnotationText.encode(insertion.label(), remaining, cancelled) + " */\n";
                    remaining = appendComment(output, heading, remaining);
                    annotationLines.add(Math.addExact(line, added++));
                    int begin = 0;
                    while (true) {
                        checkCancelled(cancelled);
                        int end = insertion.text().indexOf('\n', begin);
                        boolean last = end < 0;
                        if ((last ? insertion.text().length() : end) - begin > remaining) {
                            throw new IllegalArgumentException("annotation composition exceeds UTF-8 byte budget");
                        }
                        String part = insertion.text().substring(begin, last ? insertion.text().length() : end);
                        String encoded = AnnotationText.encode(part, remaining, cancelled) + (last ? "" : "\\n");
                        remaining = appendComment(output, "/* " + encoded + " */\n", remaining);
                        annotationLines.add(Math.addExact(line, added++));
                        if (last) break;
                        begin = end + 1;
                    }
                }
                shifts.put(line, added);
            }
            if (line != catalogLine) {
                int end = text.indexOf('\n', offset) + 1;
                output.append(text, offset, end);
                offset = end;
            }
            else break;
        }
        int count = originalLines;
        java.util.function.IntUnaryOperator remap = line -> {
            checkCancelled(cancelled);
            if (line < 1 || line > count) throw new IllegalArgumentException("source metadata line outside original text");
            var shift = shifts.floorEntry(line);
            return Math.addExact(line, shift == null ? 0 : shift.getValue());
        };
        var functions = new ArrayList<SyntheticSourceFile.FunctionLines>();
        for (var function : input.functions()) {
            functions.add(new SyntheticSourceFile.FunctionLines(function.name(), function.address(),
                remap.applyAsInt(function.startLine()), remap.applyAsInt(function.endLine()),
                function.decompiled(), function.failureDiagnostic(), function.omissionDiagnostic()));
        }
        var mapped = remap(input.mappedLines(), remap);
        var tokens = new ArrayList<SyntheticSourceFile.FunctionTokens>();
        for (var function : input.functionTokens()) {
            checkCancelled(cancelled);
            tokens.add(new SyntheticSourceFile.FunctionTokens(function.name(), function.address(), remap(function.lines(), remap)));
        }
        checkCancelled(cancelled);
        byte[] bytes = output.toString().getBytes(StandardCharsets.UTF_8);
        if (bytes.length != maxUtf8Bytes - remaining) throw new AssertionError("annotation composition byte accounting changed");
        checkCancelled(cancelled);
        return new Result(new SyntheticSourceFile(bytes, functions, mapped, tokens), annotationLines);
    }

    private static List<SyntheticSourceFile.SourceLine> remap(List<SyntheticSourceFile.SourceLine> lines,
            java.util.function.IntUnaryOperator remap) {
        var result = new ArrayList<SyntheticSourceFile.SourceLine>();
        for (var line : lines) result.add(new SyntheticSourceFile.SourceLine(remap.applyAsInt(line.line()), List.copyOf(line.addresses())));
        return result;
    }

    private static int appendComment(StringBuilder output, String text, int remaining) {
        int bytes = text.getBytes(StandardCharsets.UTF_8).length;
        if (bytes > remaining) throw new IllegalArgumentException("annotation composition exceeds UTF-8 byte budget");
        output.append(text);
        return remaining - bytes;
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("annotation composition cancelled");
    }
}
