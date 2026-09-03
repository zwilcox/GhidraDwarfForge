package ghidradwarfforge.source;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Deterministic UTF-8/LF synthetic source and its function line boundaries. */
public record SyntheticSourceFile(byte[] utf8, List<FunctionLines> functions,
        List<SourceLine> mappedLines) {
    public record FunctionText(String name, long address, String c,
            String failureDiagnostic, List<RelativeLine> mappedLines) {
        public FunctionText(String name, long address, String c, String failureDiagnostic) {
            this(name, address, c, failureDiagnostic, List.of());
        }

        public FunctionText {
            if (name == null || name.isBlank() || address < 0) {
                throw new IllegalArgumentException("invalid synthetic-source function");
            }
            if ((c == null) == (failureDiagnostic == null)) {
                throw new IllegalArgumentException(
                    "exactly one of C text or failure diagnostic is required");
            }
            mappedLines = List.copyOf(mappedLines);
        }
    }

    public record RelativeLine(int line, List<Long> addresses) {
        public RelativeLine {
            if (line < 1 || addresses.isEmpty()) {
                throw new IllegalArgumentException("invalid relative source mapping");
            }
            addresses = addresses.stream().distinct().sorted().toList();
        }
    }

    public record SourceLine(int line, List<Long> addresses) {
    }

    public record FunctionLines(String name, long address, int startLine, int endLine,
            boolean decompiled, String failureDiagnostic) {
    }

    public SyntheticSourceFile {
        utf8 = utf8.clone();
        functions = List.copyOf(functions);
        mappedLines = List.copyOf(mappedLines);
    }

    @Override
    public byte[] utf8() {
        return utf8.clone();
    }

    public static SyntheticSourceFile build(String programName, String language,
            List<FunctionText> input) {
        List<FunctionText> ordered = new ArrayList<>(input);
        ordered.sort(Comparator.comparingLong(FunctionText::address)
            .thenComparing(FunctionText::name));
        StringBuilder source = new StringBuilder();
        source.append("/*\n")
            .append(" * Synthetic source reconstructed by GhidraDwarfForge.\n")
            .append(" * This is decompiler output, not recovered original source.\n")
            .append(" * Program: ").append(commentText(programName)).append("\n")
            .append(" * Ghidra language: ").append(commentText(language)).append("\n")
            .append(" */\n\n");
        int line = 8;
        List<FunctionLines> boundaries = new ArrayList<>();
        List<SourceLine> sourceLines = new ArrayList<>();
        for (FunctionText function : ordered) {
            int startLine = line;
            boolean decompiled = function.c() != null;
            String text;
            if (decompiled) {
                text = normalizeC(function.c());
            }
            else {
                text = "/* Decompilation unavailable for " + commentText(function.name()) +
                    " at 0x" + Long.toHexString(function.address()) + ": " +
                    commentText(function.failureDiagnostic()) + " */\n";
            }
            source.append(text);
            int textLines = countNewlines(text);
            line += textLines;
            boundaries.add(new FunctionLines(function.name(), function.address(), startLine,
                line - 1, decompiled, function.failureDiagnostic()));
            if (decompiled) {
                int declarationLine = declarationLine(text, function.name());
                if (declarationLine != 0) {
                    sourceLines.add(new SourceLine(startLine + declarationLine - 1,
                        List.of(function.address())));
                }
                for (RelativeLine mapping : function.mappedLines()) {
                    if (mapping.line() <= textLines) {
                        sourceLines.add(new SourceLine(startLine + mapping.line() - 1,
                            mapping.addresses()));
                    }
                }
            }
            source.append('\n');
            line++;
        }
        return new SyntheticSourceFile(source.toString().getBytes(StandardCharsets.UTF_8),
            boundaries, mergeSourceLines(sourceLines));
    }

    private static int declarationLine(String text, String functionName) {
        String[] lines = text.split("\\n", -1);
        for (int index = 0; index < lines.length; index++) {
            String line = lines[index].strip();
            if (!line.isEmpty() && !line.startsWith("/*") && !line.startsWith("*") &&
                    !line.startsWith("//") && line.contains(functionName) &&
                    line.contains("(")) {
                return index + 1;
            }
        }
        return 0;
    }

    private static List<SourceLine> mergeSourceLines(List<SourceLine> input) {
        Map<Integer, List<Long>> merged = new TreeMap<>();
        for (SourceLine sourceLine : input) {
            merged.computeIfAbsent(sourceLine.line(), ignored -> new ArrayList<>())
                .addAll(sourceLine.addresses());
        }
        return merged.entrySet().stream()
            .map(entry -> new SourceLine(entry.getKey(), entry.getValue().stream()
                .distinct().sorted().toList()))
            .toList();
    }

    public void writeAtomically(Path output) throws IOException {
        Path target = output.toAbsolutePath().normalize();
        Path parent = target.getParent();
        if (parent == null || !Files.isDirectory(parent)) {
            throw new IOException("source output directory does not exist: " + parent);
        }
        Path temporary = Files.createTempFile(parent, ".ghidra-dwarf-forge-source-", ".tmp");
        boolean moved = false;
        try {
            Files.write(temporary, utf8);
            try {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
            }
            catch (AtomicMoveNotSupportedException unsupported) {
                throw new IOException("output filesystem does not support atomic replacement",
                    unsupported);
            }
            moved = true;
        }
        finally {
            if (!moved) {
                Files.deleteIfExists(temporary);
            }
        }
    }

    private static String normalizeC(String value) {
        String normalized = value.replace("\r\n", "\n").replace('\r', '\n');
        int end = normalized.length();
        while (end > 0 && (normalized.charAt(end - 1) == '\n' ||
                normalized.charAt(end - 1) == ' ' || normalized.charAt(end - 1) == '\t')) {
            end--;
        }
        return normalized.substring(0, end) + "\n";
    }

    private static String commentText(String value) {
        if (value == null || value.isBlank()) {
            return "<unavailable>";
        }
        return value.replace("*/", "* /").replace('\r', ' ').replace('\n', ' ');
    }

    private static int countNewlines(String value) {
        int result = 0;
        for (int index = 0; index < value.length(); index++) {
            if (value.charAt(index) == '\n') {
                result++;
            }
        }
        return result;
    }
}
