package ghidradwarfforge.source;

import java.util.Map;

/** Per-export limits; exceeding a limit fails instead of truncating stored knowledge. */
public record AnnotationLimits(int records, int textUnits, int sourceBytes) {
    public static final AnnotationLimits DEFAULT = new AnnotationLimits(1_000_000,
        16 * 1024 * 1024, 128 * 1024 * 1024);

    public AnnotationLimits {
        if (records < 0 || textUnits < 0 || sourceBytes < 0) {
            throw new IllegalArgumentException("negative annotation limit");
        }
    }

    public static AnnotationLimits fromOptions(Map<String, String> options) {
        return new AnnotationLimits(read(options, "annotation-record-limit", DEFAULT.records()),
            read(options, "annotation-text-limit", DEFAULT.textUnits()),
            read(options, "annotation-source-limit", DEFAULT.sourceBytes()));
    }

    private static int read(Map<String, String> options, String name, int fallback) {
        String value = options.get(name);
        if (value == null) return fallback;
        if (!value.matches("[0-9]+")) throw invalid(name);
        try {
            return Integer.parseInt(value);
        }
        catch (NumberFormatException invalid) {
            throw invalid(name);
        }
    }

    private static IllegalArgumentException invalid(String name) {
        return new IllegalArgumentException("--" + name + " must be a decimal integer from 0 to 2147483647");
    }
}
