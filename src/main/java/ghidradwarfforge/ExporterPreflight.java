package ghidradwarfforge;

import java.util.Objects;

import ghidra.program.model.listing.Program;

/**
 * Safe, native-free checks shared by the GUI and headless entry points.
 *
 * <p>The libdwarfp producer is intentionally not reachable from this class.
 * Native export remains disabled until packaged-native loading and the ELF
 * sidecar strategy have independent validation.</p>
 */
public final class ExporterPreflight {

    private ExporterPreflight() {
    }

    public static String describe(Program program) {
        Objects.requireNonNull(program, "program");

        String executablePath = program.getExecutablePath();
        if (executablePath == null || executablePath.isBlank()) {
            executablePath = "<unavailable>";
        }

        return String.join(System.lineSeparator(),
            "GhidraDwarfForge preflight",
            "  program: " + program.getName(),
            "  executable path: " + executablePath,
            "  executable format: " + program.getExecutableFormat(),
            "  language: " + program.getLanguageID(),
            "  pointer size: " + program.getDefaultPointerSize(),
            "  image base: " + program.getImageBase());
    }
}
