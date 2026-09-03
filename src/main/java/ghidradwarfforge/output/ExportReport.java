package ghidradwarfforge.output;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import ghidradwarfforge.GhidraFunctionSymbols.SkippedFunction;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;
import ghidradwarfforge.nativeapi.DwarfTarget;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph.OpaqueType;

/** Deterministic, dependency-free JSON summary for one export attempt. */
public final class ExportReport {
    public static final int SCHEMA_VERSION = 1;

    public enum Status {
        SUCCESS, PARTIAL, CANCELLED, FATAL
    }

    public enum ValidationStatus {
        NOT_RUN
    }

    public record TargetInfo(String architecture, int addressBits, String byteOrder) {
        public TargetInfo {
            requireText(architecture, "target architecture");
            requireText(byteOrder, "target byte order");
            if (addressBits != 32 && addressBits != 64) {
                throw new IllegalArgumentException("target address size must be 32 or 64 bits");
            }
        }
    }

    public record Artifacts(String inputPath, String inputSha256, String outputPath,
            String outputSha256, String sourcePath, String sourceSha256) {
        public Artifacts {
            requireText(inputPath, "input path");
            requireHash(inputSha256, "input SHA-256");
            requireText(outputPath, "output path");
            requireHash(outputSha256, "output SHA-256");
            requireText(sourcePath, "source path");
            requireHash(sourceSha256, "source SHA-256");
        }
    }

    public record Counts(int functionsExported, int functionsDecompiled,
            int functionsFailed, int functionsSkipped, int functionSignatures,
            int parameters, int localVariables, int globalVariables, int canonicalTypes,
            int defensibleVariableLocations, int omittedLocationRanges,
            int mappedSourceLines, int unsupportedConstructs, int diagnostics) {
        public Counts {
            if (functionsExported < 0 || functionsDecompiled < 0 || functionsFailed < 0 ||
                    functionsSkipped < 0 || functionSignatures < 0 || parameters < 0 ||
                    localVariables < 0 || globalVariables < 0 || canonicalTypes < 0 ||
                    defensibleVariableLocations < 0 || omittedLocationRanges < 0 ||
                    mappedSourceLines < 0 || unsupportedConstructs < 0 || diagnostics < 0) {
                throw new IllegalArgumentException("export counts must be nonnegative");
            }
        }
    }

    public record FunctionFailure(String name, long address, String diagnostic) {
        public FunctionFailure {
            requireText(name, "failed function name");
            requireText(diagnostic, "failed function diagnostic");
        }
    }

    public record SkippedFunctionInfo(String name, String reason) {
        public SkippedFunctionInfo {
            requireText(name, "skipped function name");
            requireText(reason, "skipped function reason");
        }
    }

    public record OmittedLocation(String function, String variable, String kind,
            long startAddress, long endAddress, String reason, String diagnostic) {
        public OmittedLocation {
            requireText(function, "omitted-location function");
            requireText(variable, "omitted-location variable");
            requireText(kind, "omitted-location variable kind");
            requireText(reason, "omitted-location reason");
            requireText(diagnostic, "omitted-location diagnostic");
            if (startAddress < 0 || endAddress <= startAddress) {
                throw new IllegalArgumentException("invalid omitted-location range");
            }
        }
    }

    public record UnsupportedConstruct(String kind, String name, String diagnostic) {
        public UnsupportedConstruct {
            requireText(kind, "unsupported construct kind");
            requireText(name, "unsupported construct name");
            requireText(diagnostic, "unsupported construct diagnostic");
        }
    }

    public record Failure(String type, String message) {
        public Failure {
            requireText(type, "failure type");
            requireText(message, "failure message");
        }
    }

    private final Status status;
    private final TargetInfo target;
    private final Artifacts artifacts;
    private final Counts counts;
    private final List<String> sections;
    private final List<FunctionFailure> failedFunctions;
    private final List<SkippedFunctionInfo> skippedFunctions;
    private final List<OmittedLocation> omittedLocations;
    private final List<UnsupportedConstruct> unsupportedConstructs;
    private final List<String> diagnostics;
    private final ValidationStatus validationStatus;
    private final String libdwarfVersion;
    private final Failure failure;

    private ExportReport(Status status, TargetInfo target, Artifacts artifacts, Counts counts,
            List<String> sections, List<FunctionFailure> failedFunctions,
            List<SkippedFunctionInfo> skippedFunctions,
            List<OmittedLocation> omittedLocations,
            List<UnsupportedConstruct> unsupportedConstructs, List<String> diagnostics,
            ValidationStatus validationStatus, String libdwarfVersion, Failure failure) {
        this.status = status;
        this.target = target;
        this.artifacts = artifacts;
        this.counts = counts;
        this.sections = List.copyOf(sections);
        this.failedFunctions = List.copyOf(failedFunctions);
        this.skippedFunctions = List.copyOf(skippedFunctions);
        this.omittedLocations = List.copyOf(omittedLocations);
        this.unsupportedConstructs = List.copyOf(unsupportedConstructs);
        this.diagnostics = List.copyOf(diagnostics);
        this.validationStatus = validationStatus;
        this.libdwarfVersion = libdwarfVersion;
        this.failure = failure;
    }

    public static ExportReport completed(DwarfTarget target, String libdwarfVersion,
            Path input, String inputSha256, Path output, String outputSha256,
            Path sourcePath, String sourceSha256, int functionCount,
            List<String> sectionNames, SyntheticSourceFile source,
            ProgramTypeModel typeModel, List<SkippedFunction> skipped,
            List<String> diagnosticMessages) {
        if (target == null || source == null || typeModel == null) {
            throw new IllegalArgumentException("completed export report requires its models");
        }
        List<FunctionFailure> failures = source.functions().stream()
            .filter(function -> !function.decompiled())
            .map(function -> new FunctionFailure(function.name(), function.address(),
                function.failureDiagnostic()))
            .sorted(Comparator.comparingLong(FunctionFailure::address)
                .thenComparing(FunctionFailure::name))
            .toList();
        List<SkippedFunctionInfo> skippedFunctions = skipped.stream()
            .map(function -> new SkippedFunctionInfo(function.name(), function.reason().name()))
            .sorted(Comparator.comparing(SkippedFunctionInfo::name)
                .thenComparing(SkippedFunctionInfo::reason))
            .toList();
        List<OmittedLocation> omitted = new ArrayList<>();
        typeModel.variableStorage().variables().forEach(variable ->
            variable.locations().forEach(location -> {
                if (location.storage() instanceof UnavailableStorage unavailable) {
                    omitted.add(new OmittedLocation(variable.functionName(), variable.name(),
                        variable.kind().name(), location.start(), location.end(),
                        unavailable.reason().name(), unavailable.diagnostic()));
                }
            }));
        omitted.sort(Comparator.comparing(OmittedLocation::function)
            .thenComparing(OmittedLocation::kind)
            .thenComparing(OmittedLocation::variable)
            .thenComparingLong(OmittedLocation::startAddress)
            .thenComparingLong(OmittedLocation::endAddress)
            .thenComparing(OmittedLocation::reason));
        List<UnsupportedConstruct> unsupported = typeModel.types().nodes().stream()
            .filter(OpaqueType.class::isInstance).map(OpaqueType.class::cast)
            .map(type -> new UnsupportedConstruct("OPAQUE_TYPE", type.name(),
                type.diagnostic()))
            .sorted(Comparator.comparing(UnsupportedConstruct::kind)
                .thenComparing(UnsupportedConstruct::name)
                .thenComparing(UnsupportedConstruct::diagnostic))
            .toList();
        List<String> diagnostics = diagnosticMessages.stream().distinct().sorted().toList();
        int decompiled = Math.toIntExact(source.functions().stream()
            .filter(SyntheticSourceFile.FunctionLines::decompiled).count());
        int parameters = typeModel.functions().stream()
            .mapToInt(function -> function.parameters().size()).sum();
        int locals = typeModel.functions().stream()
            .mapToInt(function -> function.locals().size()).sum();
        int defensibleLocations = Math.toIntExact(typeModel.variableStorage().variables()
            .stream().filter(variable -> variable.hasDefensibleLocation()).count());
        Counts reportCounts = new Counts(functionCount, decompiled, failures.size(),
            skippedFunctions.size(), typeModel.functions().size(), parameters, locals,
            typeModel.globals().size(), typeModel.types().nodes().size(), defensibleLocations,
            omitted.size(), source.mappedLines().size(), unsupported.size(), diagnostics.size());
        Status reportStatus = failures.isEmpty() && skippedFunctions.isEmpty() &&
            omitted.isEmpty() && unsupported.isEmpty() && diagnostics.isEmpty()
                ? Status.SUCCESS : Status.PARTIAL;
        return new ExportReport(reportStatus,
            new TargetInfo(target.name(), target.addressBytes() * 8,
                target.littleEndian() ? "LITTLE_ENDIAN" : "BIG_ENDIAN"),
            new Artifacts(normalize(input), inputSha256, normalize(output), outputSha256,
                normalize(sourcePath), sourceSha256), reportCounts,
            sectionNames.stream().distinct().sorted().toList(), failures, skippedFunctions,
            omitted, unsupported, diagnostics, ValidationStatus.NOT_RUN,
            requireText(libdwarfVersion, "libdwarf version"), null);
    }

    public static ExportReport terminal(Status status, Throwable throwable) {
        if (status != Status.CANCELLED && status != Status.FATAL) {
            throw new IllegalArgumentException("terminal report status must be CANCELLED or FATAL");
        }
        String message = throwable.getMessage();
        if (message == null || message.isBlank()) {
            message = throwable.getClass().getName();
        }
        return new ExportReport(status, null, null, null, List.of(), List.of(), List.of(),
            List.of(), List.of(), List.of(), ValidationStatus.NOT_RUN, null,
            new Failure(throwable.getClass().getName(), message));
    }

    public Status status() {
        return status;
    }

    public String toJson() {
        StringBuilder json = new StringBuilder(1024);
        json.append('{');
        numberField(json, "schemaVersion", SCHEMA_VERSION);
        stringField(json, "status", status.name());
        json.append(",\"target\":");
        if (target == null) {
            json.append("null");
        }
        else {
            json.append('{');
            stringField(json, "architecture", target.architecture());
            numberField(json, "addressBits", target.addressBits());
            stringField(json, "byteOrder", target.byteOrder());
            json.append('}');
        }
        json.append(",\"artifacts\":");
        appendArtifacts(json);
        json.append(",\"counts\":");
        appendCounts(json);
        json.append(",\"sections\":");
        stringArray(json, sections);
        json.append(",\"failedFunctions\":");
        objectArray(json, failedFunctions, (out, function) -> {
            out.append('{');
            stringField(out, "name", function.name());
            stringField(out, "address", hex(function.address()));
            stringField(out, "diagnostic", function.diagnostic());
            out.append('}');
        });
        json.append(",\"skippedFunctions\":");
        objectArray(json, skippedFunctions, (out, function) -> {
            out.append('{');
            stringField(out, "name", function.name());
            stringField(out, "reason", function.reason());
            out.append('}');
        });
        json.append(",\"omittedLocations\":");
        objectArray(json, omittedLocations, (out, location) -> {
            out.append('{');
            stringField(out, "function", location.function());
            stringField(out, "variable", location.variable());
            stringField(out, "kind", location.kind());
            stringField(out, "startAddress", hex(location.startAddress()));
            stringField(out, "endAddress", hex(location.endAddress()));
            stringField(out, "reason", location.reason());
            stringField(out, "diagnostic", location.diagnostic());
            out.append('}');
        });
        json.append(",\"unsupportedConstructs\":");
        objectArray(json, unsupportedConstructs, (out, construct) -> {
            out.append('{');
            stringField(out, "kind", construct.kind());
            stringField(out, "name", construct.name());
            stringField(out, "diagnostic", construct.diagnostic());
            out.append('}');
        });
        json.append(",\"diagnostics\":");
        stringArray(json, diagnostics);
        json.append(",\"validation\":{");
        stringField(json, "status", validationStatus.name());
        json.append('}');
        json.append(",\"native\":{");
        nullableStringField(json, "libdwarfVersion", libdwarfVersion);
        json.append('}');
        json.append(",\"failure\":");
        if (failure == null) {
            json.append("null");
        }
        else {
            json.append('{');
            stringField(json, "type", failure.type());
            stringField(json, "message", failure.message());
            json.append('}');
        }
        return json.append('}').toString();
    }

    private void appendArtifacts(StringBuilder json) {
        if (artifacts == null) {
            json.append("null");
            return;
        }
        json.append('{');
        stringField(json, "inputPath", artifacts.inputPath());
        stringField(json, "inputSha256", artifacts.inputSha256());
        stringField(json, "outputPath", artifacts.outputPath());
        stringField(json, "outputSha256", artifacts.outputSha256());
        stringField(json, "sourcePath", artifacts.sourcePath());
        stringField(json, "sourceSha256", artifacts.sourceSha256());
        json.append('}');
    }

    private void appendCounts(StringBuilder json) {
        if (counts == null) {
            json.append("null");
            return;
        }
        json.append('{');
        numberField(json, "functionsExported", counts.functionsExported());
        numberField(json, "functionsDecompiled", counts.functionsDecompiled());
        numberField(json, "functionsFailed", counts.functionsFailed());
        numberField(json, "functionsSkipped", counts.functionsSkipped());
        numberField(json, "functionSignatures", counts.functionSignatures());
        numberField(json, "parameters", counts.parameters());
        numberField(json, "localVariables", counts.localVariables());
        numberField(json, "globalVariables", counts.globalVariables());
        numberField(json, "canonicalTypes", counts.canonicalTypes());
        numberField(json, "defensibleVariableLocations", counts.defensibleVariableLocations());
        numberField(json, "omittedLocationRanges", counts.omittedLocationRanges());
        numberField(json, "mappedSourceLines", counts.mappedSourceLines());
        numberField(json, "unsupportedConstructs", counts.unsupportedConstructs());
        numberField(json, "diagnostics", counts.diagnostics());
        json.append('}');
    }

    private static <T> void objectArray(StringBuilder json, List<T> values,
            ObjectWriter<T> writer) {
        json.append('[');
        for (int index = 0; index < values.size(); index++) {
            if (index != 0) {
                json.append(',');
            }
            writer.write(json, values.get(index));
        }
        json.append(']');
    }

    private static void stringArray(StringBuilder json, List<String> values) {
        objectArray(json, values, ExportReport::appendString);
    }

    private static void numberField(StringBuilder json, String name, long value) {
        fieldSeparator(json);
        appendString(json, name);
        json.append(':').append(value);
    }

    private static void stringField(StringBuilder json, String name, String value) {
        fieldSeparator(json);
        appendString(json, name);
        json.append(':');
        appendString(json, value);
    }

    private static void nullableStringField(StringBuilder json, String name, String value) {
        fieldSeparator(json);
        appendString(json, name);
        json.append(':');
        if (value == null) {
            json.append("null");
        }
        else {
            appendString(json, value);
        }
    }

    private static void fieldSeparator(StringBuilder json) {
        char last = json.charAt(json.length() - 1);
        if (last != '{') {
            json.append(',');
        }
    }

    private static void appendString(StringBuilder json, String value) {
        json.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"' -> json.append("\\\"");
                case '\\' -> json.append("\\\\");
                case '\b' -> json.append("\\b");
                case '\f' -> json.append("\\f");
                case '\n' -> json.append("\\n");
                case '\r' -> json.append("\\r");
                case '\t' -> json.append("\\t");
                default -> {
                    if (character < 0x20) {
                        json.append("\\u").append(String.format("%04x", (int) character));
                    }
                    else {
                        json.append(character);
                    }
                }
            }
        }
        json.append('"');
    }

    private static String hex(long value) {
        return "0x" + Long.toHexString(value);
    }

    private static String normalize(Path path) {
        return path.toAbsolutePath().normalize().toString();
    }

    private static String requireText(String value, String description) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(description + " is required");
        }
        return value;
    }

    private static void requireHash(String value, String description) {
        if (value == null || !value.matches("[0-9a-fA-F]{64}")) {
            throw new IllegalArgumentException(description + " is invalid");
        }
    }

    @FunctionalInterface
    private interface ObjectWriter<T> {
        void write(StringBuilder json, T value);
    }
}
