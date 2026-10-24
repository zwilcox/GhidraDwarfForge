package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.GsonBuilder;
import com.google.gson.stream.JsonReader;

import ghidradwarfforge.elf.DebuglinkCandidateContent;
import ghidradwarfforge.elf.ElfBuildId;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.elf.ExecutableProgramBytes;
import ghidradwarfforge.elf.MatchedElfAllocations;
import ghidradwarfforge.elf.MatchedElfPrefix;
import ghidradwarfforge.elf.OwnedDebuglinkCandidate;
import ghidradwarfforge.nativeapi.DwarfTarget;

/** Fixture-only connected preparation; observations do not approve attachment. */
public final class ReportedCandidatePreparationProbe {
    private ReportedCandidatePreparationProbe() {
    }

    public static void main(String[] arguments) throws Exception {
        boolean rejected = arguments.length > 0 && arguments[0].equals("--expect-rejection");
        int start = rejected ? 1 : 0;
        if (arguments.length - start != 6) {
            throw new IllegalArgumentException(
                "supply report original sidecar source basename-base64 workspace-parent");
        }
        origin("binding", ExportArtifactHashBinding.class);
        origin("claims", ExportReportClaims.class);
        origin("digests", FileDigests.class);
        origin("prefix", MatchedElfPrefix.class);
        origin("allocations", MatchedElfAllocations.class);
        origin("build-id", ElfBuildId.class);
        origin("elf", ElfImage.class);
        origin("target", DwarfTarget.class);
        origin("owned-candidate", OwnedDebuglinkCandidate.class);
        origin("candidate-content", DebuglinkCandidateContent.class);
        origin("program-bytes", ExecutableProgramBytes.class);
        origin("gson", JsonReader.class);
        System.out.println("java-version=" + System.getProperty("java.version"));
        System.out.println("max-heap=" + Runtime.getRuntime().maxMemory());
        var observations = new LinkedHashMap<String, Object>();
        try {
            prepare(Path.of(arguments[start]), Path.of(arguments[start + 1]),
                Path.of(arguments[start + 2]), Path.of(arguments[start + 3]),
                Base64.getDecoder().decode(arguments[start + 4]),
                Path.of(arguments[start + 5]), observations);
            if (rejected) {
                throw new AssertionError("expected I/O rejection returned observations");
            }
        }
        catch (IOException failure) {
            if (!rejected) {
                throw failure;
            }
            if (failure.getMessage() == null || failure.getMessage().isBlank()) {
                throw new AssertionError("rejection has no diagnostic", failure);
            }
            observations.put("failure", Map.of("exception", failure.getClass().getName(),
                "diagnostic", failure.getMessage(), "terminalStatus",
                failure instanceof ExportReportClaims.TerminalReportException terminal
                    ? terminal.status().name() : "-", "suppressed",
                List.of(failure.getSuppressed()).stream().map(value ->
                    Map.of("exception", value.getClass().getName(),
                        "diagnostic", String.valueOf(value.getMessage()))).toList()));
            var construction = new LinkedHashMap<String, Object>();
            if (observations.get("construction") instanceof Map<?, ?> previous) {
                previous.forEach((key, value) -> construction.put((String) key, value));
                if (construction.get("action").equals("STARTED")) {
                    construction.put("action", "FAILED");
                }
            }
            else {
                construction.put("action", "NOT_CREATED");
            }
            construction.put("reasons", List.of("IO_FAILURE"));
            observations.put("construction", construction);
        }
        String json = new GsonBuilder().serializeNulls().create().toJson(observations);
        System.out.println("preparation-base64=" + Base64.getEncoder().encodeToString(
            json.getBytes(StandardCharsets.UTF_8)));
    }

    private static void prepare(Path report, Path original, Path sidecar, Path source,
            byte[] basename, Path parent, Map<String, Object> observations) throws IOException {
        var detailed = ExportArtifactHashBinding.observeDetailed(report, original, sidecar, source);
        var binding = detailed.binding();
        observations.put("binding", Map.of("claims", binding.claims(),
            "original", artifact(binding.original()), "sidecar", artifact(binding.sidecar()),
            "source", artifact(binding.source())));
        observations.put("inventories", inventories(detailed.inventories()));
        var reasons = new ArrayList<String>();
        for (var role : List.of(Map.entry("original", binding.original()),
                Map.entry("sidecar", binding.sidecar()), Map.entry("source", binding.source()))) {
            if (role.getValue().agreement() != ExportArtifactHashBinding.Agreement.MATCHING_REPORTED_SHA256) {
                reasons.add(role.getKey() + ":DIFFERENT_REPORTED_SHA256");
            }
        }
        if (!reasons.isEmpty()) {
            observations.put("construction", Map.of("action", "NOT_CREATED", "reasons", reasons));
            return;
        }

        var prefix = MatchedElfPrefix.compare(original, sidecar);
        var prefixFields = new LinkedHashMap<String, Object>();
        prefixFields.put("status", prefix.status().name());
        prefixFields.put("originalByteCount", prefix.originalByteCount());
        prefixFields.put("candidateByteCount", prefix.candidateByteCount());
        prefixFields.put("comparedExtent", prefix.comparedExtent());
        prefixFields.put("firstDifferentOffset", prefix.firstDifferentOffset().isPresent()
            ? prefix.firstDifferentOffset().getAsLong() : null);
        prefixFields.put("diagnostic", prefix.diagnostic());
        observations.put("prefix", prefixFields);
        if (prefix.status() != MatchedElfPrefix.Status.MATCHING_COPIED_PREFIX) {
            reasons.add("prefix:" + prefix.status().name());
        }

        var allocations = MatchedElfAllocations.compare(original, sidecar);
        var allocationFields = new LinkedHashMap<String, Object>();
        allocationFields.put("status", allocations.status().name());
        allocationFields.put("issue", allocations.issue().orElse(null));
        allocationFields.put("diagnostic", allocations.diagnostic());
        observations.put("allocations", allocationFields);
        if (allocations.status() != MatchedElfAllocations.Status.MATCHING_ALLOCATED_METADATA) {
            reasons.add("allocations:" + allocations.status().name());
        }

        var originalId = ElfBuildId.read(original);
        var sidecarId = ElfBuildId.read(sidecar);
        var relationship = ElfBuildId.compare(originalId, sidecarId);
        observations.put("buildIds", Map.of("original", buildId(originalId),
            "sidecar", buildId(sidecarId), "relationship", relationship.name()));
        if (relationship != ElfBuildId.Relationship.SAME_BUILD_ID &&
                relationship != ElfBuildId.Relationship.ABSENT_BOTH) {
            reasons.add("buildIds:" + relationship.name());
        }

        var targetFields = new LinkedHashMap<String, Object>();
        targetFields.put("reported", binding.claims().target());
        ElfImage image = ElfImage.read(original);
        try {
            var target = DwarfTarget.fromElf(image);
            var observed = new ExportReport.TargetInfo(target.name(), target.addressBytes() * 8,
                image.byteOrder().toString());
            boolean matching = observed.equals(binding.claims().target());
            targetFields.put("observed", observed);
            targetFields.put("status", matching ? "MATCHING_REPORTED_TARGET" : "DIFFERENT_REPORTED_TARGET");
            if (!matching) {
                reasons.add("target:DIFFERENT_REPORTED_TARGET");
            }
        }
        catch (IllegalArgumentException unsupported) {
            targetFields.put("status", "UNSUPPORTED_TARGET");
            targetFields.put("diagnostic", unsupported.getMessage());
            reasons.add("target:UNSUPPORTED_TARGET");
        }
        observations.put("target", targetFields);
        if (!reasons.isEmpty()) {
            observations.put("construction", Map.of("action", "NOT_CREATED", "reasons", reasons));
            return;
        }

        observations.put("construction", Map.of("action", "STARTED"));
        var created = OwnedDebuglinkCandidate.create(original, sidecar, basename, parent);
        var content = created.content();
        var construction = new LinkedHashMap<String, Object>();
        construction.put("action", "CREATED");
        construction.put("directory", created.directory().toString());
        construction.put("candidate", created.candidate().toString());
        construction.put("content", Map.of(
            "program_bytes", Map.of("status", content.programBytes().status().name()),
            "allocated_sections", Map.of("status", content.allocatedSections().status().name()),
            "new_debuglink", Map.of("status", content.newDebuglink().status().name()),
            "sidecar_digest", content.sidecarDigest()));
        observations.put("construction", construction);
        if (!content.sidecarDigest().equals(binding.sidecar().observed())) {
            IOException changed = new IOException("selected sidecar digest changed during preparation");
            construction.put("action", "CREATED_THEN_REJECTED");
            var cleanupObservations = new ArrayList<Map<String, Object>>();
            construction.put("cleanup", cleanupObservations);
            for (Path owned : List.of(created.candidate(), created.directory())) {
                try {
                    Files.delete(owned);
                    cleanupObservations.add(Map.of("path", owned.toString(), "deleted", true));
                }
                catch (IOException cleanup) {
                    changed.addSuppressed(cleanup);
                    cleanupObservations.add(Map.of("path", owned.toString(), "deleted", false,
                        "exception", cleanup.getClass().getName(),
                        "diagnostic", String.valueOf(cleanup.getMessage())));
                }
            }
            throw changed;
        }
    }

    private static Map<String, Object> artifact(ExportArtifactHashBinding.Artifact artifact) {
        return Map.of("selectedPath", artifact.selectedPath().toString(),
            "observed", artifact.observed(), "agreement", artifact.agreement().name());
    }

    private static Map<String, Object> inventories(ExportReportClaims.Inventories inventories) {
        return Map.of("failedFunctions", inventories.failedFunctions().stream().map(value ->
                Map.of("name", value.name(), "address", hex(value.address()),
                    "diagnostic", value.diagnostic())).toList(),
            "skippedFunctions", inventories.skippedFunctions(),
            "omittedLocations", inventories.omittedLocations().stream().map(value ->
                Map.of("function", value.function(), "variable", value.variable(), "kind", value.kind(),
                    "startAddress", hex(value.startAddress()), "endAddress", hex(value.endAddress()),
                    "reason", value.reason(), "diagnostic", value.diagnostic())).toList(),
            "unsupportedConstructs", inventories.unsupportedConstructs(),
            "diagnostics", inventories.diagnostics());
    }

    private static Map<String, Object> buildId(ElfBuildId.Observation observation) {
        var fields = new LinkedHashMap<String, Object>();
        fields.put("hex", observation.hex().orElse(null));
        fields.put("occurrences", observation.occurrences());
        return fields;
    }

    private static String hex(long address) {
        return "0x" + Long.toHexString(address);
    }

    private static void origin(String label, Class<?> type) throws Exception {
        System.out.println(label + "-class-source=" + type.getProtectionDomain()
            .getCodeSource().getLocation().toURI());
    }
}
