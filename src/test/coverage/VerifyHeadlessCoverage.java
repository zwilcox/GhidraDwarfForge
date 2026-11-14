import java.io.File;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

import org.jacoco.core.analysis.Analyzer;
import org.jacoco.core.analysis.CoverageBuilder;
import org.jacoco.core.analysis.IClassCoverage;
import org.jacoco.core.data.ExecutionData;
import org.jacoco.core.data.SessionInfo;
import org.jacoco.core.tools.ExecFileLoader;

/** Rejects empty, foreign, stale or combined execution before reporting it. */
public final class VerifyHeadlessCoverage {
    public static void main(String[] args) throws Exception {
        if (args.length != 3 && !(args.length == 4 && args[3].equals("--self-test"))) {
            throw new IllegalArgumentException("usage: <production.jar> <execution.exec> <session-id> [--self-test]");
        }
        verify(args[0], args[1], args[2]);
        if (args.length == 4) {
            reject(args, "mismatched class", loader -> {
                var data = loader.getExecutionDataStore().getContents().iterator().next();
                loader.getExecutionDataStore().put(new ExecutionData(data.getId() ^ 1,
                    data.getName(), data.getProbes().clone()));
            });
            reject(args, "unknown or mismatched class", loader ->
                loader.getExecutionDataStore().put(new ExecutionData(42, "foreign/Injected", new boolean[] {true})));
            reject(args, "combined coverage sessions", loader ->
                loader.getSessionInfoStore().visitSessionInfo(new SessionInfo("extra", 1, 2)));
            reject(args, "no production exporter execution", loader ->
                loader.getExecutionDataStore().reset());
            var wrongSession = args.clone();
            wrongSession[2] = "different-session";
            reject(wrongSession, "unexpected or combined coverage sessions", loader -> {});
            System.out.println("headless-coverage-negative-controls=PASS cases=5");
        }
    }

    private static void reject(String[] args, String expected, Consumer<ExecFileLoader> mutation)
            throws Exception {
        var loader = new ExecFileLoader();
        loader.load(new File(args[1]));
        mutation.accept(loader);
        var temporary = Files.createTempFile("coverage-control-", ".exec");
        try {
            loader.save(temporary.toFile(), false);
            try {
                verify(args[0], temporary.toString(), args[2]);
                throw new AssertionError("accepted invalid coverage: " + expected);
            }
            catch (IllegalArgumentException failure) {
                if (!failure.getMessage().contains(expected)) {
                    throw new AssertionError("wrong failure for " + expected, failure);
                }
            }
        }
        finally {
            Files.delete(temporary);
        }
    }

    private static void verify(String jar, String execution, String session) throws Exception {
        var loader = new ExecFileLoader();
        loader.load(new File(execution));
        var sessions = loader.getSessionInfoStore().getInfos();
        if (sessions.size() != 1 || !sessions.get(0).getId().equals(session)) {
            throw new IllegalArgumentException("unexpected or combined coverage sessions");
        }
        var coverage = new CoverageBuilder();
        new Analyzer(loader.getExecutionDataStore(), coverage).analyzeAll(new File(jar));
        Map<String, IClassCoverage> classes = new HashMap<>();
        for (var item : coverage.getClasses()) {
            if (!item.getName().startsWith("ghidradwarfforge/") ||
                    classes.put(item.getName(), item) != null) {
                throw new IllegalArgumentException("unexpected production class population");
            }
        }
        int executed = 0;
        for (ExecutionData data : loader.getExecutionDataStore().getContents()) {
            IClassCoverage expected = classes.get(data.getName());
            if (expected == null || expected.getId() != data.getId() || expected.isNoMatch()) {
                throw new IllegalArgumentException("unknown or mismatched class: " + data.getName());
            }
            if (data.hasHits()) {
                executed++;
            }
        }
        var exporter = classes.get("ghidradwarfforge/nativeapi/MinimalDwarfSidecarExporter");
        if (executed == 0 || exporter == null || exporter.getLineCounter().getCoveredCount() == 0) {
            throw new IllegalArgumentException("no production exporter execution measured");
        }
        System.out.printf("headless-class-identity=PASS production=%d executed=%d exporter-lines=%d%n",
            classes.size(), executed, exporter.getLineCounter().getCoveredCount());
    }
}
