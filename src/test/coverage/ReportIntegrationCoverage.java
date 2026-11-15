import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import org.jacoco.core.analysis.Analyzer;
import org.jacoco.core.analysis.CoverageBuilder;
import org.jacoco.core.analysis.IClassCoverage;
import org.jacoco.core.data.ExecutionData;
import org.jacoco.core.tools.ExecFileLoader;
import org.jacoco.report.DirectorySourceFileLocator;
import org.jacoco.report.xml.XMLFormatter;

/** Verify every execution identity before OR-merging probes within one named layer. */
public final class ReportIntegrationCoverage {
    public static void main(String[] args) throws Exception {
        if (args.length != 5) {
            throw new IllegalArgumentException("usage: production.jar sessions.txt source-directory output.xml layer");
        }
        var population = new CoverageBuilder();
        new Analyzer(new org.jacoco.core.data.ExecutionDataStore(), population).analyzeAll(new File(args[0]));
        Map<String, IClassCoverage> classes = new HashMap<>();
        for (var item : population.getClasses()) {
            if (!item.getName().startsWith("ghidradwarfforge/") || classes.put(item.getName(), item) != null) {
                throw new IllegalArgumentException("unexpected production class population");
            }
        }
        if (classes.isEmpty()) throw new IllegalArgumentException("empty production class population");
        var combined = new ExecFileLoader();
        var seen = new HashSet<String>();
        for (String line : Files.readAllLines(Path.of(args[1]))) {
            Path path = Path.of(line);
            String session = path.getFileName().toString().replaceFirst("\\.exec$", "");
            if (!session.matches("forge-integration-[0-9a-f]{32}") || !seen.add(session)) {
                throw new IllegalArgumentException("invalid or duplicate integration session");
            }
            var loader = new ExecFileLoader();
            loader.load(path.toFile());
            var sessions = loader.getSessionInfoStore().getInfos();
            if (sessions.size() != 1 || !sessions.getFirst().getId().equals(session)) {
                throw new IllegalArgumentException("unexpected or combined coverage sessions");
            }
            for (ExecutionData data : loader.getExecutionDataStore().getContents()) {
                var expected = classes.get(data.getName());
                if (expected == null || expected.getId() != data.getId()) {
                    throw new IllegalArgumentException("unknown or mismatched class: " + data.getName());
                }
                combined.getExecutionDataStore().put(data);
            }
            combined.getSessionInfoStore().visitSessionInfo(sessions.getFirst());
        }
        if (seen.isEmpty()) throw new IllegalArgumentException("no integration sessions");
        var coverage = new CoverageBuilder();
        new Analyzer(combined.getExecutionDataStore(), coverage).analyzeAll(new File(args[0]));
        for (var item : coverage.getClasses()) {
            if (item.isNoMatch()) throw new IllegalArgumentException("mismatched production class: " + item.getName());
        }
        var bundle = coverage.getBundle("integration-" + args[4]);
        if (bundle.getLineCounter().getCoveredCount() == 0) {
            throw new IllegalArgumentException("no production execution measured");
        }
        try (var stream = Files.newOutputStream(Path.of(args[3]))) {
            var visitor = new XMLFormatter().createVisitor(stream);
            visitor.visitInfo(combined.getSessionInfoStore().getInfos(), combined.getExecutionDataStore().getContents());
            visitor.visitBundle(bundle, new DirectorySourceFileLocator(new File(args[2]), "UTF-8", 4));
            visitor.visitEnd();
        }
        System.out.printf("integration-coverage=PASS layer=%s classes=%d sessions=%d lines=%d/%d branches=%d/%d%n",
            args[4], classes.size(), seen.size(), bundle.getLineCounter().getCoveredCount(),
            bundle.getLineCounter().getTotalCount(), bundle.getBranchCounter().getCoveredCount(),
            bundle.getBranchCounter().getTotalCount());
    }
}
