import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.zip.ZipFile;
import org.jacoco.core.analysis.Analyzer;
import org.jacoco.core.analysis.CoverageBuilder;
import org.jacoco.core.analysis.IClassCoverage;
import org.jacoco.core.data.ExecutionData;
import org.jacoco.core.data.ExecutionDataStore;
import org.jacoco.core.instr.Instrumenter;
import org.jacoco.core.tools.ExecFileLoader;
import org.jacoco.report.DirectorySourceFileLocator;
import org.jacoco.report.xml.XMLFormatter;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;

/** Verify exact bytecode and probe identities, then OR probes with independent layer stores. */
public final class ReportCombinedCoverage {
    private record Identity(long id, int probes) { }
    private static final Set<String> LAYERS = Set.of("javaexec", "headless", "native-java", "windows");

    public static void main(String[] args) throws Exception {
        if (args.length != 5) {
            throw new IllegalArgumentException(
                "usage: production.jar test-classes.jar sessions.tsv source-directory output-directory");
        }
        var production = identities(new File(args[0]), true);
        var tests = identities(new File(args[1]), false);
        if (tests.keySet().stream().anyMatch(production::containsKey)) {
            throw new IllegalArgumentException("test and production class populations overlap");
        }
        var combined = new ExecFileLoader();
        var layers = new TreeMap<String, ExecFileLoader>();
        var seenSessions = new HashSet<String>();
        var seenPaths = new HashSet<Path>();
        long totalBytes = 0;
        if (Files.size(Path.of(args[2])) > 8 * 1024 * 1024) {
            throw new IllegalArgumentException("excessive coverage session manifest");
        }
        for (String row : Files.readAllLines(Path.of(args[2]))) {
            String[] fields = row.split("\t", -1);
            if (fields.length != 3 || !LAYERS.contains(fields[0])) {
                throw new IllegalArgumentException("invalid coverage session manifest row");
            }
            String layer = fields[0], session = fields[1];
            String prefix = layer.equals("javaexec") ? "forge-javaexec-" : "forge-integration-";
            Path path = Path.of(fields[2]);
            if (!session.matches(prefix + "[0-9a-f]{32}") || !seenSessions.add(session)
                    || seenSessions.size() > 8192 || Files.isSymbolicLink(path)
                    || !Files.isRegularFile(path) || !seenPaths.add(path.toRealPath())) {
                throw new IllegalArgumentException("invalid, linked or duplicate coverage session");
            }
            long size = Files.size(path);
            totalBytes = Math.addExact(totalBytes, size);
            if (size <= 0 || size > 16 * 1024 * 1024 || totalBytes > 256 * 1024 * 1024) {
                throw new IllegalArgumentException("excessive or empty coverage execution data");
            }
            var loader = new ExecFileLoader();
            loader.load(path.toFile());
            var sessions = loader.getSessionInfoStore().getInfos();
            if (sessions.size() != 1 || !sessions.getFirst().getId().equals(session)) {
                throw new IllegalArgumentException("unexpected or combined coverage sessions");
            }
            var separate = layers.computeIfAbsent(layer, unused -> new ExecFileLoader());
            for (ExecutionData data : loader.getExecutionDataStore().getContents()) {
                Identity identity = production.get(data.getName());
                boolean testOnly = false;
                if (identity == null && layer.equals("javaexec")) {
                    identity = tests.get(data.getName());
                    testOnly = identity != null;
                }
                if (identity == null || identity.id() != data.getId()) {
                    throw new IllegalArgumentException("unknown or mismatched class: " + data.getName());
                }
                if (identity.probes() != data.getProbes().length) {
                    throw new IllegalArgumentException("wrong probe count: " + data.getName());
                }
                if (!testOnly) {
                    // ExecutionDataStore merges into its retained mutable arrays.
                    // Separate copies prevent combined hits leaking into a layer.
                    addCopy(combined, data);
                    addCopy(separate, data);
                }
            }
            combined.getSessionInfoStore().visitSessionInfo(sessions.getFirst());
            separate.getSessionInfoStore().visitSessionInfo(sessions.getFirst());
        }
        if (seenSessions.isEmpty()) throw new IllegalArgumentException("no coverage sessions");
        Path output = Files.createDirectory(Path.of(args[4]));
        for (var layer : layers.entrySet()) {
            write(args[0], args[3], output.resolve(layer.getKey() + ".xml"), layer.getKey(), layer.getValue());
        }
        write(args[0], args[3], output.resolve("combined.xml"), "combined", combined);
        System.out.printf("combined-coverage=PASS production-classes=%d test-classes=%d sessions=%d layers=%s%n",
            production.size(), tests.size(), seenSessions.size(), layers.keySet());
    }

    private static void addCopy(ExecFileLoader target, ExecutionData data) {
        target.getExecutionDataStore().put(new ExecutionData(data.getId(), data.getName(), data.getProbes().clone()));
    }

    private static Map<String, Identity> identities(File jar, boolean production) throws Exception {
        var population = new CoverageBuilder();
        new Analyzer(new ExecutionDataStore(), population).analyzeAll(jar);
        Map<String, IClassCoverage> classes = new HashMap<>();
        for (var item : population.getClasses()) {
            if ((production && !item.getName().startsWith("ghidradwarfforge/"))
                    || classes.put(item.getName(), item) != null) {
                throw new IllegalArgumentException("unexpected class population");
            }
        }
        if (classes.isEmpty()) throw new IllegalArgumentException("empty class population");
        var counts = new HashMap<String, Integer>();
        // JaCoCo itself determines probe layouts from these exact class bytes.
        // Instrumented bytes are discarded and are never executed or packaged.
        var instrumenter = new Instrumenter((id, name, count, visitor) -> {
            var expected = classes.get(name);
            if (expected == null || expected.getId() != id) {
                throw new IllegalArgumentException("inconsistent class identity during instrumentation");
            }
            var prior = counts.putIfAbsent(name, count);
            if (prior != null && prior != count) throw new IllegalArgumentException("inconsistent probe layout");
            visitor.visitInsn(Opcodes.ACONST_NULL);
            return 1;
        });
        long bytes = 0;
        var names = new HashSet<String>();
        try (var archive = new ZipFile(jar)) {
            for (var entry : archive.stream().filter(item -> item.getName().endsWith(".class")).toList()) {
                if (!names.add(entry.getName()) || entry.getSize() <= 0
                        || (bytes = Math.addExact(bytes, entry.getSize())) > 64 * 1024 * 1024) {
                    throw new IllegalArgumentException("duplicate or excessive class bytes");
                }
                try (var stream = archive.getInputStream(entry)) {
                    byte[] content = stream.readAllBytes();
                    if (!(new ClassReader(content).getClassName() + ".class").equals(entry.getName())) {
                        throw new IllegalArgumentException("class name differs from JAR member");
                    }
                    instrumenter.instrument(content, entry.getName());
                }
            }
        }
        if (names.size() != classes.size()) {
            throw new IllegalArgumentException("analyzed class population differs from JAR population");
        }
        var identities = new HashMap<String, Identity>();
        classes.forEach((name, value) -> identities.put(name, new Identity(value.getId(), counts.getOrDefault(name, 0))));
        return identities;
    }

    private static void write(String jar, String source, Path output, String layer, ExecFileLoader data)
            throws Exception {
        var coverage = new CoverageBuilder();
        new Analyzer(data.getExecutionDataStore(), coverage).analyzeAll(new File(jar));
        for (var item : coverage.getClasses()) {
            if (item.isNoMatch()) throw new IllegalArgumentException("mismatched production bytecode");
        }
        var bundle = coverage.getBundle(layer);
        if (bundle.getLineCounter().getCoveredCount() == 0) {
            throw new IllegalArgumentException("no production execution measured for " + layer);
        }
        try (var stream = Files.newOutputStream(output)) {
            var visitor = new XMLFormatter().createVisitor(stream);
            visitor.visitInfo(data.getSessionInfoStore().getInfos(), data.getExecutionDataStore().getContents());
            visitor.visitBundle(bundle, new DirectorySourceFileLocator(new File(source), "UTF-8", 4));
            visitor.visitEnd();
        }
    }
}
