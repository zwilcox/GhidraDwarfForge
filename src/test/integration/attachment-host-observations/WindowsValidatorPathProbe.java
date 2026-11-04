import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** Owned, standalone Java21 observations; not attachment acceptance. */
public final class WindowsValidatorPathProbe {
    public static void main(String[] args) throws Exception {
        if (args.length == 1 && args[0].equals("--child")) {
            System.out.println("owned-child-started cwd=" + System.getProperty("user.dir"));
            return;
        }
        if (!System.getProperty("os.name").startsWith("Windows") || args.length != 1) {
            throw new IllegalArgumentException("requires Windows and a new owned result directory");
        }
        Path root = Files.createDirectory(Path.of(args[0]).toAbsolutePath());
        Path deep = root;
        while (deep.toString().length() < 310) {
            deep = Files.createDirectory(deep.resolve("owned long path é " + "x".repeat(42)));
        }
        Path java = Path.of(System.getProperty("java.home"), "bin", "java.exe");
        String classes = Path.of(System.getProperty("java.class.path")).toAbsolutePath().toString();
        var results = new ArrayList<String>();
        observe("short-cwd", root.toFile(), root, java, classes, results);
        observe("long-cwd", deep.toFile(), root, java, classes, results);
        observe("prefixed-long-cwd", new java.io.File("\\\\?\\" + deep), root, java, classes, results);
        observe("short-cwd-long-logs", root.toFile(), deep, java, classes, results);
        Files.writeString(root.resolve("result.json"), "{\"scope\":\"Windows process working-directory and Java redirection observations; not a feature pass\",\"java\":" +
            quote(System.getProperty("java.version")) + ",\"deepPathCharacters\":" + deep.toString().length() +
            ",\"cases\":[" + String.join(",", results) + "]}\n", StandardCharsets.UTF_8);
        System.out.println("windows-validator-path-observation=COMPLETE");
    }

    private static void observe(String label, java.io.File cwd, Path output, Path java, String classes,
            List<String> results) throws Exception {
        Path stdout = output.resolve(label + ".stdout");
        Path stderr = output.resolve(label + ".stderr");
        Process process = null;
        String outcome;
        try {
            process = new ProcessBuilder(java.toString(), "-cp", classes,
                WindowsValidatorPathProbe.class.getName(), "--child").directory(cwd)
                .redirectOutput(stdout.toFile()).redirectError(stderr.toFile()).start();
            process.getOutputStream().close();
            if (!process.waitFor(20, TimeUnit.SECONDS)) throw new IllegalStateException("owned child timed out");
            if (process.exitValue() != 0 || !Files.readString(stdout).contains("owned-child-started")) {
                throw new IllegalStateException("owned child did not complete; inspect logs");
            }
            outcome = "started-and-exited";
        }
        catch (java.io.IOException failure) {
            if (label.equals("short-cwd")) throw failure;
            outcome = failure.toString();
        }
        finally {
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
                if (!process.waitFor(5, TimeUnit.SECONDS)) throw new IllegalStateException("owned child survived cleanup");
            }
        }
        results.add("{\"case\":" + quote(label) + ",\"cwd\":" + quote(cwd.toString()) +
            ",\"cwdCharacters\":" + cwd.toString().length() + ",\"outcome\":" + quote(outcome) + "}");
    }

    private static String quote(String value) {
        var out = new StringBuilder("\"");
        for (char character : value.toCharArray()) {
            if (character == '\\' || character == '"') out.append('\\').append(character);
            else if (character < 32) out.append(String.format("\\u%04x", (int) character));
            else out.append(character);
        }
        return out.append('"').toString();
    }
}
