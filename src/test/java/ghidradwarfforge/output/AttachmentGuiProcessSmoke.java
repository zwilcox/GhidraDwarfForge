package ghidradwarfforge.output;

import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

/** Real child processes prove cooperative stop/draining; no OS authorization or attachment claim. */
public final class AttachmentGuiProcessSmoke {
    public static void main(String[] args) throws Exception {
        if (args.length != 0) {
            Path control = Path.of(args[1]);
            Path receipt = Path.of(args[2]);
            // More than an OS pipe buffer on both streams exposes deadlocks.
            System.out.print("x".repeat(128 * 1024));
            System.err.print("y".repeat(128 * 1024));
            Files.writeString(receipt.resolveSibling("ready"), "ready");
            long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(15);
            while (Files.size(control) == 0) {
                if (System.nanoTime() >= deadline) throw new AssertionError("cooperative cancellation did not arrive");
                Thread.sleep(10);
            }
            Thread.sleep(150); // Model cleanup that must finish after cancellation.
            Files.writeString(receipt, "cleanup-completed");
            System.out.print("\nSAFE_STOP\n");
            return;
        }
        Path root = Files.createTempDirectory("forge-gui-process-λ ");
        Path control = root.resolve("cancel");
        Path receipt = root.resolve("receipt");
        boolean windows = System.getProperty("os.name").startsWith("Windows");
        Path java = Path.of(System.getProperty("java.home"), "bin", windows ? "java.exe" : "java");
        var command = new ArrayList<>(List.of(java.toString(), "-cp", System.getProperty("java.class.path"),
            AttachmentGuiProcessSmoke.class.getName(), "child", control.toString(), receipt.toString()));
        try (var channel = FileChannel.open(control, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            var result = AttachmentGui.process(command, () -> Files.exists(root.resolve("ready")), channel, false);
            require(result.exitCode() == 0 && result.cancellationRequested(), "child was killed or cancellation lost");
            require(Files.readString(receipt).equals("cleanup-completed"), "returned before safe cleanup");
            require(result.output().endsWith("SAFE_STOP\n") && result.output().length() > 128 * 1024 &&
                result.errors().length() == 128 * 1024, "child output was lost or pipe blocked");
        }
        finally {
            for (String name : List.of("cancel", "receipt", "ready")) Files.deleteIfExists(root.resolve(name));
            Files.delete(root);
        }
        System.out.println("attachment-gui-process=PASS cooperative-stop=true drained-both-streams=true native-execution=false");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
