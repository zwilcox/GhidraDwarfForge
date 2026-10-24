import java.awt.Component;
import java.awt.Container;
import java.awt.Dialog;
import java.awt.GraphicsEnvironment;
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.Robot;
import java.awt.Window;
import java.awt.event.InputEvent;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;

import javax.imageio.ImageIO;
import javax.swing.AbstractButton;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import generic.jar.ResourceFile;
import ghidra.GhidraApplicationLayout;
import ghidra.app.script.GhidraState;
import ghidra.app.script.ScriptControls;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.framework.Application;
import ghidra.framework.GhidraApplicationConfiguration;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Executes the real script and its real chooser in a private, non-headless Ghidra JVM. */
public final class GuiOutputFallbackSmoke {
    private static final String TITLE = "Select GhidraDwarfForge output directory";
    private static final long UI_TIMEOUT_NANOS = Duration.ofSeconds(30).toNanos();

    public static void main(String[] args) {
        try {
            run(args);
            System.exit(0);
        }
        catch (Throwable failure) {
            failure.printStackTrace();
            System.exit(1);
        }
    }

    private static void run(String[] args) throws Exception {
        if (args.length != 7) {
            throw new IllegalArgumentException(
                "expected ghidra-dir module-dir fixture consumer producer result-dir function-address");
        }
        if (GraphicsEnvironment.isHeadless()) {
            throw new AssertionError("this test requires a real X display, such as isolated Xvfb");
        }
        Path module = Path.of(args[1]);
        Path fixture = Path.of(args[2]);
        Path results = Path.of(args[5]);
        GhidraApplicationConfiguration configuration = new GhidraApplicationConfiguration();
        configuration.setShowSplashScreen(false);
        configuration.setApplicationLogFile(results.resolve("application.log").toFile());
        configuration.setScriptLogFile(results.resolve("script.log").toFile());
        Application.initializeApplication(new GhidraApplicationLayout(Path.of(args[0]).toFile()),
            configuration);

        try (var imported = ProgramLoader.builder().source(fixture.toFile()).load()) {
            Object harnessConsumer = new Object();
            Program program = imported.getPrimary().getDomainObject(harnessConsumer);
            try {
                FlatProgramAPI api = new FlatProgramAPI(program, TaskMonitor.DUMMY);
                int transaction = program.startTransaction("Analyze GUI fixture");
                try {
                    api.analyzeAll(program);
                    var address = program.getAddressFactory().getAddress(args[6]);
                    var function = program.getFunctionManager().getFunctionAt(address);
                    require(function != null, "fixture function was not recovered at " + address);
                    function.setName("gui_recovered_add", SourceType.USER_DEFINED);
                }
                finally {
                    program.endTransaction(transaction, true);
                }
                runCase(program, fixture, module, args[3], args[4], results, false);
                runCase(program, fixture, module, args[3], args[4], results, true);
            }
            finally {
                program.release(harnessConsumer);
            }
        }
        System.out.println("GUI output fallback selection and cancellation PASS");
    }

    private static void runCase(Program program, Path fixture, Path module,
            String consumer, String producer, Path results, boolean cancel) throws Exception {
        String name = cancel ? "cancel" : "select";
        Path caseDirectory = Files.createDirectory(results.resolve(name));
        Path originalDirectory = Files.createDirectory(caseDirectory.resolve("readonly"));
        Path input = Files.copy(fixture, originalDirectory.resolve("fixture"));
        Path selected = Files.createDirectory(caseDirectory.resolve("chosen"));
        String originalHash = sha256(input);
        Files.setPosixFilePermissions(originalDirectory, PosixFilePermissions.fromString("r-xr-xr-x"));
        try {
            require(!Files.isWritable(originalDirectory),
                "read-only directory is writable; run this GUI test as a non-root user");
            GhidraDwarfForge script = new GhidraDwarfForge();
            require(!script.isRunningHeadless(), "the production script must run in GUI mode");
            script.setSourceFile(new ResourceFile(module.resolve("ghidra_scripts/GhidraDwarfForge.java")
                .toFile()));
            script.setScriptArgs(new String[] {
                "--libdwarf=" + consumer, "--libdwarfp=" + producer, "--input=" + input
            });
            script.setReusePreviousChoices(false);
            StringWriter output = new StringWriter();
            PrintWriter writer = new PrintWriter(output, true);
            GhidraState state = new GhidraState(null, null, program, null, null, null);
            CompletableFuture<Void> interaction = CompletableFuture.runAsync(() -> {
                try {
                    operateChooser(selected, caseDirectory, cancel);
                }
                catch (Exception failure) {
                    throw new RuntimeException(failure);
                }
            });
            boolean cancelled = false;
            try {
                script.execute(state, new ScriptControls(writer, writer, TaskMonitor.DUMMY));
            }
            catch (CancelledException expected) {
                cancelled = true;
            }
            finally {
                writer.flush();
                Files.writeString(caseDirectory.resolve("export.log"), output.toString());
            }
            interaction.get(35, TimeUnit.SECONDS);
            require(cancelled == cancel, "unexpected script cancellation state");
            require(sha256(input).equals(originalHash), "the original ELF changed");
            require(!Files.exists(input.resolveSibling("fixture.dbg")),
                "the default read-only sidecar was published");
            require(!Files.exists(input.resolveSibling("fixture.dbg.c")),
                "the default read-only source was published");
            if (cancel) {
                require(output.toString().contains("\"status\":\"CANCELLED\""),
                    "missing cancelled export report");
                try (var entries = Files.list(selected)) {
                    require(entries.findAny().isEmpty(), "cancelled chooser left output artifacts");
                }
            }
            else {
                require(output.toString().contains("output policy: GUI fallback"),
                    "script did not report the GUI fallback");
                require(output.toString().contains("GhidraDwarfForge symbol export PASS"),
                    "script did not complete the export");
                try (var entries = Files.list(selected)) {
                    require(entries.count() == 2, "expected only the completed artifact pair");
                }
                require(Files.size(selected.resolve("fixture.dbg")) > 0, "missing DWARF sidecar");
                require(Files.size(selected.resolve("fixture.dbg.c")) > 0, "missing synthetic source");
            }
            Files.writeString(caseDirectory.resolve("result.txt"),
                "gui_mode=true\nchooser=" + name + "\ninput_sha256=" + originalHash + "\nresult=PASS\n");
        }
        finally {
            Files.setPosixFilePermissions(originalDirectory,
                PosixFilePermissions.fromString("rwxr-xr-x"));
        }
    }

    private static void operateChooser(Path selected, Path results, boolean cancel) throws Exception {
        Dialog dialog = awaitDialog();
        Robot robot = new Robot();
        robot.setAutoDelay(80);
        if (!cancel) {
            SwingUtilities.invokeAndWait(() -> {
                JTextField filename = (JTextField) find(dialog,
                    component -> component instanceof JTextField &&
                        "filenameTextField".equals(component.getName()));
                require(filename != null, "Ghidra chooser filename field is missing");
                filename.setText(selected.toString());
            });
            click(robot, dialog, "Select");
            awaitCurrentDirectory(dialog, selected);
        }
        robot.waitForIdle();
        Rectangle bounds = onSwingBounds(dialog);
        ImageIO.write(robot.createScreenCapture(bounds), "png",
            results.resolve("chooser.png").toFile());
        click(robot, dialog, cancel ? "Cancel" : "Select");
    }

    private static Dialog awaitDialog() throws Exception {
        long deadline = System.nanoTime() + UI_TIMEOUT_NANOS;
        while (System.nanoTime() < deadline) {
            AtomicReference<Dialog> result = new AtomicReference<>();
            SwingUtilities.invokeAndWait(() -> Arrays.stream(Window.getWindows())
                .filter(window -> window instanceof Dialog && window.isShowing())
                .map(window -> (Dialog) window)
                .filter(window -> TITLE.equals(window.getTitle()))
                .findFirst().ifPresent(result::set));
            if (result.get() != null) {
                return result.get();
            }
            Thread.sleep(100);
        }
        throw new AssertionError("production script did not show its output directory chooser");
    }

    private static void awaitCurrentDirectory(Dialog dialog, Path expected) throws Exception {
        long deadline = System.nanoTime() + UI_TIMEOUT_NANOS;
        while (System.nanoTime() < deadline) {
            AtomicReference<String> actual = new AtomicReference<>();
            SwingUtilities.invokeAndWait(() -> {
                JTextField path = (JTextField) find(dialog, component ->
                    component instanceof JTextField && "Path".equals(component.getName()));
                if (path != null) {
                    actual.set(path.getText());
                }
            });
            if (expected.toString().equals(actual.get())) {
                return;
            }
            Thread.sleep(100);
        }
        throw new AssertionError("chooser did not navigate to the selected directory");
    }

    private static Rectangle onSwingBounds(Component component) throws Exception {
        AtomicReference<Rectangle> result = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            Point location = component.getLocationOnScreen();
            result.set(new Rectangle(location.x, location.y,
                component.getWidth(), component.getHeight()));
        });
        return result.get();
    }

    private static void click(Robot robot, Dialog dialog, String text) throws Exception {
        AtomicReference<Component> button = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> button.set(find(dialog,
            component -> component instanceof AbstractButton candidate &&
                text.equals(candidate.getText()) && candidate.isShowing() && candidate.isEnabled())));
        require(button.get() != null, "missing enabled chooser button: " + text);
        Rectangle bounds = onSwingBounds(button.get());
        robot.mouseMove(bounds.x + bounds.width / 2, bounds.y + bounds.height / 2);
        robot.mousePress(InputEvent.BUTTON1_DOWN_MASK);
        robot.mouseRelease(InputEvent.BUTTON1_DOWN_MASK);
        robot.waitForIdle();
    }

    private static Component find(Component component, Predicate<Component> predicate) {
        if (predicate.test(component)) {
            return component;
        }
        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                Component found = find(child, predicate);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static String sha256(Path path) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
            .digest(Files.readAllBytes(path)));
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
