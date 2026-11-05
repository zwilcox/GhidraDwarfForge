import java.awt.Component;
import java.awt.GraphicsEnvironment;
import java.awt.Rectangle;
import java.awt.Robot;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import javax.swing.JTable;

import docking.ComponentProvider;
import docking.widgets.table.AbstractSortedTableModel;
import docking.widgets.table.GTable;
import docking.widgets.table.GTableFilterPanel;
import docking.widgets.table.RowObjectTableModel;
import docking.widgets.tree.GTree;
import ghidra.GhidraApplicationLayout;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.services.ConsoleService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.GhidraApplicationConfiguration;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.SwingUpdateManager;

/** Uses the installed Script Manager table and Run task, not direct script construction. */
public final class GuiScriptManagerSmoke {
    private static final String PREFLIGHT = "GhidraDwarfForge.java";
    private static final boolean WITH_COMPRESSION = "1".equals(System.getenv("GHIDRA_GUI_COMPRESSION"));
    private static final String EXPORT = WITH_COMPRESSION ? "ExportCompressedGhidraDwarfForge.java" :
        "ExportGhidraDwarfForge.java";
    private static final String LOADER_EXPORT = "ExportGhidraDwarfForgeWithGdbLoader.java";
    private static final String ATTACH = "AttachGhidraDwarfForge.java";
    private static final String RECOVER = "RecoverGhidraDwarfForgeAttachment.java";
    private static final String PREPARE = "ExportAndAttachGhidraDwarfForge.java";
    private static final boolean WITH_LOADER = "1".equals(System.getenv("GHIDRA_GUI_GDB_LOADER"));
    private static final boolean WINDOWS = System.getProperty("os.name").startsWith("Windows");

    private static final class ProbeFrontEnd extends FrontEndTool {
        ProbeFrontEnd(ProjectManager manager) {
            super(manager);
        }

        @Override
        protected void shutdown() {
            // The harness owns the process exit status and project cleanup.
        }
    }

    private static final class ProbeTool extends PluginTool {
        ProbeTool(Project project) {
            super(project, "GhidraDwarfForge Script Manager validation", true, true, false);
        }

        void disposeForTest() {
            super.dispose();
        }
    }

    public static void main(String[] arguments) {
        try {
            run(arguments);
            System.exit(0);
        }
        catch (Throwable failure) {
            failure.printStackTrace();
            System.exit(1);
        }
    }

    private static void run(String[] arguments) throws Exception {
        GuiTestSupport.require(arguments.length == 5,
            "expected ghidra-dir module-dir fixture result-dir function-address");
        GuiTestSupport.require(!GraphicsEnvironment.isHeadless(), "a real desktop is required");
        GuiTestSupport.require(!(WITH_COMPRESSION && WITH_LOADER), "select one GUI shortcut per journey");
        Path ghidra = Path.of(arguments[0]);
        Path module = Path.of(arguments[1]);
        Path fixture = Path.of(arguments[2]);
        Path results = Path.of(arguments[3]);
        GuiTableClickSmoke.run(Files.createDirectory(results.resolve("filter-focus-control")));
        GhidraApplicationConfiguration configuration = new GhidraApplicationConfiguration();
        configuration.setShowSplashScreen(false);
        configuration.setApplicationLogFile(results.resolve("application.log").toFile());
        configuration.setScriptLogFile(results.resolve("script.log").toFile());
        Application.initializeApplication(new GhidraApplicationLayout(ghidra.toFile()), configuration);
        GuiFileChooserSmoke.run(Files.createDirectory(results.resolve("file-chooser-control")));
        GuiTaskCancellation.verifyLauncherCancellation(results.resolve("task-launcher-cancellation"));
        GuiTableClickSmoke.runPendingFilter(
            Files.createDirectory(results.resolve("pending-filter-control")));

        Path projectDirectory = Files.createDirectory(results.resolve("project"));
        GhidraProject project = GhidraProject.createProject(projectDirectory.toString(),
            "ScriptManagerProbe", true);
        ProbeFrontEnd frontEnd = GuiTestSupport.onSwing(() -> {
            ProbeFrontEnd result = new ProbeFrontEnd(project.getProjectManager());
            result.setActiveProject(project.getProject());
            result.setVisible(true);
            return result;
        });
        try {
            ProbeTool tool = GuiTestSupport.onSwing(() -> {
                ProbeTool result = new ProbeTool(project.getProject());
                try {
                    result.addPlugins(java.util.List.of(
                        "ghidra.app.plugin.core.progmgr.ProgramManagerPlugin",
                        "ghidra.app.plugin.core.script.GhidraScriptMgrPlugin"
                    ));
                }
                catch (Exception failure) {
                    throw new RuntimeException(failure);
                }
                result.getToolFrame().setSize(1100, 800);
                result.setVisible(true);
                return result;
            });
            try {
                for (String script : new String[] { PREFLIGHT, EXPORT, LOADER_EXPORT, ATTACH, RECOVER, PREPARE }) {
                    var found = GhidraScriptUtil.findScriptByName(script);
                    GuiTestSupport.require(found != null, "installed script was not discovered: " + script);
                    GuiTestSupport.require(found.getFile(false).toPath().toRealPath().equals(
                        module.resolve("ghidra_scripts").resolve(script).toRealPath()),
                        "Script Manager discovered a different source: " + found);
                }
                for (boolean cancel : new boolean[] { false, true }) {
                    runCase(tool, fixture, results, arguments[4], cancel);
                }
            }
            finally {
                GuiTestSupport.onSwing(() -> { tool.disposeForTest(); return null; });
            }
        }
        finally {
            GuiTestSupport.onSwing(() -> { frontEnd.dispose(); return null; });
            project.close();
        }
        Files.writeString(results.resolve("result.txt"),
            "installed-script-discovery=PASS\nnative-free-preflight-run=PASS\n" +
            "script-manager-export-selection=PASS\nscript-manager-export-cancellation=PASS\n" +
            "console-report-presentation=PASS\noriginal-input-preservation=PASS\n");
        System.out.println("gui-script-manager=PASS");
    }

    private static void runCase(ProbeTool tool, Path fixture, Path results,
            String functionAddress, boolean cancel) throws Exception {
        Path caseDirectory = Files.createDirectory(results.resolve(cancel ? "cancel" : "select"));
        Path restricted = Files.createDirectory(caseDirectory.resolve("readonly"));
        Path input = Files.copy(fixture, restricted.resolve("fixture"));
        Path chosen = Files.createDirectory(caseDirectory.resolve("chosen"));
        String originalHash = GuiTestSupport.sha256(input);
        ProgramManager manager = tool.getService(ProgramManager.class);
        ConsoleService console = tool.getService(ConsoleService.class);
        GuiTestSupport.require(manager != null && console != null, "missing real tool services");
        try (var imported = ProgramLoader.builder().source(input.toFile()).load()) {
            Object owner = new Object();
            Program program = imported.getPrimary().getDomainObject(owner);
            try {
                int transaction = program.startTransaction("Analyze GUI fixture");
                try {
                    new FlatProgramAPI(program, TaskMonitor.DUMMY).analyzeAll(program);
                    var address = program.getAddressFactory().getAddress(functionAddress);
                    var function = program.getFunctionManager().getFunctionAt(address);
                    GuiTestSupport.require(function != null, "missing fixture function at " + address);
                    function.setName("gui_recovered_add", SourceType.USER_DEFINED);
                }
                finally {
                    program.endTransaction(transaction, true);
                }
                GuiTestSupport.onSwing(() -> { manager.openProgram(program); return null; });
                try (var permissions = new GuiTestSupport.ReadOnlyDirectory(restricted,
                        caseDirectory.resolve("permissions.txt"))) {
                    clearConsole(console);
                    launchFromTable(tool, PREFLIGHT, caseDirectory.resolve("preflight-manager.png"));
                    awaitConsole(console, "Symbol export was not requested.");
                    awaitConsole(console, "Finished!");
                    String preflight = consoleText(console);
                    GuiTestSupport.require(!preflight.contains("native policy:"),
                        "native-free preflight loaded the native producer");
                    Files.writeString(caseDirectory.resolve("preflight-console.txt"), preflight);
                    clearConsole(console);
                    CompletableFuture<Void> interaction = CompletableFuture.runAsync(() -> {
                        try {
                            GuiTestSupport.operateChooser(chosen, caseDirectory, cancel);
                        }
                        catch (Exception failure) {
                            throw new RuntimeException(failure);
                        }
                    });
                    launchFromTable(tool, WITH_LOADER ? LOADER_EXPORT : EXPORT,
                        caseDirectory.resolve("export-manager.png"));
                    interaction.get(100, TimeUnit.SECONDS);
                    awaitConsole(console, "GhidraDwarfForge report: ");
                    awaitConsole(console, cancel ? "User cancelled script." : "Finished!");
                    String transcript = consoleText(console);
                    Files.writeString(caseDirectory.resolve("export-console.txt"), transcript);
                    GuiTestSupport.require(transcript.contains("native policy: verified packaged libraries"),
                        "GUI export did not verify the installed native pair");
                    GuiTestSupport.require(transcript.contains(cancel ? "\"status\":\"CANCELLED\"" :
                        "GhidraDwarfForge symbol export PASS"), "missing expected GUI export result");
                    GuiTestSupport.require(!transcript.contains("\"status\":\"FATAL\""),
                        "GUI export reported fatal failure");
                    GuiTestSupport.require(originalHash.equals(GuiTestSupport.sha256(input)),
                        "original ELF changed");
                    GuiTestSupport.require(!Files.exists(restricted.resolve("fixture.dbg")) &&
                        !Files.exists(restricted.resolve("fixture.dbg.c")) &&
                        !Files.exists(restricted.resolve("fixture.dbg.gdb.py")),
                        "output was published in the restricted original directory");
                    try (var entries = Files.list(chosen)) {
                        GuiTestSupport.require(entries.count() == (cancel ? 0 : WITH_LOADER ? 3 : 2),
                            "wrong artifact count or staging files left behind");
                    }
                    if (!cancel) {
                        GuiTestSupport.require(transcript.contains("output policy: GUI fallback"),
                            "export did not use the selected output directory");
                        GuiTestSupport.require(Files.size(chosen.resolve("fixture.dbg")) > 0 &&
                            Files.size(chosen.resolve("fixture.dbg.c")) > 0,
                            "completed GUI artifact pair is missing");
                        if (WITH_LOADER) {
                            GuiTestSupport.require(Files.size(chosen.resolve("fixture.dbg.gdb.py")) > 0,
                                "completed GUI companion is missing");
                            GuiTestSupport.require(transcript.contains("GDB companion"),
                                "GUI console does not identify the companion");
                        }
                        runAttachmentDecline(tool, input, chosen.resolve("fixture.dbg"),
                            chosen.resolve("fixture.dbg.c"), caseDirectory, saveCoverageReport(caseDirectory));
                        runPreparationDecline(tool, input, caseDirectory);
                        if ("1".equals(System.getenv("GHIDRA_GUI_NATIVE_ATTACHMENT"))) {
                            runNativeAttachment(tool, program, input, caseDirectory, functionAddress);
                        }
                    }
                    ComponentProvider provider = tool.getComponentProvider("Console");
                    GuiTestSupport.onSwing(() -> {
                        tool.showComponentProvider(provider, true);
                        return null;
                    });
                    GuiTestSupport.screenshot(new Robot(), provider.getComponent(),
                        caseDirectory.resolve("console.png"));
                    Files.writeString(caseDirectory.resolve("result.txt"),
                        "script-manager-action=double-click\nchooser=" + (cancel ? "cancel" : "select") +
                        "\ngdb-loader=" + WITH_LOADER +
                        "\ncompression=" + WITH_COMPRESSION +
                        "\ninput_sha256=" + originalHash + "\nresult=PASS\n");
                }
                catch (Exception | Error failure) {
                    try {
                        Files.writeString(caseDirectory.resolve("failure-console.txt"),
                            consoleText(console));
                        GuiTestSupport.captureDesktop(caseDirectory);
                    }
                    catch (Exception diagnosticFailure) {
                        failure.addSuppressed(diagnosticFailure);
                    }
                    throw failure;
                }
                finally {
                    GuiTestSupport.onSwing(() -> { manager.closeProgram(program, true); return null; });
                }
            }
            finally {
                program.release(owner);
            }
        }
    }

    private static Path saveCoverageReport(Path directory) throws Exception {
        var dialog = GuiTestSupport.dialog(ghidradwarfforge.output.CoverageReportGui.TITLE);
        var robot = new Robot();
        GuiTestSupport.onSwing(() -> {
            var table = (javax.swing.JTable) GuiTestSupport.find(dialog,
                component -> "coverage-functions".equals(component.getName()));
            var summary = (javax.swing.JTextArea) GuiTestSupport.find(dialog,
                component -> "coverage-summary".equals(component.getName()));
            var details = (javax.swing.JTextArea) GuiTestSupport.find(dialog,
                component -> "coverage-details".equals(component.getName()));
            GuiTestSupport.require(table != null && table.getRowCount() > 0 && table.getColumnCount() == 8,
                "missing per-function coverage table");
            GuiTestSupport.require(summary.getText().contains("not execution coverage") &&
                summary.getText().contains("unknown scopes excluded"), "coverage summary hides metric limits");
            table.setRowSelectionInterval(0, 0);
            GuiTestSupport.require(details.getText().contains("Signature provenance:"), "missing function evidence");
            return null;
        });
        GuiTestSupport.foregroundWindow(((javax.swing.JDialog) dialog).getRootPane());
        requireCoverageOnScreen(dialog);
        GuiTestSupport.screenshot(robot, dialog, directory.resolve("coverage.png"));
        Path report = directory.resolve("coverage-report.json").toAbsolutePath();
        GuiTestSupport.clickButton(robot, dialog, "Save report...");
        var chooser = GuiTestSupport.dialog("Save coverage report");
        GuiTestSupport.onSwing(() -> {
            var filename = (javax.swing.JTextField) GuiTestSupport.find(chooser, component ->
                component instanceof javax.swing.JTextField && "filenameTextField".equals(component.getName()));
            GuiTestSupport.require(filename != null, "missing report filename field");
            filename.setText(report.toString());
            return null;
        });
        GuiTestSupport.clickButton(robot, chooser, "Save");
        GuiTestSupport.await("complete report save", () -> {
            var status = (javax.swing.JTextArea) GuiTestSupport.find(dialog,
                component -> "coverage-save-status".equals(component.getName()));
            GuiTestSupport.require(!status.getText().startsWith("Report save failed:"), status.getText());
            return status.getText().startsWith("Report saved:") ? Boolean.TRUE : null;
        });
        var retained = ghidradwarfforge.output.ExportReportClaims.readWithCoverage(report, () -> false);
        GuiTestSupport.require(retained.claims().schemaVersion() == 2 && retained.coverage() != null,
            "saved report lost schema-two coverage");
        GuiTestSupport.onSwing(() -> {
            var table = (javax.swing.JTable) GuiTestSupport.find(dialog,
                component -> "coverage-functions".equals(component.getName()));
            GuiTestSupport.require(table.getRowCount() == retained.coverage().coverage().functions().size(),
                "saved and displayed function populations differ");
            return null;
        });
        compareCoverageReports(dialog, robot, directory, report);
        GuiTestSupport.clickButton(robot, dialog, "Close");
        return report;
    }

    private static void compareCoverageReports(java.awt.Dialog dialog, Robot robot, Path directory, Path report) throws Exception {
        String original = Files.readString(report);
        chooseCoverageComparison(dialog, robot, report);
        checkCoverageComparison(robot, directory.resolve("comparison-identical.txt"), "Reported changes: 0", "does not prove declaration lineage");
        var changed = com.google.gson.JsonParser.parseString(original).getAsJsonObject();
        var first = changed.getAsJsonObject("coverage").getAsJsonArray("functions").get(0).getAsJsonObject();
        first.addProperty("name", first.get("name").getAsString() + " previous λ");
        Path previous = Files.writeString(directory.resolve("coverage-earlier.json"), changed.toString());
        chooseCoverageComparison(dialog, robot, previous);
        checkCoverageComparison(robot, directory.resolve("comparison-changed.txt"), "FUNCTION_RENAMED", "previous λ");
        var legacy = com.google.gson.JsonParser.parseString(original).getAsJsonObject();
        legacy.addProperty("schemaVersion", 1);
        legacy.remove("coverage");
        Path legacyFile = Files.writeString(directory.resolve("coverage-legacy.json"), legacy.toString());
        chooseCoverageComparison(dialog, robot, legacyFile);
        checkCoverageComparison(robot, directory.resolve("comparison-incomparable.txt"), "INCOMPARABLE", "Coverage unavailable");
        Path malformed = Files.writeString(directory.resolve("coverage-malformed.json"), "{");
        chooseCoverageComparison(dialog, robot, malformed);
        GuiTestSupport.await("malformed comparison error", () -> {
            var status = (javax.swing.JTextArea) GuiTestSupport.find(dialog,
                component -> "coverage-save-status".equals(component.getName()));
            return status.getText().startsWith("Comparison failed:") ? Boolean.TRUE : null;
        });
        chooseCoverageComparison(dialog, robot, report);
        checkCoverageComparison(robot, directory.resolve("comparison-retry.txt"), "Reported changes: 0", "No differences in the compared evidence fields");
        GuiTestSupport.require(Files.readString(report).equals(original) && Files.readString(previous).equals(changed.toString()) &&
            Files.readString(legacyFile).equals(legacy.toString()) && Files.readString(malformed).equals("{"), "GUI comparison modified selected reports");
        Files.writeString(directory.resolve("comparison-result.txt"), "gui-comparison=PASS identical/changed/incomparable/malformed/retry/read-only\n");
    }

    private static void chooseCoverageComparison(java.awt.Dialog dialog, Robot robot, Path earlier) throws Exception {
        GuiTestSupport.foregroundWindow(((javax.swing.JDialog) dialog).getRootPane());
        GuiTestSupport.clickButton(robot, dialog, "Compare report...");
        var chooser = GuiTestSupport.dialog("Select earlier coverage report");
        GuiTestSupport.onSwing(() -> {
            var filename = (javax.swing.JTextField) GuiTestSupport.find(chooser, component ->
                component instanceof javax.swing.JTextField && "filenameTextField".equals(component.getName()));
            GuiTestSupport.require(filename != null, "missing earlier report filename field");
            filename.setText(earlier.toAbsolutePath().toString());
            return null;
        });
        GuiTestSupport.clickButton(robot, chooser, "Compare");
    }

    private static void checkCoverageComparison(Robot robot, Path result, String required, String detail) throws Exception {
        var dialog = GuiTestSupport.dialog(ghidradwarfforge.output.CoverageReportGui.COMPARISON_TITLE);
        String text = GuiTestSupport.onSwing(() -> {
            var area = (javax.swing.JTextArea) GuiTestSupport.find(dialog,
                component -> "coverage-comparison-result".equals(component.getName()));
            GuiTestSupport.require(area != null && !area.isEditable(), "missing read-only comparison results");
            GuiTestSupport.require(area.getText().contains(required) && area.getText().contains(detail), "comparison content mismatch: " + area.getText());
            return area.getText();
        });
        Files.writeString(result, text);
        GuiTestSupport.foregroundWindow(((javax.swing.JDialog) dialog).getRootPane());
        requireCoverageOnScreen(dialog);
        GuiTestSupport.screenshot(robot, dialog, Path.of(result + ".png"));
        GuiTestSupport.clickButton(robot, dialog, "Close comparison");
    }

    private static void requireCoverageOnScreen(java.awt.Dialog dialog) throws Exception {
        GuiTestSupport.onSwing(() -> {
            var configuration = dialog.getGraphicsConfiguration();
            var usable = new java.awt.Rectangle(configuration.getBounds());
            var insets = java.awt.Toolkit.getDefaultToolkit().getScreenInsets(configuration);
            usable.x += insets.left;
            usable.y += insets.top;
            usable.width -= insets.left + insets.right;
            usable.height -= insets.top + insets.bottom;
            GuiTestSupport.require(usable.contains(dialog.getBounds()),
                "coverage window exceeds usable desktop: " + dialog.getBounds() + " / " + usable);
            return null;
        });
    }

    private static void runAttachmentDecline(ProbeTool tool, Path input, Path sidecar, Path source,
            Path caseDirectory, Path savedReport) throws Exception {
        Path work = Files.createDirectory(caseDirectory.resolve("attachment-decline"));
        // The export fallback fixture deliberately separates the pair from its
        // read-only target directory. Attachment discovery requires neighbors;
        // use owned copies for this read-only preview/decline control.
        Path target = Files.copy(input, work.resolve("fixture"));
        Path pair = Files.copy(sidecar, work.resolve("fixture.dbg"));
        Path synthetic = Files.copy(source, work.resolve("fixture.dbg.c"));
        Path exportReport = Files.copy(savedReport, work.resolve("export.json"));
        var reported = ghidradwarfforge.output.ExportReportClaims.read(exportReport).artifacts();
        GuiTestSupport.require(reported.inputSha256().equals(GuiTestSupport.sha256(input)) &&
            reported.outputSha256().equals(GuiTestSupport.sha256(sidecar)) &&
            reported.sourceSha256().equals(GuiTestSupport.sha256(source)),
            "saved coverage report does not describe the exported generation");
        var tools = new java.util.HashMap<String, Path>();
        for (String role : java.util.List.of("helper", "readelf", "llvm", "strict", "configuration")) {
            tools.put(role, Files.writeString(work.resolve(role), "not executed in declined GUI operation"));
        }
        var operation = new ghidradwarfforge.output.AttachmentOperation.Request(target, pair, synthetic,
            exportReport, work.resolve("original.backup"), work.resolve("validation.json"), work.resolve("receipt.json"),
            work.resolve("recovery.json"), work.resolve("restore"), null);
        var invocation = new ghidradwarfforge.output.AttachmentInvocation(operation, tools, work.resolve("saved-recovery.json"));
        Path request = Files.writeString(work.resolve("request λ.json"), invocation.toJson());
        var before = new java.util.HashMap<Path, String>();
        for (Path path : java.util.List.of(input, sidecar, source, target, pair, synthetic, exportReport, request)) {
            before.put(path, GuiTestSupport.sha256(path));
        }
        ConsoleService console = tool.getService(ConsoleService.class);
        clearConsole(console);
        var interaction = CompletableFuture.runAsync(() -> {
            try {
                GuiTestSupport.selectFile("Select attachment or refresh request", request);
                Robot robot = new Robot();
                robot.setAutoDelay(80);
                javax.swing.JDialog review = GuiTestSupport.await("attachment review", () ->
                    java.util.Arrays.stream(java.awt.Window.getWindows())
                        .filter(window -> window instanceof javax.swing.JDialog && window.isShowing())
                        .map(window -> (javax.swing.JDialog) window)
                        .filter(window -> window.getTitle().equals("Review GhidraDwarfForge target change"))
                        .findFirst().orElse(null));
                GuiTestSupport.onSwing(() -> {
                    GuiTestSupport.require(review.getRootPane().getDefaultButton().getText().equals("Cancel"),
                        "target modification is the default action");
                    var text = (javax.swing.JTextArea) GuiTestSupport.find(review, component -> component instanceof javax.swing.JTextArea);
                    GuiTestSupport.require(text != null && text.getText().contains(target.toString()) &&
                        text.getText().contains("Original backup:") && text.getText().contains("Receipt:"), "preview omitted selected artifacts");
                    return null;
                });
                GuiTestSupport.foregroundWindow(review.getRootPane());
                GuiTestSupport.screenshot(robot, review, work.resolve("review.png"));
                robot.keyPress(java.awt.event.KeyEvent.VK_ENTER);
                robot.keyRelease(java.awt.event.KeyEvent.VK_ENTER);
            }
            catch (Exception failure) { throw new RuntimeException(failure); }
        });
        launchFromTable(tool, ATTACH, work.resolve("script-manager.png"));
        interaction.get(100, TimeUnit.SECONDS);
        awaitConsole(console, "attachment declined; modifying helper was not started.");
        awaitConsole(console, "Finished!");
        String transcript = consoleText(console);
        Files.writeString(work.resolve("console.txt"), transcript);
        GuiTestSupport.require(transcript.contains("\"outcome\":\"PREVIEW\"") && !transcript.contains("Starting explicit target change"),
            "GUI decline did not follow read-only helper preview");
        clearConsole(console);
        var authorizationDecline = CompletableFuture.runAsync(() -> {
            try {
                GuiTestSupport.selectFile("Select attachment or refresh request", request);
                GuiTestSupport.clickButton(new Robot(), GuiTestSupport.dialog("Review GhidraDwarfForge target change"),
                    "Attach selected sidecar");
                var authorization = GuiTestSupport.dialog("Attachment helper authorization");
                GuiTestSupport.onSwing(() -> {
                    var choices = (javax.swing.JComboBox<?>) GuiTestSupport.find(authorization,
                        component -> component instanceof javax.swing.JComboBox<?>);
                    GuiTestSupport.require(choices != null && "Cancel".equals(choices.getSelectedItem()),
                        "authorization defaults to starting the helper");
                    return null;
                });
                GuiTestSupport.screenshot(new Robot(), authorization, work.resolve("authorization-decline.png"));
                GuiTestSupport.clickButton(new Robot(), authorization, "OK");
            }
            catch (Exception failure) { throw new RuntimeException(failure); }
        });
        launchFromTable(tool, ATTACH, work.resolve("authorization-manager.png"));
        authorizationDecline.get(100, TimeUnit.SECONDS);
        awaitConsole(console, "attachment declined; modifying helper was not started.");
        awaitConsole(console, "Finished!");
        String authorizationTranscript = consoleText(console);
        Files.writeString(work.resolve("authorization-console.txt"), authorizationTranscript);
        GuiTestSupport.require(authorizationTranscript.contains("\"outcome\":\"PREVIEW\"") &&
            !authorizationTranscript.contains("Starting explicit target change"), "declined authorization started modifying helper");
        for (var entry : before.entrySet()) {
            GuiTestSupport.require(entry.getValue().equals(GuiTestSupport.sha256(entry.getKey())), "GUI decline changed selected input");
        }
        for (String name : java.util.List.of("original.backup", "validation.json", "receipt.json", "recovery.json", "restore", "saved-recovery.json")) {
            GuiTestSupport.require(!Files.exists(work.resolve(name)), "declined GUI operation created " + name);
        }
        Files.writeString(work.resolve("result.txt"), "packaged-helper-preview=PASS\ndefault-enter-declines=PASS\n" +
            "separate-authorization-default-decline=PASS\nselected-inputs-unchanged=PASS\nno-transaction-outputs=PASS\n");
    }

    private static void runPreparationDecline(ProbeTool tool, Path input, Path caseDirectory) throws Exception {
        Path work = Files.createDirectory(caseDirectory.resolve("attachment-prepare"));
        Path target = Files.copy(input, work.resolve("fixture"));
        Path records = Files.createDirectory(work.resolve("records"));
        var selectedTools = new java.util.HashMap<String, Path>();
        for (String role : java.util.List.of("readelf", "llvm", "strict", "configuration")) {
            selectedTools.put(role, Files.writeString(work.resolve(role), "not executed until attachment consent"));
        }
        String before = GuiTestSupport.sha256(target);
        ConsoleService console = tool.getService(ConsoleService.class);
        clearConsole(console);
        var interaction = CompletableFuture.runAsync(() -> {
            try {
                GuiTestSupport.choose("Prepare sidecar attachment", "Initial attachment");
                GuiTestSupport.selectFile("Select executable to attach", target);
                GuiTestSupport.enterText("Fresh sidecar filename", "prepared.dbg");
                GuiTestSupport.operateChooser(records, work, false, "Select directory for attachment records and backups");
                GuiTestSupport.selectFile("Select GNU readelf executable", selectedTools.get("readelf"));
                GuiTestSupport.selectFile("Select llvm-dwarfdump executable", selectedTools.get("llvm"));
                GuiTestSupport.selectFile("Select pinned libdwarf 2.3.2 raw checker executable", selectedTools.get("strict"));
                GuiTestSupport.selectFile("Select pinned dwarfdump configuration", selectedTools.get("configuration"));
                var export = GuiTestSupport.dialog("Export and prepare attachment");
                GuiTestSupport.clickButton(new Robot(), export, "Yes");
                var review = (javax.swing.JDialog) GuiTestSupport.dialog("Review GhidraDwarfForge target change");
                GuiTestSupport.onSwing(() -> {
                    GuiTestSupport.require(review.getRootPane().getDefaultButton().getText().equals("Cancel"),
                        "prepared export silently enabled attachment");
                    return null;
                });
                Robot robot = new Robot();
                GuiTestSupport.foregroundWindow(review.getRootPane());
                GuiTestSupport.screenshot(robot, review, work.resolve("prepared-review.png"));
                robot.keyPress(java.awt.event.KeyEvent.VK_ENTER);
                robot.keyRelease(java.awt.event.KeyEvent.VK_ENTER);
            }
            catch (Exception failure) { throw new RuntimeException(failure); }
        });
        launchFromTable(tool, PREPARE, work.resolve("script-manager.png"));
        interaction.get(130, TimeUnit.SECONDS);
        awaitConsole(console, "attachment declined; modifying helper was not started.");
        awaitConsole(console, "Finished!");
        String transcript = consoleText(console);
        Files.writeString(work.resolve("console.txt"), transcript);
        GuiTestSupport.require(transcript.contains("Prepared attachment request:") &&
            transcript.contains("GhidraDwarfForge symbol export PASS") && !transcript.contains("Starting explicit target change"),
            "prepared request did not follow a real completed export and separate decline");
        Path directory;
        try (var children = Files.list(records)) {
            var found = children.toList();
            GuiTestSupport.require(found.size() == 1, "wrong preparation directory count");
            directory = found.getFirst();
        }
        var request = ghidradwarfforge.output.AttachmentInvocation.read(directory.resolve("request.json"), () -> false);
        request.preflight(directory.resolve("request.json")).recheck();
        var binding = ghidradwarfforge.output.ExportArtifactHashBinding.observe(request.operation().exportReport(),
            target, request.operation().sidecar(), request.operation().source());
        var reported = ghidradwarfforge.output.ExportReportClaims.readWithCoverage(
            request.operation().exportReport(), () -> false);
        GuiTestSupport.require(reported.claims().schemaVersion() == 2 && reported.coverage() != null &&
            reported.claims().counts().functionsExported() == reported.coverage().coverage().functions().size(),
            "prepared GUI generation did not retain its schema-two coverage report");
        for (var artifact : java.util.List.of(binding.original(), binding.sidecar(), binding.source())) {
            GuiTestSupport.require(artifact.agreement() == ghidradwarfforge.output.ExportArtifactHashBinding.Agreement.MATCHING_REPORTED_SHA256,
                "captured report differs from actual exported bytes");
        }
        GuiTestSupport.require(before.equals(GuiTestSupport.sha256(target)) && before.equals(GuiTestSupport.sha256(input)),
            "preparation/decline changed executable bytes");
        try (var files = Files.list(directory)) {
            GuiTestSupport.require(files.map(path -> path.getFileName().toString()).sorted().toList()
                .equals(java.util.List.of("export.json", "request.json")), "declined preparation started transaction or left stages");
        }
        Files.writeString(work.resolve("result.txt"), "real-curated-export=PASS\ncaptured-report-bound-to-files=PASS\ncoverage-report-retained=PASS\nseparate-default-decline=PASS\noriginal-unchanged=PASS\nno-transaction-outputs=PASS\n");
    }

    private static void runNativeAttachment(ProbeTool tool, Program program, Path input,
            Path caseDirectory, String functionAddress) throws Exception {
        GuiTestSupport.require(WINDOWS || System.getProperty("os.name").equals("Linux"), "unsupported GUI fixture host");
        if (!WINDOWS) {
            GuiTestSupport.require(!Files.readString(Path.of("/proc/self/status")).lines()
                .filter(line -> line.startsWith("Uid:")).findFirst().orElseThrow().split("\\s+")[1].equals("0"),
                "Ghidra must run unprivileged during the authorization journey");
        }
        Path work = Files.createDirectory(caseDirectory.resolve("attachment-native"));
        Path target = Files.copy(input, work.resolve("fixture"));
        String original = GuiTestSupport.sha256(input);
        Path first = prepareAndAttach(tool, target, work, null, "initial.dbg");
        var initial = ghidradwarfforge.output.AttachmentInvocation.read(first.resolve("request.json"), () -> false);
        String firstTarget = GuiTestSupport.sha256(target);
        GuiTestSupport.require(!firstTarget.equals(original) &&
            GuiTestSupport.sha256(initial.operation().originalBackup()).equals(original), "initial attachment/backup bytes differ");
        GuiTestSupport.require(!Files.isSameFile(target, initial.operation().originalBackup()), "backup is not independent");
        Files.copy(target, work.resolve("initial-target"), java.nio.file.StandardCopyOption.COPY_ATTRIBUTES);
        var retained = new java.util.LinkedHashMap<Path, String>();
        for (Path path : java.util.List.of(initial.operation().sidecar(), initial.operation().source(),
                initial.operation().originalBackup(), initial.operation().receipt())) {
            retained.put(path, GuiTestSupport.sha256(path));
        }
        runActiveAttachmentCancellation(tool, input, work, initial);
        int transaction = program.startTransaction("Curate GUI attachment refresh");
        try {
            program.getFunctionManager().getFunctionAt(program.getAddressFactory().getAddress(functionAddress))
                .setName("gui_refreshed_add", SourceType.USER_DEFINED);
        }
        finally { program.endTransaction(transaction, true); }
        Path second = prepareAndAttach(tool, target, work, first, "refreshed.dbg");
        var refresh = ghidradwarfforge.output.AttachmentInvocation.read(second.resolve("request.json"), () -> false);
        GuiTestSupport.require(!GuiTestSupport.sha256(target).equals(firstTarget) &&
            GuiTestSupport.sha256(refresh.operation().refresh().priorTargetBackup()).equals(firstTarget),
            "refresh did not retain the previous target");
        GuiTestSupport.require(!GuiTestSupport.sha256(refresh.operation().sidecar()).equals(
            retained.get(initial.operation().sidecar())), "analyst change did not reach refreshed sidecar");
        Files.copy(target, work.resolve("refreshed-target"), java.nio.file.StandardCopyOption.COPY_ATTRIBUTES);
        ConsoleService console = tool.getService(ConsoleService.class);
        clearConsole(console);
        var interaction = CompletableFuture.runAsync(() -> {
            try {
                GuiTestSupport.selectFile("Select saved attachment recovery request", refresh.recoveryInvocation());
                confirmNativeChange(work.resolve("recovery-review.png"), true, target,
                    "Recovery receipt", refresh.operation().recoveryReceipt());
            }
            catch (Exception failure) { throw new RuntimeException(failure); }
        });
        launchFromTable(tool, RECOVER, work.resolve("recovery-manager.png"));
        interaction.get(180, TimeUnit.SECONDS);
        awaitNativeCompletion(console, work.resolve("recovery-console.txt"), "ROLLED_BACK");
        requireNativeReceipt(refresh.operation().recoveryReceipt(), "ROLLED_BACK");
        GuiTestSupport.require(GuiTestSupport.sha256(target).equals(firstTarget), "GUI recovery did not restore prior generation");
        GuiTestSupport.require(Files.isRegularFile(refresh.operation().recoveryReceipt()), "durable recovery receipt missing");
        for (var retainedFile : retained.entrySet()) {
            GuiTestSupport.require(GuiTestSupport.sha256(retainedFile.getKey()).equals(retainedFile.getValue()),
                "refresh/recovery changed retained original generation");
        }
        GuiTestSupport.require(GuiTestSupport.sha256(input).equals(original), "GUI attachment changed source fixture");
        Files.writeString(work.resolve("generations.txt"), first + "\n" + second + "\n");
        Files.writeString(work.resolve("result.txt"), (WINDOWS ?
            "windows-existing-runner-token=true\ninteractive-standard-user-uac=NOT_PROVEN\n" : "unprivileged-ghidra=PASS\n") +
            "explicit-os-authorization=PASS\n" +
            "gui-initial-attachment=PASS\ngui-curated-refresh=PASS\ngui-saved-recovery=PASS\nretained-generations=PASS\n");
    }

    private static void runActiveAttachmentCancellation(ProbeTool tool, Path input, Path work,
            ghidradwarfforge.output.AttachmentInvocation initial) throws Exception {
        Path directory = Files.createDirectory(work.resolve("cancel-active"));
        Path target = Files.copy(input, work.resolve("cancel-target"));
        Path validator = Files.copy(Path.of(System.getenv("FORGE_GUI_CANCEL_VALIDATOR")),
            directory.resolve(WINDOWS ? "pending-validator.exe" : "pending-validator"),
            java.nio.file.StandardCopyOption.COPY_ATTRIBUTES);
        Path marker = Path.of(validator + ".started");
        var tools = new java.util.LinkedHashMap<>(initial.validatorTools());
        tools.put("readelf", validator);
        var request = new ghidradwarfforge.output.AttachmentOperation.Request(target, initial.operation().sidecar(),
            initial.operation().source(), initial.operation().exportReport(), directory.resolve("original.backup"),
            directory.resolve("validation.json"), directory.resolve("receipt.json"), directory.resolve("recovery.json"),
            directory.resolve("restore.elf"), null);
        Path saved = directory.resolve("saved-recovery.json");
        var invocation = new ghidradwarfforge.output.AttachmentInvocation(request, tools, saved);
        Path selection = Files.writeString(directory.resolve("request.json"), invocation.toJson());
        var protectedFiles = new java.util.LinkedHashMap<Path, String>();
        for (Path path : java.util.List.of(target, request.sidecar(), request.source(), request.exportReport(), selection, validator)) {
            protectedFiles.put(path, GuiTestSupport.sha256(path));
        }
        ConsoleService console = tool.getService(ConsoleService.class);
        clearConsole(console);
        var interaction = CompletableFuture.runAsync(() -> {
            try {
                GuiTestSupport.selectFile("Select attachment or refresh request", selection);
                confirmNativeChange(directory.resolve("review.png"), false, target, "Sidecar", request.sidecar());
                GuiTestSupport.await("native validator started before cancellation", () ->
                    Files.isRegularFile(marker) ? marker : null);
                GuiTaskCancellation.cancelLaunchedTask(new Robot(), ATTACH, "Attaching sidecar; Cancel requests safe rollback",
                    directory.resolve("active-task.png"));
            }
            catch (Exception failure) { throw new RuntimeException(failure); }
        });
        launchFromTable(tool, ATTACH, directory.resolve("manager.png"));
        interaction.get(180, TimeUnit.SECONDS);
        awaitConsole(console, "User cancelled script.");
        String transcript = consoleText(console);
        Files.writeString(directory.resolve("console.txt"), transcript);
        GuiTestSupport.require(transcript.contains("Attachment helper exit=130; cancellation requested=true"),
            "GUI did not wait for the modifying helper's cancellation outcome");
        long pid = Long.parseLong(Files.readString(marker).strip());
        GuiTestSupport.require(ProcessHandle.of(pid).map(process -> !process.isAlive()).orElse(true),
            "cancelled validator process survived helper completion");
        for (var entry : protectedFiles.entrySet()) {
            GuiTestSupport.require(GuiTestSupport.sha256(entry.getKey()).equals(entry.getValue()),
                "cancelled validation changed selected file: " + entry.getKey());
        }
        for (Path absent : java.util.List.of(request.originalBackup(), request.receipt(), request.validationEvidence(),
                request.recoveryReceipt(), request.restoreImage(), saved)) {
            GuiTestSupport.require(!Files.exists(absent), "cancelled validation published transaction output: " + absent);
        }
        Files.writeString(directory.resolve("result.txt"),
            "native-validator-started=PASS\nreal-task-cancel-button=PASS\nhelper-exit=130\nvalidator-process-gone=PASS\n" +
            "selected-files-unchanged=PASS\ntransaction-outputs-absent=PASS\n");
    }

    private static Path prepareAndAttach(ProbeTool tool, Path target, Path work,
            Path previous, String basename) throws Exception {
        Path records = Files.createDirectory(work.resolve(basename + "-records"));
        ConsoleService console = tool.getService(ConsoleService.class);
        clearConsole(console);
        var interaction = CompletableFuture.runAsync(() -> {
            try {
                GuiTestSupport.choose("Prepare sidecar attachment", previous == null ?
                    "Initial attachment" : "Refresh existing attachment");
                GuiTestSupport.selectFile("Select executable to attach", target);
                if (previous != null) {
                    var prior = ghidradwarfforge.output.AttachmentInvocation.read(previous.resolve("request.json"), () -> false);
                    GuiTestSupport.selectFile("Select retained original executable backup", prior.operation().originalBackup());
                    GuiTestSupport.selectFile("Select previous committed receipt", prior.operation().receipt());
                    GuiTestSupport.selectFile("Select previous sidecar to retain", prior.operation().sidecar());
                    GuiTestSupport.selectFile("Select previous synthetic source to retain", prior.operation().source());
                }
                GuiTestSupport.enterText("Fresh sidecar filename", basename);
                GuiTestSupport.operateChooser(records, work, false, "Select directory for attachment records and backups");
                GuiTestSupport.selectFile("Select GNU readelf executable", Path.of(System.getenv("FORGE_GUI_READELF")));
                GuiTestSupport.selectFile("Select llvm-dwarfdump executable", Path.of(System.getenv("FORGE_GUI_LLVM")));
                GuiTestSupport.selectFile("Select pinned libdwarf 2.3.2 raw checker executable", Path.of(System.getenv("FORGE_GUI_STRICT")));
                GuiTestSupport.selectFile("Select pinned dwarfdump configuration", Path.of(System.getenv("FORGE_GUI_CONFIGURATION")));
                GuiTestSupport.clickButton(new Robot(), GuiTestSupport.dialog("Export and prepare attachment"), "Yes");
                confirmNativeChange(work.resolve(basename + "-review.png"), false, target,
                    "Sidecar", target.toRealPath().resolveSibling(basename));
            }
            catch (Exception failure) { throw new RuntimeException(failure); }
        });
        launchFromTable(tool, PREPARE, work.resolve(basename + "-manager.png"));
        interaction.get(180, TimeUnit.SECONDS);
        awaitNativeCompletion(console, work.resolve(basename + "-console.txt"), "COMMITTED");
        try (var children = Files.list(records)) {
            var directories = children.toList();
            GuiTestSupport.require(directories.size() == 1, "wrong native preparation directory count");
            requireNativeReceipt(directories.getFirst().resolve("receipt.json"), "COMMITTED");
            return directories.getFirst();
        }
    }

    private static void confirmNativeChange(Path screenshot, boolean recovery, Path target,
            String selectedRole, Path selectedPath) throws Exception {
        var review = GuiTestSupport.dialog("Review GhidraDwarfForge target change");
        GuiTestSupport.onSwing(() -> {
            var text = (javax.swing.JTextArea) GuiTestSupport.find(review,
                component -> component instanceof javax.swing.JTextArea);
            GuiTestSupport.require(text != null &&
                text.getText().contains("Executable:\n" + target + "\n\n") &&
                text.getText().contains(selectedRole + ":\n" + selectedPath + "\n\n"),
                "target-change review does not describe the intended " + target + " and " + selectedPath);
            return null;
        });
        GuiTestSupport.screenshot(new Robot(), review, screenshot);
        GuiTestSupport.clickButton(new Robot(), review, recovery ? "Restore selected image" : "Attach selected sidecar");
        GuiTestSupport.choose("Attachment helper authorization", "Request OS authorization");
        if (WINDOWS) GuiTestSupport.selectFile("Select PowerShell 7 executable", Path.of(System.getenv("FORGE_GUI_POWERSHELL")));
    }

    private static void requireNativeReceipt(Path receipt, String phase) throws Exception {
        var record = com.google.gson.JsonParser.parseString(Files.readString(receipt)).getAsJsonObject();
        GuiTestSupport.require(record.get("phase").getAsString().equals(phase) &&
            record.get("hostContract").getAsString().equals(WINDOWS ?
                "windows-x64-local-ntfs-raw-security-v1" : "linux-x64-ext4-protected-metadata-v1"),
            "native GUI receipt phase or host differs");
    }

    private static void awaitNativeCompletion(ConsoleService console, Path log, String outcome) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(180);
        while (System.nanoTime() < deadline) {
            String text = consoleText(console);
            Files.writeString(log, text);
            if (text.contains("Finished!") || text.contains("Error running script")) {
                // RunAs cannot redirect the elevated console. The caller also
                // checks the selected durable receipt, never just the exit code.
                GuiTestSupport.require(text.contains(WINDOWS ? "\"launcherExitCode\":0" : "\"outcome\":\"" + outcome + "\"") &&
                    text.contains("Attachment helper exit=0"), "native GUI operation failed; inspect " + log);
                return;
            }
            Thread.sleep(100);
        }
        throw new AssertionError("timed out waiting for native GUI helper; inspect " + log);
    }

    private static void launchFromTable(ProbeTool tool, String filename, Path screenshot)
            throws Exception {
        ComponentProvider provider = tool.getComponentProvider("Script Manager");
        GuiTestSupport.require(provider != null, "real Script Manager provider is missing");
        GuiTestSupport.onSwing(() -> { tool.showComponentProvider(provider, true); return null; });
        JTable table = GuiTestSupport.await("installed Script Manager row " + filename, () -> {
            Component found = GuiTestSupport.find(provider.getComponent(), component -> {
                if (!(component instanceof JTable candidate) || !candidate.isShowing()) {
                    return false;
                }
                return findRow(candidate, filename) >= 0;
            });
            return (JTable) found;
        });
        Robot robot = new Robot();
        robot.setAutoDelay(80);
        // A visible floating provider can still be covered by Console/front end.
        // Provider activation intentionally focuses Ghidra's filter field.
        // Mouse dispatch needs the foreground window, not table keyboard focus.
        GuiTestSupport.foregroundWindow(table);
        GuiTestSupport.require(table instanceof GTable, "Script Manager no longer uses GTable");
        GTable scriptTable = (GTable) table;
        Object scriptList = readField(provider, "scriptList");
        SwingUpdateManager refresh = (SwingUpdateManager) readField(
            scriptList, "refreshUpdateManager");
        GTree categories = (GTree) readField(provider, "scriptCategoryTree");
        SwingUpdateManager treeFilter = (SwingUpdateManager) readField(
            categories, GTree.class, "filterUpdateManager");
        GuiTestSupport.await("Script Manager refresh, categories, filter and sort completion", () ->
            Boolean.TRUE.equals(readField(provider, "hasBeenRefreshed")) &&
                !refresh.isBusy() && !categories.isBusy() && !treeFilter.isBusy() &&
                isTableReady(scriptTable) ?
                    scriptTable : null);
        awaitTableReady(scriptTable);
        GuiTestSupport.onSwing(() -> {
            int index = findRow(table, filename);
            GuiTestSupport.require(index >= 0, "Script Manager target row disappeared");
            table.setRowSelectionInterval(index, index);
            table.scrollRectToVisible(table.getCellRect(index, findNameColumn(table), true));
            return null;
        });
        robot.waitForIdle();
        GuiTestSupport.screenshot(robot, provider.getComponent(), screenshot);
        int[] cell = GuiTestSupport.onSwing(() -> {
            int index = findRow(table, filename);
            GuiTestSupport.require(index >= 0 && !refresh.isBusy() && !categories.isBusy() &&
                !treeFilter.isBusy() && isTableReady(scriptTable),
                "Script Manager model changed before launch");
            return new int[] { index, findNameColumn(table) };
        });
        GuiTestSupport.doubleClickCell(robot, table, cell[0], cell[1], filename);
    }

    static void awaitTableReady(GTable table) throws Exception {
        GuiTestSupport.await("table filter and sort completion", () ->
            isTableReady(table) ? table : null);
        // Ghidra repairs row-object selection with invokeLater after filtering.
        // Drain that queued repair before selecting the final visible row.
        GuiTestSupport.onSwing(() -> null);
    }

    static boolean isTableReady(GTable table) {
        GTableFilterPanel<?> filter = table.getTableFilterPanel();
        GuiTestSupport.require(filter != null, "expected the real Ghidra table filter");
        SwingUpdateManager updater = (SwingUpdateManager) readField(
            filter, GTableFilterPanel.class, "filterUpdater");
        Object model = RowObjectTableModel.unwrap(table.getModel());
        return !updater.isBusy() && (!(model instanceof AbstractSortedTableModel<?> sorted) ||
            !sorted.isSortPending());
    }

    private static Object readField(Object owner, String name) {
        return readField(owner, owner.getClass(), name);
    }

    private static Object readField(Object owner, Class<?> ownerClass, String name) {
        // Pinned Ghidra 12.0.3 exposes no public filter/ScriptList busy query.
        // Observe their actual update managers; never flush or change their work.
        try {
            var field = ownerClass.getDeclaredField(name);
            field.setAccessible(true);
            return field.get(owner);
        }
        catch (ReflectiveOperationException failure) {
            throw new AssertionError("Ghidra readiness field changed: " + name, failure);
        }
    }

    private static int findNameColumn(JTable table) {
        for (int column = 0; column < table.getColumnCount(); column++) {
            if ("Name".equals(table.getColumnName(column))) {
                return column;
            }
        }
        throw new AssertionError("Script Manager Name column disappeared");
    }

    private static int findRow(JTable table, String filename) {
        for (int row = 0; row < table.getRowCount(); row++) {
            for (int column = 0; column < table.getColumnCount(); column++) {
                Object value = table.getValueAt(row, column);
                if (value != null && filename.equals(value.toString())) {
                    return row;
                }
            }
        }
        return -1;
    }

    private static void clearConsole(ConsoleService console) throws Exception {
        GuiTestSupport.onSwing(() -> { console.clearMessages(); return null; });
    }

    private static String consoleText(ConsoleService console) throws Exception {
        return GuiTestSupport.onSwing(() -> console.getText(0, console.getTextLength()));
    }

    private static void awaitConsole(ConsoleService console, String text) throws Exception {
        GuiTestSupport.await("console text: " + text, () -> {
            String actual = console.getText(0, console.getTextLength());
            return actual.contains(text) ? actual : null;
        });
    }
}
