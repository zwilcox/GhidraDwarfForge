import java.awt.Component;
import java.awt.GraphicsEnvironment;
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.Robot;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import javax.swing.JTable;

import docking.ComponentProvider;
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

/** Uses the installed Script Manager table and Run task, not direct script construction. */
public final class GuiScriptManagerSmoke {
    private static final String PREFLIGHT = "GhidraDwarfForge.java";
    private static final String EXPORT = "ExportGhidraDwarfForge.java";

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
        Path ghidra = Path.of(arguments[0]);
        Path module = Path.of(arguments[1]);
        Path fixture = Path.of(arguments[2]);
        Path results = Path.of(arguments[3]);
        GhidraApplicationConfiguration configuration = new GhidraApplicationConfiguration();
        configuration.setShowSplashScreen(false);
        configuration.setApplicationLogFile(results.resolve("application.log").toFile());
        configuration.setScriptLogFile(results.resolve("script.log").toFile());
        Application.initializeApplication(new GhidraApplicationLayout(ghidra.toFile()), configuration);

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
                for (String script : new String[] { PREFLIGHT, EXPORT }) {
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
                    launchFromTable(tool, EXPORT, caseDirectory.resolve("export-manager.png"));
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
                        !Files.exists(restricted.resolve("fixture.dbg.c")),
                        "output was published in the restricted original directory");
                    try (var entries = Files.list(chosen)) {
                        GuiTestSupport.require(entries.count() == (cancel ? 0 : 2),
                            "wrong artifact count or staging files left behind");
                    }
                    if (!cancel) {
                        GuiTestSupport.require(transcript.contains("output policy: GUI fallback"),
                            "export did not use the selected output directory");
                        GuiTestSupport.require(Files.size(chosen.resolve("fixture.dbg")) > 0 &&
                            Files.size(chosen.resolve("fixture.dbg.c")) > 0,
                            "completed GUI artifact pair is missing");
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
                        "\ninput_sha256=" + originalHash + "\nresult=PASS\n");
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
        Rectangle row = GuiTestSupport.onSwing(() -> {
            int index = findRow(table, filename);
            table.setRowSelectionInterval(index, index);
            Rectangle cell = table.getCellRect(index, 0, true);
            table.scrollRectToVisible(cell);
            Point point = table.getLocationOnScreen();
            return new Rectangle(point.x + cell.x, point.y + cell.y,
                Math.max(table.getWidth(), 1), cell.height);
        });
        Robot robot = new Robot();
        robot.setAutoDelay(80);
        GuiTestSupport.screenshot(robot, provider.getComponent(), screenshot);
        GuiTestSupport.click(robot, row, 2);
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
