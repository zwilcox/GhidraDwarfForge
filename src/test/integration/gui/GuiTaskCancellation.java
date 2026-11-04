import java.awt.Component;
import java.awt.Robot;
import java.awt.Window;
import java.nio.file.Path;
import javax.swing.AbstractButton;
import javax.swing.SwingUtilities;

/** Real Ghidra task cancellation, kept separate from bare-JDK geometry checks. */
final class GuiTaskCancellation {
    private GuiTaskCancellation() { }

    static void cancelTask(Robot robot, String message, Path screenshot) throws Exception {
        var monitor = GuiTestSupport.await("active task " + message, () -> {
            for (Window window : Window.getWindows()) {
                Component found = GuiTestSupport.find(window, component ->
                    component instanceof ghidra.util.task.TaskMonitorComponent candidate &&
                    candidate.isShowing() && message.equals(candidate.getMessage()));
                if (found != null) return (ghidra.util.task.TaskMonitorComponent) found;
            }
            return null;
        });
        Component button = GuiTestSupport.await("active task cancel button", () -> GuiTestSupport.find(monitor, component ->
            component instanceof AbstractButton candidate && candidate.isShowing() &&
            candidate.isEnabled() && "CANCEL_TASK".equals(candidate.getName())));
        GuiTestSupport.foregroundWindow(button);
        GuiTestSupport.screenshot(robot, SwingUtilities.getWindowAncestor(button), screenshot);
        GuiTestSupport.click(robot, GuiTestSupport.bounds(button), 1);
        GuiTestSupport.clickButton(robot, GuiTestSupport.dialog("Cancel?"), "Yes");
    }

    static void cancelLaunchedTask(Robot robot, String title, String message, Path screenshot) throws Exception {
        // TaskLauncher uses TaskDialog: its message is in the dialog's status
        // area and its Cancel button is separate from TaskMonitorComponent.
        var dialog = GuiTestSupport.await("launched task " + title + ": " + message, () -> {
            for (Window window : Window.getWindows()) {
                if (window instanceof docking.DockingDialog candidate && candidate.isShowing() &&
                        title.equals(candidate.getTitle()) &&
                        candidate.getDialogComponent() instanceof ghidra.util.task.TaskDialog task &&
                        message.equals(task.getMessage()) && task.isCancelEnabled() && !task.isCompleted()) {
                    return candidate;
                }
            }
            return null;
        });
        Component button = GuiTestSupport.await("launched task Cancel button", () -> GuiTestSupport.find(dialog,
            component -> component instanceof AbstractButton candidate && candidate.isShowing() &&
                candidate.isEnabled() && "Cancel".equals(candidate.getText())));
        GuiTestSupport.foregroundWindow(button);
        GuiTestSupport.screenshot(robot, dialog, screenshot);
        GuiTestSupport.click(robot, GuiTestSupport.bounds(button), 1);
        GuiTestSupport.clickButton(robot, GuiTestSupport.dialog("Cancel?"), "Yes");
    }

    static void verifyLauncherCancellation(Path directory) throws Exception {
        java.nio.file.Files.createDirectory(directory);
        var started = new java.util.concurrent.CompletableFuture<ghidra.util.task.TaskMonitor>();
        var finished = new java.util.concurrent.CountDownLatch(1);
        String title = "Owned Script Manager task control";
        String message = "Waiting for real task cancellation";
        var task = new ghidra.util.task.Task(title, true, false, false) {
            @Override
            public void run(ghidra.util.task.TaskMonitor monitor) {
                monitor.setMessage(message);
                started.complete(monitor);
                try {
                    while (!monitor.isCancelled()) Thread.sleep(20);
                }
                catch (InterruptedException failure) { Thread.currentThread().interrupt(); }
                finally { finished.countDown(); }
            }
        };
        GuiTestSupport.onSwing(() -> { new ghidra.util.task.TaskLauncher(task, null, 0); return null; });
        var monitor = started.get(30, java.util.concurrent.TimeUnit.SECONDS);
        try {
            var dialog = GuiTestSupport.dialog(title);
            GuiTestSupport.require(GuiTestSupport.onSwing(() -> GuiTestSupport.find(dialog, component ->
                component instanceof ghidra.util.task.TaskMonitorComponent candidate &&
                    candidate.isShowing() && message.equals(candidate.getMessage()))) == null,
                "control no longer reproduces the obsolete task-monitor lookup");
            cancelLaunchedTask(new Robot(), title, message, directory.resolve("active-task.png"));
            GuiTestSupport.require(finished.await(30, java.util.concurrent.TimeUnit.SECONDS) && monitor.isCancelled(),
                "launched task did not finish after the real Cancel/Yes interaction");
            java.nio.file.Files.writeString(directory.resolve("result.txt"),
                "obsolete-monitor-lookup=ABSENT\nreal-task-dialog-cancel=PASS\nconfirmation-yes=PASS\nworker-finished=PASS\n");
        }
        finally { if (finished.getCount() != 0) monitor.cancel(); }
    }

}
