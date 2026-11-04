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

}
