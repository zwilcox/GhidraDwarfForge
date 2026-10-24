import java.awt.BorderLayout;
import java.awt.Robot;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;

/** Exercises real table clicks with filter focus and a modal action listener. */
public final class GuiTableClickSmoke {
    public static void main(String[] arguments) throws Exception {
        run(Path.of(arguments[0]));
    }

    static void run(Path results) throws Exception {
        runFilterFocus(results);
        runModalDispatch(Files.createDirectory(results.resolve("modal-dispatch")));
    }

    private static void runFilterFocus(Path results) throws Exception {
        AtomicInteger launches = new AtomicInteger();
        JTable table = GuiTestSupport.onSwing(() -> new JTable(new Object[][] {
            { "Other.java" }, { "GhidraDwarfForge.java" }
        }, new Object[] { "Name" }));
        JTextField filter = GuiTestSupport.onSwing(() ->
            new JTextField("Script Manager activation focuses this filter"));
        JFrame frame = GuiTestSupport.onSwing(() -> {
            JFrame created = new JFrame("Script table mouse dispatch control");
            table.setDefaultEditor(Object.class, null);
            table.setRowSelectionInterval(1, 1);
            table.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent event) {
                    if (event.getButton() == MouseEvent.BUTTON1 && event.getClickCount() == 2 &&
                            table.rowAtPoint(event.getPoint()) == 1) {
                        launches.incrementAndGet();
                    }
                }
            });
            created.add(new JScrollPane(table), BorderLayout.CENTER);
            created.add(filter, BorderLayout.SOUTH);
            created.setBounds(120, 120, 600, 260);
            created.setVisible(true);
            return created;
        });
        try {
            Robot robot = new Robot();
            robot.setAutoDelay(80);
            GuiTestSupport.focus(filter);
            GuiTestSupport.require(GuiTestSupport.onSwing(() ->
                frame.isFocused() && filter.isFocusOwner() && !table.isFocusOwner() &&
                    table.getVisibleRect().contains(table.getCellRect(1, 0, true))),
                "filter focus did not reproduce the previous table-focus rejection");
            GuiTestSupport.screenshot(robot, frame, results.resolve("filter-focus.png"));
            GuiTestSupport.doubleClickCell(robot, table, 1, 0, "GhidraDwarfForge.java");
            GuiTestSupport.require(launches.get() == 1,
                "real double-click did not invoke the target exactly once");
            Files.writeString(results.resolve("result.txt"),
                "old-table-keyboard-focus-precondition=REJECTED\n" +
                "foreground-filter-focused-real-table-double-click=PASS\n" +
                "target-invocations=1\n");
            System.out.println("filter-focus-mouse-dispatch=PASS");
        }
        catch (Exception | Error failure) {
            GuiTestSupport.captureDesktop(results);
            throw failure;
        }
        finally {
            GuiTestSupport.onSwing(() -> { frame.dispose(); return null; });
        }
    }

    private static void runModalDispatch(Path results) throws Exception {
        AtomicInteger launches = new AtomicInteger();
        AtomicInteger lateDeliveries = new AtomicInteger();
        AtomicBoolean actionReturned = new AtomicBoolean();
        JTable table = GuiTestSupport.onSwing(() -> new JTable(new Object[][] {
            { "GhidraDwarfForge.java" }
        }, new Object[] { "Name" }));
        JFrame frame = GuiTestSupport.onSwing(() -> {
            JFrame created = new JFrame("Modal script compilation dispatch control");
            table.setDefaultEditor(Object.class, null);
            table.setRowSelectionInterval(0, 0);
            created.add(new JScrollPane(table));
            created.setBounds(160, 160, 600, 260);
            created.setVisible(true);
            return created;
        });
        JDialog modal = GuiTestSupport.onSwing(() -> {
            JDialog created = new JDialog(frame, "Compiling Script Directory control", true);
            created.add(new JLabel("The real mouse action is suspended in this modal dialog."));
            created.setSize(500, 140);
            created.setLocationRelativeTo(frame);
            table.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent event) {
                    if (event.getButton() == MouseEvent.BUTTON1 && event.getClickCount() == 2) {
                        launches.incrementAndGet();
                        created.setVisible(true);
                        actionReturned.set(true);
                    }
                }
            });
            // Like the old observer, this listener cannot run until the modal
            // action returns, although the nested EDT processes waitForIdle().
            table.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent event) {
                    if (event.getButton() == MouseEvent.BUTTON1 && event.getClickCount() == 2) {
                        lateDeliveries.incrementAndGet();
                    }
                }
            });
            return created;
        });
        try {
            Robot robot = new Robot();
            robot.setAutoDelay(80);
            GuiTestSupport.foregroundWindow(table);
            GuiTestSupport.doubleClickCell(robot, table, 0, 0, "GhidraDwarfForge.java");
            GuiTestSupport.require(GuiTestSupport.onSwing(() -> modal.isShowing()) &&
                launches.get() == 1 && !actionReturned.get() && lateDeliveries.get() == 0,
                "modal action did not suspend the late component observer");
            GuiTestSupport.screenshot(robot, modal, results.resolve("modal.png"));
            GuiTestSupport.onSwing(() -> { modal.dispose(); return null; });
            GuiTestSupport.await("modal action and late observer completion", () ->
                actionReturned.get() && lateDeliveries.get() == 1 ? table : null);
            GuiTestSupport.require(launches.get() == 1, "modal action was invoked again");
            Files.writeString(results.resolve("result.txt"),
                "real-double-click-observed-before-modal-action-return=PASS\n" +
                "late-component-observer-before-modal-close=0\n" +
                "late-component-observer-after-modal-close=1\n" +
                "target-invocations=1\n");
            System.out.println("modal-mouse-dispatch=PASS");
        }
        catch (Exception | Error failure) {
            GuiTestSupport.captureDesktop(results);
            throw failure;
        }
        finally {
            GuiTestSupport.onSwing(() -> { modal.dispose(); frame.dispose(); return null; });
        }
    }
}
