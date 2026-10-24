import java.awt.BorderLayout;
import java.awt.Robot;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;

/** Reproduces the Script Manager's filter-focus state before a real table click. */
public final class GuiTableClickSmoke {
    public static void main(String[] arguments) throws Exception {
        run(Path.of(arguments[0]));
    }

    static void run(Path results) throws Exception {
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
}
