import java.awt.AWTEvent;
import java.awt.Component;
import java.awt.Container;
import java.awt.Dialog;
import java.awt.Frame;
import java.awt.GraphicsEnvironment;
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.Robot;
import java.awt.Toolkit;
import java.awt.Window;
import java.awt.event.AWTEventListener;
import java.awt.event.InputEvent;
import java.awt.event.MouseEvent;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;
import java.util.function.Supplier;

import javax.imageio.ImageIO;
import javax.swing.AbstractButton;
import javax.swing.JTextField;
import javax.swing.JTable;
import javax.swing.SwingUtilities;

/** Real desktop interaction and filesystem restrictions, shared by the GUI probes. */
final class GuiTestSupport {
    private GuiTestSupport() {
    }

    static final class ReadOnlyDirectory implements AutoCloseable {
        private final PosixFileAttributeView posix;
        private final Set<PosixFilePermission> originalPermissions;
        private final AclFileAttributeView acl;
        private final List<AclEntry> originalAcl;

        ReadOnlyDirectory(Path directory, Path evidence) throws Exception {
            posix = Files.getFileAttributeView(directory, PosixFileAttributeView.class);
            acl = Files.getFileAttributeView(directory, AclFileAttributeView.class);
            originalPermissions = posix == null ? null : posix.readAttributes().permissions();
            originalAcl = posix == null && acl != null ? acl.getAcl() : null;
            try {
                if (posix != null) {
                    Set<PosixFilePermission> denied = EnumSet.copyOf(originalPermissions);
                    denied.remove(PosixFilePermission.OWNER_WRITE);
                    denied.remove(PosixFilePermission.GROUP_WRITE);
                    denied.remove(PosixFilePermission.OTHERS_WRITE);
                    posix.setPermissions(denied);
                    Files.writeString(evidence, "permission-policy=POSIX\n" + denied + "\n");
                }
                else {
                    require(acl != null, "filesystem has neither POSIX nor ACL permissions");
                    AclEntry deny = AclEntry.newBuilder().setType(AclEntryType.DENY)
                        .setPrincipal(acl.getOwner())
                        .setPermissions(AclEntryPermission.WRITE_DATA,
                            AclEntryPermission.APPEND_DATA,
                            AclEntryPermission.WRITE_ATTRIBUTES,
                            AclEntryPermission.WRITE_NAMED_ATTRS).build();
                    List<AclEntry> denied = new ArrayList<>();
                    denied.add(deny);
                    denied.addAll(originalAcl);
                    acl.setAcl(denied);
                    Files.writeString(evidence, "permission-policy=Windows ACL\nowner=" +
                        acl.getOwner() + "\noriginal=" + originalAcl + "\nrestricted=" +
                        acl.getAcl() + "\n");
                }
                require(!Files.isWritable(directory), "restricted directory is still writable");
                try {
                    Path unexpected = Files.createTempFile(directory, "write-probe-", ".tmp");
                    Files.delete(unexpected);
                    throw new AssertionError("actual file creation succeeded in restricted directory");
                }
                catch (AccessDeniedException expected) {
                    Files.writeString(evidence, "actual-create=ACCESS_DENIED\n",
                        java.nio.file.StandardOpenOption.APPEND);
                }
            }
            catch (Exception | Error failure) {
                try {
                    close();
                }
                catch (Exception cleanup) {
                    failure.addSuppressed(cleanup);
                }
                throw failure;
            }
        }

        @Override
        public void close() throws java.io.IOException {
            if (posix != null) {
                posix.setPermissions(originalPermissions);
            }
            else if (acl != null && originalAcl != null) {
                acl.setAcl(originalAcl);
            }
        }
    }

    static void operateChooser(Path selected, Path results, boolean cancel) throws Exception {
        operateChooser(selected, results, cancel, "Select GhidraDwarfForge output directory");
    }

    static void operateChooser(Path selected, Path results, boolean cancel, String title) throws Exception {
        Dialog dialog = await("output chooser", () -> Arrays.stream(Window.getWindows())
            .filter(window -> window instanceof Dialog && window.isShowing())
            .map(window -> (Dialog) window)
            .filter(window -> title.equals(window.getTitle()))
            .findFirst().orElse(null));
        Robot robot = new Robot();
        robot.setAutoDelay(80);
        if (!cancel) {
            awaitFileChooser(dialog);
            onSwing(() -> {
                JTextField filename = (JTextField) find(dialog, component ->
                    component instanceof JTextField &&
                    "filenameTextField".equals(component.getName()));
                require(filename != null, "missing chooser filename field");
                filename.setText(selected.toString());
                return null;
            });
            clickButton(robot, dialog, "Select");
            try {
                await("chosen directory", () -> {
                    JTextField path = (JTextField) find(dialog, component ->
                        component instanceof JTextField && "Path".equals(component.getName()));
                    return path != null && selected.equals(Path.of(path.getText())) ? path : null;
                });
            }
            catch (Exception | Error failure) {
                // Preserve the real failure and report the observed controls.
                // Do not retry selection or turn a timeout into acceptance.
                try {
                    String observed = onSwing(() -> {
                        JTextField path = (JTextField) find(dialog, component ->
                            component instanceof JTextField && "Path".equals(component.getName()));
                        JTextField filename = (JTextField) find(dialog, component ->
                            component instanceof JTextField && "filenameTextField".equals(component.getName()));
                        return "requested=" + selected + "\ndialogShowing=" + dialog.isShowing() +
                            "\npath=" + (path == null ? "<missing>" : path.getText()) +
                            "\nfilename=" + (filename == null ? "<missing>" : filename.getText()) + "\n";
                    });
                    System.err.println("output-chooser-navigation-failure:\n" + observed);
                    Files.writeString(results.resolve("chooser-navigation-failure.txt"), observed);
                    if (onSwing(dialog::isShowing)) {
                        screenshot(robot, dialog, results.resolve("chooser-navigation-failure.png"));
                    }
                }
                catch (Exception | Error diagnosticFailure) { failure.addSuppressed(diagnosticFailure); }
                throw failure;
            }
            awaitFileChooser(dialog);
        }
        screenshot(robot, dialog, results.resolve("chooser.png"));
        clickButton(robot, dialog, cancel ? "Cancel" : "Select");
    }

    static Dialog dialog(String title) throws Exception {
        return await(title, () -> Arrays.stream(Window.getWindows())
            .filter(window -> window instanceof Dialog && window.isShowing())
            .map(window -> (Dialog) window).filter(window -> title.equals(window.getTitle()))
            .findFirst().orElse(null));
    }

    static void selectFile(String title, Path selected) throws Exception {
        Dialog dialog = dialog(title);
        Object chooser = awaitFileChooser(dialog);
        JTextField filename = onSwing(() -> (JTextField) find(dialog, component ->
            component instanceof JTextField && "filenameTextField".equals(component.getName())));
        require(filename != null, "missing file chooser field: " + title);
        focus(filename);
        onSwing(() -> {
            filename.setText(selected.toString());
            return null;
        });
        clickButton(new Robot(), dialog, "Select");
        await("file chooser accepted selection", () -> !dialog.isShowing() ? Boolean.TRUE : null);
        java.io.File actual = (java.io.File) chooser.getClass()
            .getMethod("getSelectedFile", boolean.class).invoke(chooser, false);
        require(actual != null && Files.isSameFile(actual.toPath(), selected),
            "file chooser accepted " + actual + " instead of " + selected);
    }

    static Object awaitFileChooser(Dialog dialog) throws Exception {
        // Ghidra 12.0.3 refreshes the remembered selection asynchronously after
        // showing the dialog. That refresh can overwrite freshly entered text.
        // Keep reflection here so standalone desktop/ACL probes need no Ghidra
        // classes. This reads the pinned chooser's test-facing busy indicator;
        // selection still goes through its actual filename field and Select.
        Object chooser = dialog.getClass().getMethod("getDialogComponent").invoke(dialog);
        awaitFileChooserReady(chooser);
        return chooser;
    }

    static void awaitFileChooserReady(Object chooser) throws Exception {
        var pending = chooser.getClass().getDeclaredMethod("pendingUpdate");
        pending.setAccessible(true);
        var updaterField = chooser.getClass().getDeclaredField("modelUpdater");
        updaterField.setAccessible(true);
        Object updater = updaterField.get(chooser);
        var updating = updater.getClass().getMethod("isBusy");
        await("file chooser initialization", () -> {
            try {
                return Boolean.FALSE.equals(pending.invoke(chooser)) &&
                    Boolean.FALSE.equals(updating.invoke(updater)) ? chooser : null;
            }
            catch (ReflectiveOperationException failure) {
                throw new AssertionError("cannot observe pinned Ghidra chooser", failure);
            }
        });
    }

    static void choose(String title, String choice) throws Exception {
        Dialog dialog = dialog(title);
        onSwing(() -> {
            var choices = (javax.swing.JComboBox<?>) find(dialog, component -> component instanceof javax.swing.JComboBox<?>);
            require(choices != null, "missing choice list: " + title);
            choices.setSelectedItem(choice);
            require(choice.equals(choices.getSelectedItem()), "choice was not offered: " + choice);
            return null;
        });
        clickButton(new Robot(), dialog, "OK");
    }

    static void enterText(String title, String text) throws Exception {
        Dialog dialog = dialog(title);
        onSwing(() -> {
            var field = (JTextField) find(dialog, component -> component instanceof JTextField);
            require(field != null, "missing input field: " + title);
            field.setText(text);
            return null;
        });
        clickButton(new Robot(), dialog, "OK");
    }

    static void clickButton(Robot robot, Container parent, String text) throws Exception {
        Component button = await("button " + text, () -> find(parent, component ->
            component instanceof AbstractButton candidate &&
                text.equals(candidate.getText()) && candidate.isShowing() && candidate.isEnabled()));
        click(robot, bounds(button), 1);
    }

    static Window foregroundWindow(Component component) throws Exception {
        Window window = onSwing(() -> SwingUtilities.getWindowAncestor(component));
        require(window != null, "GUI target has no window");
        onSwing(() -> {
            window.toFront();
            window.requestFocus();
            return null;
        });
        await("foreground target window", () -> window.isFocused() ? window : null);
        return window;
    }

    static void focus(Component component) throws Exception {
        Window window = foregroundWindow(component);
        onSwing(() -> component.requestFocusInWindow());
        await("foreground target window and keyboard focus", () ->
            window.isFocused() && component.isFocusOwner() ? component : null);
    }

    static void doubleClickCell(Robot robot, JTable table, int row, int column,
            String expectedName) throws Exception {
        AtomicInteger delivered = new AtomicInteger();
        AtomicReference<String> actual = new AtomicReference<>();
        // Ghidra's component listener can enter a modal compilation loop. An
        // appended MouseListener would then run only after that action returns,
        // while Robot.waitForIdle() can complete in the nested EDT loop.
        // Observe the real event before component dispatch without consuming it.
        // Match GMouseListenerAdapter: rapid consecutive gestures can retain
        // click counts 3/4, and every positive even count triggers the action.
        AWTEventListener listener = deliveredEvent -> {
            if (deliveredEvent instanceof MouseEvent event && event.getSource() == table &&
                    event.getID() == MouseEvent.MOUSE_CLICKED &&
                    event.getButton() == MouseEvent.BUTTON1 && event.getClickCount() > 0 &&
                    event.getClickCount() % 2 == 0) {
                delivered.incrementAndGet();
                int clickedRow = table.rowAtPoint(event.getPoint());
                int clickedColumn = table.columnAtPoint(event.getPoint());
                actual.set(clickedRow + ":" + clickedColumn + ":" +
                    (clickedRow < 0 || clickedColumn < 0 ? "<outside>" :
                        String.valueOf(table.getValueAt(clickedRow, clickedColumn))));
            }
        };
        try {
            Rectangle target = onSwing(() -> {
                Window window = SwingUtilities.getWindowAncestor(table);
                Rectangle cell = table.getCellRect(row, column, true);
                require(window != null && window.isFocused() &&
                    table.getSelectedRow() == row && table.getVisibleRect().contains(cell) &&
                    expectedName.equals(String.valueOf(table.getValueAt(row, column))),
                    "target window, selected visible cell, or filename changed before mouse dispatch");
                Toolkit.getDefaultToolkit().addAWTEventListener(listener, AWTEvent.MOUSE_EVENT_MASK);
                Point point = table.getLocationOnScreen();
                return new Rectangle(point.x + cell.x, point.y + cell.y, cell.width, cell.height);
            });
            click(robot, target, 2);
            require(delivered.get() == 1 &&
                (row + ":" + column + ":" + expectedName).equals(actual.get()),
                "real double-click missed intended cell: delivered=" + delivered.get() +
                    " actual=" + actual.get());
        }
        finally {
            onSwing(() -> {
                Toolkit.getDefaultToolkit().removeAWTEventListener(listener);
                return null;
            });
        }
    }

    static void captureDesktop(Path directory) throws Exception {
        String windows = onSwing(() -> {
            StringBuilder text = new StringBuilder();
            for (Window window : Window.getWindows()) {
                if (window.isShowing()) {
                    String title = window instanceof Frame frame ? frame.getTitle() :
                        window instanceof Dialog dialog ? dialog.getTitle() : "";
                    text.append(window.getClass().getName()).append(" title=").append(title)
                        .append(" bounds=").append(window.getBounds())
                        .append(" focused=").append(window.isFocused())
                        .append(" active=").append(window.isActive())
                        .append(" focusOwner=").append(window.getFocusOwner()).append('\n');
                }
            }
            return text.toString();
        });
        Files.writeString(directory.resolve("failure-windows.txt"), windows);
        Rectangle desktop = GraphicsEnvironment.getLocalGraphicsEnvironment()
            .getDefaultScreenDevice().getDefaultConfiguration().getBounds();
        ImageIO.write(new Robot().createScreenCapture(desktop), "png",
            directory.resolve("failure-desktop.png").toFile());
    }

    static void click(Robot robot, Rectangle rectangle, int count) {
        robot.mouseMove(rectangle.x + rectangle.width / 2, rectangle.y + rectangle.height / 2);
        for (int index = 0; index < count; index++) {
            robot.mousePress(InputEvent.BUTTON1_DOWN_MASK);
            robot.mouseRelease(InputEvent.BUTTON1_DOWN_MASK);
            if (count > 1) {
                robot.delay(80);
            }
        }
        robot.waitForIdle();
    }

    static void screenshot(Robot robot, Component component, Path path) throws Exception {
        robot.waitForIdle();
        ImageIO.write(robot.createScreenCapture(bounds(component)), "png", path.toFile());
    }

    static Rectangle bounds(Component component) throws Exception {
        return onSwing(() -> {
            Point point = component.getLocationOnScreen();
            return new Rectangle(point.x, point.y, component.getWidth(), component.getHeight());
        });
    }

    static Component find(Component component, Predicate<Component> predicate) {
        if (predicate.test(component)) {
            return component;
        }
        if (component instanceof Container parent) {
            for (Component child : parent.getComponents()) {
                Component found = find(child, predicate);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    static <T> T await(String description, Supplier<T> query) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(90).toNanos();
        while (System.nanoTime() < deadline) {
            T result = onSwing(query);
            if (result != null) {
                return result;
            }
            Thread.sleep(100);
        }
        throw new AssertionError("timed out waiting for " + description);
    }

    static <T> T onSwing(Supplier<T> action) throws Exception {
        AtomicReference<T> result = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> result.set(action.get()));
        return result.get();
    }

    static String sha256(Path file) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
            .digest(Files.readAllBytes(file)));
    }

    static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
