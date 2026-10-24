import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Insets;
import java.awt.Rectangle;
import java.awt.Robot;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JTable;

/** Linux-only native-coordinate check for Ghidra's pack, position, show sequence. */
public final class GuiWindowGeometrySmoke {
    public static void main(String[] arguments) throws Exception {
        GuiTestSupport.require(arguments.length == 1, "expected result directory");
        Path results = Path.of(arguments[0]);
        Files.createDirectories(results);
        Robot robot = new Robot();
        Rectangle screen = java.awt.GraphicsEnvironment.getLocalGraphicsEnvironment()
            .getDefaultScreenDevice().getDefaultConfiguration().getBounds();
        for (int index = 0; index < 100; index++) {
            String title = "Forge native geometry control " + index;
            JFrame frame = GuiTestSupport.onSwing(() -> {
                JFrame created = new JFrame(title);
                JTable table = new JTable(new Object[][] {{ "GhidraDwarfForge.java" }},
                    new Object[] { "Name" });
                JScrollPane scroll = new JScrollPane(table);
                scroll.setPreferredSize(new Dimension(684, 519));
                created.add(scroll, BorderLayout.CENTER);
                // DetachedWindowNode uses this order for a new floating provider.
                created.pack();
                Dimension size = created.getSize();
                created.setBounds(screen.x + (screen.width - size.width) / 2,
                    screen.y + (screen.height - size.height) / 2, size.width, size.height);
                created.setVisible(true);
                return created;
            });
            try {
                GuiTestSupport.foregroundWindow(frame.getRootPane());
                robot.waitForIdle();
                Path nativeLog = results.resolve("native-" + index + ".txt");
                ProcessBuilder queryBuilder = new ProcessBuilder("xwininfo", "-name", title)
                    .redirectErrorStream(true).redirectOutput(nativeLog.toFile());
                queryBuilder.environment().put("LC_ALL", "C");
                Process query = queryBuilder.start();
                try {
                    GuiTestSupport.require(query.waitFor(5, TimeUnit.SECONDS),
                        "native window geometry query timed out");
                    GuiTestSupport.require(query.exitValue() == 0,
                        "native window geometry query failed: " + nativeLog);
                }
                finally {
                    if (query.isAlive()) {
                        query.destroyForcibly();
                        query.waitFor(5, TimeUnit.SECONDS);
                    }
                }
                String nativeBounds = Files.readString(nativeLog, StandardCharsets.UTF_8);
                Rectangle javaBounds = GuiTestSupport.onSwing(frame::getBounds);
                Insets decorations = GuiTestSupport.onSwing(frame::getInsets);
                var x = Pattern.compile("Absolute upper-left X:\\s*(-?\\d+)").matcher(nativeBounds);
                var y = Pattern.compile("Absolute upper-left Y:\\s*(-?\\d+)").matcher(nativeBounds);
                GuiTestSupport.require(x.find() && y.find(), "missing native coordinates");
                int nativeX = Integer.parseInt(x.group(1));
                int nativeY = Integer.parseInt(y.group(1));
                // X names the client window; JFrame includes WM decorations.
                boolean matches = javaBounds.x + decorations.left == nativeX &&
                    javaBounds.y + decorations.top == nativeY;
                Files.writeString(results.resolve("geometry.txt"), index + " Java=" + javaBounds +
                    " decorations=" + decorations + " native-client=" + nativeX + "," + nativeY +
                    " matches=" + matches + "\n", java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.APPEND);
                GuiTestSupport.require(matches, "Java/native window coordinates disagree at " + index);
            }
            catch (Exception | Error failure) {
                GuiTestSupport.captureDesktop(results);
                throw failure;
            }
            finally {
                GuiTestSupport.onSwing(() -> { frame.dispose(); return null; });
            }
        }
        Files.writeString(results.resolve("result.txt"), "native-window-geometry=PASS cases=100\n");
        System.out.println("native-window-geometry=PASS cases=100");
    }
}
