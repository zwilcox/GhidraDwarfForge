import java.awt.GraphicsEnvironment;
import java.awt.Robot;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.JButton;
import javax.swing.JFrame;

/** Fail explicitly unless the native Windows job can drive a real desktop and deny writes. */
public final class WindowsDesktopAclProbe {
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
        GuiTestSupport.require(arguments.length == 1, "expected result directory");
        GuiTestSupport.require(System.getProperty("os.name").startsWith("Windows"),
            "Windows desktop evidence requires native Windows execution");
        GuiTestSupport.require(!GraphicsEnvironment.isHeadless(), "native Windows JVM is headless");
        Path results = Path.of(arguments[0]);
        Files.createDirectories(results);
        Path restricted = Files.createDirectory(results.resolve("restricted"));
        Path original = Files.writeString(restricted.resolve("original.txt"), "preserve original\n");
        String before = GuiTestSupport.sha256(original);
        try (var permissions = new GuiTestSupport.ReadOnlyDirectory(restricted,
                results.resolve("acl.txt"))) {
            GuiTestSupport.require(Files.readString(original).equals("preserve original\n"),
                "ACL setup made the original unreadable");
        }
        GuiTestSupport.require(before.equals(GuiTestSupport.sha256(original)), "original changed");
        AtomicBoolean clicked = new AtomicBoolean();
        JFrame frame = GuiTestSupport.onSwing(() -> {
            JFrame result = new JFrame("GhidraDwarfForge Windows desktop probe");
            JButton button = new JButton("Confirm desktop interaction");
            button.addActionListener(event -> clicked.set(true));
            result.add(button);
            result.setSize(600, 180);
            result.setLocationRelativeTo(null);
            result.setVisible(true);
            return result;
        });
        try {
            Robot robot = new Robot();
            robot.setAutoDelay(100);
            GuiTestSupport.screenshot(robot, frame, results.resolve("desktop.png"));
            GuiTestSupport.clickButton(robot, frame, "Confirm desktop interaction");
            GuiTestSupport.await("real desktop button click", () -> clicked.get() ? frame : null);
        }
        finally {
            GuiTestSupport.onSwing(() -> { frame.dispose(); return null; });
        }
        Files.writeString(results.resolve("result.txt"),
            "windows-native-desktop-click=PASS\nwindows-real-acl-denial=PASS\n" +
            "input-preservation=PASS\n");
        System.out.println("windows-desktop-acl-probe=PASS");
    }
}
