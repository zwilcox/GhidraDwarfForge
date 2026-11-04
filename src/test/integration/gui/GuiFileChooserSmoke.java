import java.awt.Dialog;
import java.awt.Robot;
import java.io.File;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.util.filechooser.GhidraFileChooserModel;

/** Reproduces the remembered-file refresh racing with automated filename entry. */
public final class GuiFileChooserSmoke {
    static void run(Path results) throws Exception {
        Path remembered = Files.writeString(results.resolve("previous request.json"), "previous");
        Path intended = Files.writeString(results.resolve("intended request λ.json"), "intended");
        exercise(results, remembered, intended, false);
        exercise(results, remembered, intended, true);
        Files.writeString(results.resolve("result.txt"),
            "delayed-refresh-overwrites-early-entry=PASS\n" +
            "old-interaction-selects-previous-file=PASS\n" +
            "selection-waits-for-refresh=PASS\nintended-file-accepted=PASS\n");
        System.out.println("real-file-chooser-delayed-refresh=PASS");
    }

    private static void exercise(Path results, Path remembered, Path intended, boolean guarded)
            throws Exception {
        String title = guarded ? "Guarded delayed chooser" : "Early-entry delayed chooser";
        GhidraFileChooser chooser = GuiTestSupport.onSwing(() -> {
            var created = new GhidraFileChooser(null);
            created.setTitle(title);
            created.setApproveButtonText("Select");
            created.setSelectedFile(remembered.toFile());
            return created;
        });
        CountDownLatch listingStarted = new CountDownLatch(1);
        CountDownLatch releaseListing = new CountDownLatch(1);
        var chosen = new CompletableFuture<File>();
        var interaction = new CompletableFuture<Void>();
        AtomicReference<Thread> selector = new AtomicReference<>();
        try {
            GuiTestSupport.awaitFileChooserReady(chooser);
            // Retain the real local filesystem model, delaying only its directory
            // listing. The chooser's own worker/EDT code restores the old filename.
            var modelField = GhidraFileChooser.class.getDeclaredField("fileChooserModel");
            modelField.setAccessible(true);
            Object model = modelField.get(chooser);
            Object delayed = Proxy.newProxyInstance(GhidraFileChooserModel.class.getClassLoader(),
                new Class<?>[] {GhidraFileChooserModel.class}, (proxy, method, arguments) -> {
                    if (method.getName().equals("getListing")) {
                        listingStarted.countDown();
                        GuiTestSupport.require(releaseListing.await(30, TimeUnit.SECONDS),
                            "controlled directory listing was not released");
                    }
                    return method.invoke(model, arguments);
                });
            GuiTestSupport.onSwing(() -> {
                try { modelField.set(chooser, delayed); }
                catch (IllegalAccessException failure) { throw new AssertionError(failure); }
                return null;
            });
            SwingUtilities.invokeLater(() -> {
                try { chosen.complete(chooser.getSelectedFile()); }
                catch (Throwable failure) { chosen.completeExceptionally(failure); }
            });
            Dialog dialog = GuiTestSupport.dialog(title);
            GuiTestSupport.require(listingStarted.await(30, TimeUnit.SECONDS),
                "chooser did not start its delayed listing");
            JTextField filename = GuiTestSupport.onSwing(() -> (JTextField) GuiTestSupport.find(dialog,
                component -> component instanceof JTextField && "filenameTextField".equals(component.getName())));
            GuiTestSupport.require(filename != null, "missing real chooser filename field");
            if (guarded) {
                Thread worker = new Thread(() -> {
                    try {
                        GuiTestSupport.selectFile(title, intended);
                        interaction.complete(null);
                    }
                    catch (Throwable failure) { interaction.completeExceptionally(failure); }
                }, "guarded-file-selection");
                selector.set(worker);
                worker.start();
                // Observe the helper waiting on the held listing, rather than
                // guessing how long a busy desktop needs to initialize.
                GuiTestSupport.await("selection waiting for delayed directory refresh", () -> {
                    GuiTestSupport.require(!interaction.isDone(), "selection completed before directory refresh");
                    return Arrays.stream(worker.getStackTrace()).anyMatch(frame ->
                        frame.getClassName().equals("GuiTestSupport") &&
                        frame.getMethodName().equals("awaitFileChooserReady")) ? Boolean.TRUE : null;
                });
                GuiTestSupport.require(!GuiTestSupport.onSwing(filename::getText).equals(intended.toString()),
                    "guarded helper entered text before initialization finished");
                releaseListing.countDown();
                interaction.get(90, TimeUnit.SECONDS);
            }
            else {
                GuiTestSupport.onSwing(() -> { filename.setText(intended.toString()); return null; });
                releaseListing.countDown();
                GuiTestSupport.await("remembered filename overwrote early entry", () ->
                    filename.getText().equals(remembered.getFileName().toString()) ? filename : null);
                GuiTestSupport.screenshot(new Robot(), dialog, results.resolve("overwritten-entry.png"));
                GuiTestSupport.clickButton(new Robot(), dialog, "Select");
            }
            File actual = chosen.get(30, TimeUnit.SECONDS);
            Path expected = guarded ? intended : remembered;
            GuiTestSupport.require(actual != null && Files.isSameFile(actual.toPath(), expected),
                "delayed chooser selected " + actual + " instead of " + expected);
            Files.writeString(results.resolve(guarded ? "guarded.txt" : "early-entry.txt"),
                "requested=" + intended + "\naccepted=" + actual + "\n");
        }
        finally {
            releaseListing.countDown();
            Thread worker = selector.get();
            if (worker != null && worker.isAlive()) {
                worker.interrupt();
                worker.join(5000);
            }
            GuiTestSupport.onSwing(() -> { chooser.close(); chooser.dispose(); return null; });
        }
    }
}
