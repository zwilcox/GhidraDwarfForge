package ghidradwarfforge;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;

/** Real program edits/restoration, file replacement, cancellation and I/O controls. */
public final class GhidraExportConsistencySmoke {
    private static int checks;
    @FunctionalInterface private interface Checked { void run() throws Exception; }
    @FunctionalInterface private interface Cancellable { void run(BooleanSupplier cancelled) throws Exception; }

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        Path work = Path.of(args[1]); Files.createDirectories(work);
        Path input = work.resolve("owned-input"), saved = work.resolve("saved-input");
        byte[] bytes = new byte[128 * 1024 + 17];
        for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) i;
        Files.write(input, bytes);
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:64:default"));
        Object owner = new Object();
        var program = new ProgramDB("consistency", language, language.getCompilerSpecByID(new CompilerSpecID("gcc")), owner);
        try {
            int transaction = program.startTransaction("owned fixture");
            try {
                var address = language.getDefaultSpace().getAddress(0x1000);
                program.getMemory().createInitializedBlock("text", address, 16, (byte) 0, TaskMonitor.DUMMY, false);
                var guard = GhidraExportConsistency.capture(program, input, () -> false);
                guard.requireUnchanged(() -> false); checks++;
                program.getMemory().setByte(address, (byte) 1);
                rejected(() -> guard.requireUnchanged(() -> false), "Ghidra program changed");
                program.getMemory().setByte(address, (byte) 0);
                rejected(() -> guard.requireUnchanged(() -> false), "Ghidra program changed");
                var refreshed = GhidraExportConsistency.capture(program, input, () -> false);
                refreshed.requireUnchanged(() -> false); checks++;
                bytes[11] ^= 1; Files.write(input, bytes);
                rejected(() -> refreshed.requireUnchanged(() -> false), "Original ELF changed");
                bytes[11] ^= 1; Files.write(input, bytes);
                refreshed.requireUnchanged(() -> false); checks++;
                Files.move(input, saved);
                try {
                    try { refreshed.requireUnchanged(() -> false); throw new AssertionError("missing input accepted"); }
                    catch (java.nio.file.NoSuchFileException expected) { checks++; }
                }
                finally { Files.move(saved, input); }
                cancellation(cancelled -> GhidraExportConsistency.capture(program, input, cancelled));
                cancellation(refreshed::requireUnchanged);
                refreshed.requireUnchanged(() -> false); checks++;
            }
            finally { program.endTransaction(transaction, false); }
        }
        finally { program.release(owner); }
        System.out.println("export-consistency-smoke=PASS checks=" + checks);
    }

    private static void rejected(Checked operation, String message) throws Exception {
        try { operation.run(); throw new AssertionError("changed evidence accepted"); }
        catch (IOException expected) {
            if (!expected.getMessage().contains(message)) throw expected;
            checks++;
        }
    }

    private static void cancellation(Cancellable operation) throws Exception {
        int[] polls = {0};
        operation.run(() -> { polls[0]++; return false; });
        for (int stopAt = 1; stopAt <= polls[0]; stopAt++) {
            int stop = stopAt; int[] seen = {0};
            try { operation.run(() -> ++seen[0] == stop); throw new AssertionError("cancellation ignored"); }
            catch (CancellationException expected) { checks++; }
        }
        operation.run(() -> false); checks++;
    }
}
