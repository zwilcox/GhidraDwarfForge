package ghidradwarfforge.firmware;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.firmware.GhidraFirmwareMemoryMap.BoundInput;

/** Deterministic edits at public cancellation polls, with real FileBytes and memory blocks. */
public final class FirmwareCaptureConsistencySmoke {
    private static int checks;

    private FirmwareCaptureConsistencySmoke() { }

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        run();
    }

    static void run() throws Exception {
        checks = 0;
        try (var fixture = new Fixture()) {
            long modification = fixture.program.getModificationNumber();
            var monitor = new EditMonitor(0, 0, () -> {});
            var baseline = fixture.capture(fixture.bindings(), monitor);
            require(fixture.program.getModificationNumber() == modification, "baseline changed saved program");
            var region = baseline.regions().getFirst();
            require(region.address() == 0x08004000 && region.length() == 131073 &&
                region.spans().equals(List.of(new FirmwareMemoryMap.FileSpan(0, 131073, "input", 24))),
                "multi-chunk provenance must retain exact absolute file offset and extent");
            require(baseline.inputs().getFirst().sha256().equals(HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(fixture.original))), "whole input digest mismatch");
            require(monitor.hashPolls > 8 && monitor.hashPolls % 2 == 0 && monitor.checkPolls > 4,
                "fixture must exercise two equal multi-chunk digest passes and capture polls");
            int secondDigest = monitor.hashPolls / 2 + 1;
            // Edit an unmapped byte. Provenance comparison alone cannot detect this;
            // the final whole-input digest must reject the changed file.
            byte[] changed = fixture.original.clone();
            changed[changed.length - 1] ^= 1;
            var diskEdit = new EditMonitor(secondDigest, 0, () -> {
                try { Files.write(fixture.path, changed); }
                catch (IOException failure) { throw new UncheckedIOException(failure); }
            });
            try {
                reject(() -> fixture.capture(fixture.bindings(), diskEdit), IOException.class,
                    "original firmware input changed during memory-map capture");
                require(diskEdit.edited && Arrays.equals(changed, Files.readAllBytes(fixture.path)),
                    "capture must neither miss nor undo the injected input edit");
                require(fixture.program.getModificationNumber() == modification, "file refusal changed the program");
            }
            finally { Files.write(fixture.path, fixture.original); }

            var programEdit = new EditMonitor(0, monitor.checkPolls, () -> fixture.block.setWrite(true));
            try {
                reject(() -> fixture.capture(fixture.bindings(), programEdit), IOException.class,
                    "Ghidra program changed during firmware memory-map capture");
                require(programEdit.edited && fixture.block.isWrite(), "capture must preserve the analyst edit");
                require(Arrays.equals(fixture.original, Files.readAllBytes(fixture.path)), "program refusal changed input");
            }
            finally { fixture.block.setWrite(false); }

            reject(() -> fixture.capture(List.of(fixture.binding("first"), fixture.binding("second")), TaskMonitor.DUMMY),
                IllegalArgumentException.class, "duplicate raw firmware input binding");
            var otherBytes = fixture.program.getMemory().createFileBytes("different-filebytes.bin", 8, 131089,
                new ByteArrayInputStream(fixture.original, 8, 131089), TaskMonitor.DUMMY);
            reject(() -> fixture.capture(List.of(fixture.binding("input"), new BoundInput("input", fixture.path, otherBytes)),
                TaskMonitor.DUMMY), IllegalArgumentException.class, "duplicate raw firmware input binding");
            try (var foreign = new Fixture()) {
                reject(() -> fixture.capture(List.of(new BoundInput("input", fixture.path, foreign.bytes)), TaskMonitor.DUMMY),
                    IllegalArgumentException.class, "does not belong to this program");
            }
            Files.write(fixture.path, Arrays.copyOf(fixture.original, 131096));
            try {
                reject(() -> fixture.capture(fixture.bindings(), TaskMonitor.DUMMY), IllegalArgumentException.class,
                    "extent is outside original firmware input");
            }
            finally { Files.write(fixture.path, fixture.original); }
            for (int offset : new int[] {65535, 65536, 131072}) {
                var address = fixture.block.getStart().add(offset);
                fixture.program.getMemory().setByte(address, (byte) (fixture.original[24 + offset] ^ 1));
                try {
                    reject(() -> fixture.capture(fixture.bindings(), TaskMonitor.DUMMY), IllegalArgumentException.class,
                        "analysis bytes differ from original input");
                }
                finally { fixture.program.getMemory().setByte(address, fixture.original[24 + offset]); }
            }
            require(baseline.equals(fixture.capture(fixture.bindings(), TaskMonitor.DUMMY)),
                "restoring explicit fixture edits must restore the exact map");
            require(Arrays.equals(fixture.original, Files.readAllBytes(fixture.path)), "capture changed original bytes");
        }
        System.out.println("firmware-capture-consistency=PASS checks=" + checks);
    }

    private static final class EditMonitor extends TaskMonitorAdapter {
        final int hashAt;
        final int checkAt;
        final Runnable edit;
        int hashPolls;
        int checkPolls;
        boolean edited;

        EditMonitor(int hashAt, int checkAt, Runnable edit) {
            this.hashAt = hashAt;
            this.checkAt = checkAt;
            this.edit = edit;
        }

        @Override
        public boolean isCancelled() {
            if (++hashPolls == hashAt) apply();
            return false;
        }

        @Override
        public void checkCancelled() {
            if (++checkPolls == checkAt) apply();
        }

        private void apply() {
            require(!edited, "test edit must run once");
            edited = true;
            edit.run();
        }
    }

    private static final class Fixture implements AutoCloseable {
        final Object owner = new Object();
        final ProgramDB program;
        final int transaction;
        final Path path;
        final byte[] original = new byte[131104];
        final FileBytes bytes;
        final MemoryBlock block;

        Fixture() throws Exception {
            var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("ARM:LE:32:Cortex"));
            program = new ProgramDB("firmware-consistency", language, language.getDefaultCompilerSpec(), owner);
            path = Files.createTempFile("forge-firmware-consistency-", ".bin");
            for (int index = 0; index < original.length; index++) original[index] = (byte) (index * 37 + index / 256);
            Files.write(path, original);
            transaction = program.startTransaction("bounded firmware fixture");
            bytes = program.getMemory().createFileBytes("original.bin", 8, 131089,
                new ByteArrayInputStream(original, 8, 131089), TaskMonitor.DUMMY);
            block = program.getMemory().createInitializedBlock("flash",
                program.getAddressFactory().getDefaultAddressSpace().getAddress(0x08004000), bytes, 16, 131073, false);
            block.setPermissions(true, false, true);
        }

        BoundInput binding(String id) { return new BoundInput(id, path, bytes); }
        List<BoundInput> bindings() { return List.of(binding("input")); }

        FirmwareMemoryMap capture(List<BoundInput> bindings, TaskMonitor monitor) throws Exception {
            return GhidraFirmwareMemoryMap.capture(program, FirmwareTarget.CORTEX_M3, bindings, monitor);
        }

        @Override
        public void close() throws Exception {
            try { program.endTransaction(transaction, false); }
            finally {
                try { program.release(owner); }
                finally { Files.deleteIfExists(path); }
            }
        }
    }

    @FunctionalInterface
    private interface Action { void run() throws Exception; }

    private static void reject(Action action, Class<? extends Exception> type, String message) throws Exception {
        try { action.run(); }
        catch (Exception expected) {
            require(type.isInstance(expected) && expected.getMessage().contains(message), "unexpected refusal: " + expected);
            return;
        }
        throw new AssertionError("unsafe capture accepted: " + message);
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }
}
