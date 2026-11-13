package ghidradwarfforge.firmware;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.firmware.GhidraFirmwareMemoryMap.BoundInput;

/** Real Ghidra FileBytes, mapped blocks and modified bytes; no provenance mocks. */
public final class GhidraFirmwareMemoryMapSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        Path path = Files.createTempFile("forge-firmware-map-", ".bin");
        byte[] original = new byte[256];
        for (int i = 0; i < original.length; i++) original[i] = (byte) i;
        Files.write(path, original);
        try {
            for (long base : new long[] {0, 0x08004000}) testLayout(path, original, base);
            if (!Arrays.equals(original, Files.readAllBytes(path))) throw new AssertionError("input changed");
        }
        finally { Files.delete(path); }
        System.out.println("ghidra-firmware-memory-map=PASS checks=" + checks);
    }

    private static void testLayout(Path path, byte[] original, long base) throws Exception {
        Object owner = new Object();
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("ARM:LE:32:Cortex"));
        var program = new ProgramDB("raw-firmware", language, language.getDefaultCompilerSpec(), owner);
        try {
            int transaction = program.startTransaction("fixture raw memory map");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                var memory = program.getMemory();
                var bytes = memory.createFileBytes("original.bin", 8, 96,
                    new ByteArrayInputStream(original, 8, 96), TaskMonitor.DUMMY);
                var bindings = List.of(new BoundInput("firmware", path, bytes));
                var flash = memory.createInitializedBlock("flash", space.getAddress(base), bytes, 16, 32, false);
                flash.setPermissions(true, false, true);
                var data = memory.createInitializedBlock("data", space.getAddress(0x20000000), bytes, 64, 16, false);
                data.setPermissions(true, true, false);
                memory.createUninitializedBlock("unknown-ram", space.getAddress(0x20000010), 64, false);
                long before = program.getModificationNumber();
                var map = GhidraFirmwareMemoryMap.capture(program, FirmwareTarget.CORTEX_M3, bindings, TaskMonitor.DUMMY);
                if (program.getModificationNumber() != before || map.regions().size() != 3 ||
                        map.regions().get(0).address() != base ||
                        map.regions().get(0).spans().getFirst().fileOffset() != 24 ||
                        map.regions().get(1).spans().getFirst().fileOffset() != 72 ||
                        map.regions().get(2).storage() != FirmwareMemoryMap.Storage.UNINITIALIZED) {
                    throw new AssertionError("incorrect or mutating Ghidra provenance capture");
                }
                checks++;
                if (!map.equals(GhidraFirmwareMemoryMap.capture(program, FirmwareTarget.CORTEX_M3,
                        bindings, TaskMonitor.DUMMY))) throw new AssertionError("capture not deterministic");
                checks++;
                memory.setByte(flash.getStart(), (byte) 0x55);
                reject(() -> GhidraFirmwareMemoryMap.capture(program, FirmwareTarget.CORTEX_M3,
                    bindings, TaskMonitor.DUMMY), "analysis bytes differ");
                memory.setByte(flash.getStart(), original[24]);
                // Same filename does not authorize a different actual input.
                byte[] changed = original.clone();
                changed[10] ^= 1;
                Files.write(path, changed);
                try {
                    reject(() -> GhidraFirmwareMemoryMap.capture(program, FirmwareTarget.CORTEX_M3,
                        bindings, TaskMonitor.DUMMY), "original bytes do not match");
                }
                finally { Files.write(path, original); }
                reject(() -> GhidraFirmwareMemoryMap.capture(program, FirmwareTarget.CORTEX_M3,
                    List.of(), TaskMonitor.DUMMY), "missing or ambiguous");
                var overlay = memory.createInitializedBlock("overlay", space.getAddress(base), bytes, 16, 8, true);
                reject(() -> GhidraFirmwareMemoryMap.capture(program, FirmwareTarget.CORTEX_M3,
                    bindings, TaskMonitor.DUMMY), "overlay, alias or unmapped");
                memory.removeBlock(overlay, TaskMonitor.DUMMY);
                var alias = memory.createByteMappedBlock("alias", space.getAddress(0x40000000),
                    flash.getStart(), 8, false);
                reject(() -> GhidraFirmwareMemoryMap.capture(program, FirmwareTarget.CORTEX_M3,
                    bindings, TaskMonitor.DUMMY), "overlay, alias or unmapped");
                memory.removeBlock(alias, TaskMonitor.DUMMY);
                var unbacked = memory.createInitializedBlock("unbacked", space.getAddress(0x40000000),
                    8, (byte) 0, TaskMonitor.DUMMY, false);
                reject(() -> GhidraFirmwareMemoryMap.capture(program, FirmwareTarget.CORTEX_M3,
                    bindings, TaskMonitor.DUMMY), "no original-file provenance");
                memory.removeBlock(unbacked, TaskMonitor.DUMMY);
                var cancelled = new TaskMonitorAdapter(true);
                cancelled.cancel();
                try {
                    GhidraFirmwareMemoryMap.capture(program, FirmwareTarget.CORTEX_M3, bindings, cancelled);
                    throw new AssertionError("cancelled capture completed");
                }
                catch (CancelledException expected) { checks++; }
                if (!map.equals(GhidraFirmwareMemoryMap.capture(program, FirmwareTarget.CORTEX_M3,
                        bindings, TaskMonitor.DUMMY))) throw new AssertionError("retry after controls changed map");
                checks++;
            }
            finally { program.endTransaction(transaction, false); }
        }
        finally { program.release(owner); }
    }

    @FunctionalInterface
    private interface Action { void run() throws Exception; }

    private static void reject(Action action, String message) throws Exception {
        try { action.run(); }
        catch (IllegalArgumentException expected) {
            if (!expected.getMessage().contains(message)) throw new AssertionError(expected);
            checks++;
            return;
        }
        throw new AssertionError("invalid Ghidra firmware map accepted: " + message);
    }
}
