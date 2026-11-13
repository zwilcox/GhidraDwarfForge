package ghidradwarfforge.firmware;

import java.nio.ByteOrder;
import java.util.List;
import ghidradwarfforge.firmware.FirmwareMemoryMap.FileSpan;
import ghidradwarfforge.firmware.FirmwareMemoryMap.Input;
import ghidradwarfforge.firmware.FirmwareMemoryMap.Region;
import ghidradwarfforge.firmware.FirmwareMemoryMap.Storage;

/** File offsets deliberately differ from runtime addresses, including copied initialization. */
public final class FirmwareMemoryMapSmoke {
    private static int checks;
    private static final Input FLASH = new Input("flash", 512, "ab".repeat(32));
    private static final Input DATA = new Input("data", 32, "cd".repeat(32));

    public static void main(String[] args) {
        FirmwareTarget.select("cortex-m3").requireSupported();
        reject(() -> FirmwareTarget.select("arm"), "unsupported");
        reject(() -> new FirmwareTarget("cortex-m3", "ARMv7-M", "AAPCS32-base", 40,
            32, 32, ByteOrder.BIG_ENDIAN, "Thumb-only", "ARM:LE:32:Cortex", "default",
            0x05000000L).requireSupported(), "contradictory");
        for (long base : new long[] {0, 0x08004000}) {
            Region text = file("flash", base, 256, "flash", 128);
            Region ram = new Region("initialized-ram", 0x20000000, 64, true, true, false,
                Storage.FILE_BACKED, List.of(new FileSpan(32, 32, "data", 0),
                    new FileSpan(0, 32, "flash", 384)));
            Region bss = unknown("unknown-ram", 0x20000040, 128);
            var map = new FirmwareMemoryMap(32, List.of(DATA, FLASH), List.of(bss, ram, text));
            if (map.regions().get(0).address() != base ||
                    map.regions().get(0).spans().getFirst().fileOffset() != 128 ||
                    map.regions().get(1).spans().getFirst().fileOffset() != 384 ||
                    map.regions().get(2).storage() != Storage.UNINITIALIZED) {
                throw new AssertionError("input offsets, runtime addresses or unknown contents lost");
            }
            if (!map.equals(new FirmwareMemoryMap(32, List.of(FLASH, DATA), List.of(text, ram, bss)))) {
                throw new AssertionError("map order depends on extraction iteration order");
            }
            checks += 2;
        }
        // Shared source bytes at distinct VAs describe an explicit initial copy, not a live alias.
        var copies = new FirmwareMemoryMap(32, List.of(FLASH), List.of(
            file("flash", 0, 16, "flash", 0), file("ram-copy", 0x20000000, 16, "flash", 0)));
        if (copies.regions().size() != 2) throw new AssertionError("explicit copy collapsed");
        checks++;
        new FirmwareMemoryMap(32, List.of(FLASH), List.of(file("top", 0xfffffff0L, 16, "flash", 0)));
        new FirmwareMemoryMap(64, List.of(FLASH), List.of(file("high", 0x1_0000_0000L, 16, "flash", 0)));
        checks += 2;
        reject(() -> new FirmwareMemoryMap(32, List.of(FLASH), List.of(
            file("a", 0, 16, "flash", 0), unknown("b", 15, 10))), "overlapping");
        reject(() -> new FirmwareMemoryMap(32, List.of(FLASH), List.of(
            file("a", 0, 16, "flash", 0), unknown("a", 16, 10))), "duplicate");
        reject(() -> new FirmwareMemoryMap(32, List.of(FLASH, FLASH), List.of(
            file("a", 0, 16, "flash", 0))), "duplicate");
        reject(() -> new FirmwareMemoryMap(32, List.of(FLASH, DATA), List.of(
            file("a", 0, 16, "flash", 0))), "no mapped bytes");
        reject(() -> new FirmwareMemoryMap(32, List.of(FLASH), List.of(
            file("a", 0, 16, "missing", 0))), "missing or short");
        reject(() -> new FirmwareMemoryMap(32, List.of(FLASH), List.of(
            file("a", 0, 16, "flash", 500))), "missing or short");
        reject(() -> new FirmwareMemoryMap(32, List.of(FLASH), List.of(
            file("a", 0xfffffff0L, 17, "flash", 0))), "32-bit");
        reject(() -> file("a", Long.MAX_VALUE, 1, "flash", 0), "range");
        reject(() -> new FileSpan(0, 10, "flash", Long.MAX_VALUE - 9), "range");
        reject(() -> new FileSpan(-1, 10, "flash", 0), "range");
        reject(() -> unknown("a", 0, 0), "range");
        reject(() -> new Region("a", 0, 16, true, false, false, Storage.FILE_BACKED,
            List.of(new FileSpan(1, 15, "flash", 0))), "gap or overlap");
        reject(() -> new Region("a", 0, 16, true, false, false, Storage.FILE_BACKED,
            List.of(new FileSpan(0, 8, "flash", 0), new FileSpan(7, 8, "flash", 8))), "gap or overlap");
        reject(() -> new Region("a", 0, 16, true, false, false, Storage.FILE_BACKED,
            List.of(new FileSpan(0, 15, "flash", 0))), "does not cover");
        reject(() -> new Region("a", 0, 16, true, false, false, Storage.UNINITIALIZED,
            List.of(new FileSpan(0, 16, "flash", 0))), "cannot claim");
        reject(() -> new Input("flash", 512, "wrong-hash"), "SHA-256");
        System.out.println("firmware-memory-map=PASS checks=" + checks);
    }

    private static Region file(String name, long address, long size, String input, long offset) {
        return new Region(name, address, size, true, false, true, Storage.FILE_BACKED,
            List.of(new FileSpan(0, size, input, offset)));
    }

    private static Region unknown(String name, long address, long size) {
        return new Region(name, address, size, true, true, false, Storage.UNINITIALIZED, List.of());
    }

    private static void reject(Runnable action, String reason) {
        try { action.run(); }
        catch (IllegalArgumentException expected) {
            if (!expected.getMessage().contains(reason)) throw new AssertionError(expected);
            checks++;
            return;
        }
        throw new AssertionError("invalid firmware metadata accepted: " + reason);
    }
}
