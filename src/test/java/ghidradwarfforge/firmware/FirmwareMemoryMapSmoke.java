package ghidradwarfforge.firmware;

import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Collections;
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
        try { run(); }
        catch (IllegalArgumentException unexpected) {
            throw new AssertionError("valid firmware metadata was rejected", unexpected);
        }
    }

    private static void run() {
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
        boundaryInventory();
        exhaustiveRegions();
        System.out.println("firmware-memory-map=PASS checks=" + checks);
    }

    private static void boundaryInventory() {
        for (String name : new String[] {null, "", " \t\n", "bad\0name", "\ud800", "\udc00"}) {
            reject(() -> new Input(name, 1, "ab".repeat(32)), "input ID");
            reject(() -> new FileSpan(0, 1, name, 0), "span input ID");
            reject(() -> unknown(name, 0, 1), "region name");
        }
        for (String hash : new String[] {null, "", "AB".repeat(32), "a".repeat(63), "a".repeat(65), "g".repeat(64)}) {
            reject(() -> new Input("flash", 1, hash), "SHA-256");
        }
        for (long size : new long[] {0, -1, Long.MIN_VALUE}) {
            reject(() -> new Input("flash", size, "ab".repeat(32)), "positive size");
            reject(() -> new FileSpan(0, size, "flash", 0), "range");
            reject(() -> unknown("empty", 0, size), "range");
        }
        for (int bits : new int[] {0, 16, 31, 33, 63, 65}) {
            reject(() -> new FirmwareMemoryMap(bits, List.of(FLASH), List.of(file("a", 0, 1, "flash", 0))), "width");
        }
        reject(() -> new FirmwareMemoryMap(32, List.of(), List.of(unknown("ram", 0, 1))), "original inputs");
        reject(() -> new FirmwareMemoryMap(32, List.of(FLASH), List.of()), "memory regions");
        reject(() -> new FileSpan(0, 1, "flash", -1), "range");
        for (String name : List.of("firmware λ", "raw-\ud83d\ude80", "e\u0301")) {
            var input = new Input(name, Long.MAX_VALUE, "ab".repeat(32));
            var region = file(name, Long.MAX_VALUE - 1, 1, name, Long.MAX_VALUE - 1);
            var map = new FirmwareMemoryMap(64, List.of(input), List.of(region));
            require(map.regions().getFirst().endExclusive() == Long.MAX_VALUE &&
                map.regions().getFirst().spans().getFirst().fileOffset() == Long.MAX_VALUE - 1,
                "largest supported endpoints and Unicode identities must survive");
        }
        var spans = new ArrayList<>(List.of(new FileSpan(2, 2, "flash", 10), new FileSpan(0, 2, "flash", 0)));
        var region = new Region("fragmented", 0, 4, true, false, true, Storage.FILE_BACKED, spans);
        var regions = new ArrayList<>(List.of(unknown("ram", 4, 1), region));
        var inputs = new ArrayList<>(List.of(FLASH));
        var map = new FirmwareMemoryMap(32, inputs, regions);
        spans.clear(); regions.clear(); inputs.clear();
        require(map.inputs().equals(List.of(FLASH)) && map.regions().size() == 2 &&
            region.spans().equals(List.of(new FileSpan(0, 2, "flash", 0), new FileSpan(2, 2, "flash", 10))),
            "mutable extraction inventories must not change the admitted map");
        for (Runnable change : List.<Runnable>of(() -> map.inputs().clear(), () -> map.regions().clear(), () -> region.spans().clear())) {
            try { change.run(); throw new AssertionError("admitted inventory is mutable"); }
            catch (UnsupportedOperationException expected) { checks++; }
        }
    }

    /** Small byte occupancy is independent of the production sorted-endpoint check. */
    private static void exhaustiveRegions() {
        for (int first = 0; first < 5; first++) {
            for (int second = 0; second < 5; second++) {
                for (int firstLength = 1; firstLength <= 3; firstLength++) {
                    for (int secondLength = 1; secondLength <= 3; secondLength++) {
                        boolean[] occupied = new boolean[8];
                        for (int index = first; index < first + firstLength; index++) occupied[index] = true;
                        boolean overlap = false;
                        for (int index = second; index < second + secondLength; index++) overlap |= occupied[index];
                        for (int flags = 0; flags < 8; flags++) {
                            var initial = file("mapped", first, firstLength, "flash", 0);
                            var unknown = new Region("unknown", second, secondLength,
                                (flags & 1) != 0, (flags & 2) != 0, (flags & 4) != 0, Storage.UNINITIALIZED, List.of());
                            var selected = new ArrayList<>(List.of(initial, unknown));
                            if (overlap) {
                                reject(() -> new FirmwareMemoryMap(32, List.of(FLASH), selected), "overlapping");
                                Collections.reverse(selected);
                                reject(() -> new FirmwareMemoryMap(32, List.of(FLASH), selected), "overlapping");
                            }
                            else {
                                var accepted = new FirmwareMemoryMap(32, List.of(FLASH), selected);
                                Collections.reverse(selected);
                                require(accepted.equals(new FirmwareMemoryMap(32, List.of(FLASH), selected)), "input order changed map");
                                var retained = accepted.regions().stream().filter(r -> r.name().equals("unknown")).findFirst().orElseThrow();
                                require(retained.equals(unknown) && retained.spans().isEmpty(),
                                    "permissions or uninitialized memory contents were invented");
                            }
                        }
                    }
                }
            }
        }
    }

    private static void require(boolean value, String message) {
        if (!value) throw new AssertionError(message);
        checks++;
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
