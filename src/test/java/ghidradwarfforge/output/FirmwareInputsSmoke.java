package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.CancellationException;

/** Strict selection grammar prevents ambiguous original-file associations. */
public final class FirmwareInputsSmoke {
    public static void main(String[] args) throws Exception {
        Path path = Files.createTempFile("firmware-input-selection-", ".json");
        int checks = 0;
        String row = "{\"id\":\"flash\",\"fileBytesIndex\":0,\"path\":\"firmware λ.bin\"}";
        String valid = "{\"schema\":1,\"inputs\":[" + row + "]}";
        try {
            checks += boundaries(path);
            Files.writeString(path, valid);
            var input = FirmwareInputs.read(path, () -> false).inputs().getFirst();
            if (!input.id().equals("flash") || input.fileBytesIndex() != 0 ||
                    !input.path().equals("firmware λ.bin")) throw new AssertionError("selection changed");
            checks++;
            for (String bad : new String[] {
                    "{}", valid + "{}", valid.replace("\"schema\":1", "\"schema\":2"),
                    valid.replace("\"schema\":1", "\"schema\":1,\"schema\":1"),
                    valid.replace("\"schema\":1", "\"schema\":1,\"unknown\":0"),
                    "{\"schema\":1,\"inputs\":[]}",
                    "{\"schema\":1,\"inputs\":[" + row + "," + row + "]}",
                    valid.replace("\"fileBytesIndex\":0", "\"fileBytesIndex\":-1"),
                    valid.replace("\"fileBytesIndex\":0", "\"fileBytesIndex\":0.0"),
                    valid.replace("\"fileBytesIndex\":0", "\"fileBytesIndex\":2147483648"),
                    valid.replace("\"fileBytesIndex\":0", "\"fileBytesIndex\":\"0\""),
                    valid.replace("\"id\":\"flash\"", "\"id\":\"\""),
                    valid.replace("firmware λ.bin", "bad\\uD800"),
                    valid.replace("\"path\":", "\"file\":"),
                    valid.replace("\"path\":", "\"path\":\"other\",\"path\":")}) {
                Files.writeString(path, bad);
                try {
                    FirmwareInputs.read(path, () -> false);
                    throw new AssertionError("ambiguous input selection accepted: " + bad);
                }
                catch (IOException | IllegalArgumentException expected) { checks++; }
            }
            Files.write(path, new byte[] {(byte) 0xff});
            try {
                FirmwareInputs.read(path, () -> false);
                throw new AssertionError("invalid UTF-8 accepted");
            }
            catch (IOException expected) { checks++; }
            Files.write(path, (" ".repeat(65536) + valid).getBytes(StandardCharsets.UTF_8));
            try {
                FirmwareInputs.read(path, () -> false);
                throw new AssertionError("selection input byte limit ignored");
            }
            catch (IOException expected) { checks++; }
            Files.writeString(path, valid);
            try {
                FirmwareInputs.read(path, () -> true);
                throw new AssertionError("cancelled selection read completed");
            }
            catch (CancellationException expected) { checks++; }
        }
        finally { Files.delete(path); }
        System.out.println("firmware-input-selection=PASS checks=" + checks);
    }

    private static int boundaries(Path path) throws Exception {
        int checks = 0;
        for (String invalid : new String[] {null, "", " \t\n", "bad\0name"}) {
            reject(() -> new FirmwareInputs.Selection(invalid, 0, "image.bin"));
            reject(() -> new FirmwareInputs.Selection("flash", 0, invalid));
            checks += 2;
        }
        reject(() -> new FirmwareInputs.Selection("flash", -1, "image.bin"));
        reject(() -> new FirmwareInputs(List.of()));
        checks += 2;
        var rows = new ArrayList<FirmwareInputs.Selection>();
        for (int i = 0; i < 128; i++) {
            // Distinct IDs may intentionally name the same path: FileBytes indices
            // are the original-program identities, not filesystem path strings.
            rows.add(new FirmwareInputs.Selection("flash-" + i,
                i == 127 ? Integer.MAX_VALUE : i, "firmware λ.bin"));
        }
        FirmwareInputs selected;
        try { selected = new FirmwareInputs(rows); }
        catch (IllegalArgumentException invalid) {
            throw new AssertionError("exactly 128 distinct FileBytes associations must be accepted", invalid);
        }
        if (!selected.inputs().equals(rows)) throw new AssertionError("128-input order or identity changed");
        rows.clear();
        if (selected.inputs().size() != 128) throw new AssertionError("selection retained mutable caller list");
        try {
            selected.inputs().clear();
            throw new AssertionError("published selection is mutable");
        }
        catch (UnsupportedOperationException expected) { checks++; }
        rows.addAll(selected.inputs());
        rows.add(new FirmwareInputs.Selection("extra", 128, "other.bin"));
        reject(() -> new FirmwareInputs(rows));
        checks += 3;
        for (var duplicate : List.of(
                new FirmwareInputs.Selection("flash-0", 129, "different.bin"),
                new FirmwareInputs.Selection("different-id", 0, "different.bin"))) {
            reject(() -> new FirmwareInputs(List.of(selected.inputs().getFirst(), duplicate)));
            checks++;
        }
        var json = new StringBuilder("{\"schema\":1,\"inputs\":[");
        for (int i = 0; i < selected.inputs().size(); i++) {
            if (i != 0) json.append(',');
            var row = selected.inputs().get(i);
            json.append("{\"id\":\"").append(row.id()).append("\",\"fileBytesIndex\":")
                .append(row.fileBytesIndex()).append(",\"path\":\"firmware λ.bin\"}");
        }
        json.append("]}");
        Files.writeString(path, json);
        byte[] original = Files.readAllBytes(path);
        var polls = new AtomicInteger();
        if (!FirmwareInputs.read(path, () -> { polls.incrementAndGet(); return false; }).equals(selected)) {
            throw new AssertionError("128-input JSON changed associations");
        }
        checks++;
        for (int cancelAt : new int[] {1, Math.max(1, polls.get() / 2), polls.get()}) {
            var counter = new AtomicInteger();
            try {
                FirmwareInputs.read(path, () -> counter.incrementAndGet() >= cancelAt);
                throw new AssertionError("selection cancellation ignored at " + cancelAt);
            }
            catch (CancellationException expected) { checks++; }
            if (!Arrays.equals(original, Files.readAllBytes(path)) ||
                    !FirmwareInputs.read(path, () -> false).equals(selected)) {
                throw new AssertionError("cancelled selection changed input or prevented retry");
            }
            checks++;
        }
        String valid = json.toString();
        for (String bad : List.of(valid.replace("flash-1\"", "flash-0\""),
                valid.replace("\"fileBytesIndex\":1,", "\"fileBytesIndex\":0,"),
                valid.replace("flash-0", "bad\\u0000id"),
                valid.replace("firmware λ.bin", "bad\\u0000path"),
                valid.replace("firmware λ.bin", "  "),
                valid.substring(0, valid.length() - 2) +
                    ",{\"id\":\"extra\",\"fileBytesIndex\":128,\"path\":\"extra.bin\"}]}")) {
            Files.writeString(path, bad);
            byte[] before = Files.readAllBytes(path);
            try {
                FirmwareInputs.read(path, () -> false);
                throw new AssertionError("invalid firmware associations accepted");
            }
            catch (IOException | IllegalArgumentException expected) { checks++; }
            if (!Arrays.equals(before, Files.readAllBytes(path))) throw new AssertionError("rejected input changed");
            checks++;
        }
        return checks;
    }

    private static void reject(Runnable action) {
        try {
            action.run();
            throw new AssertionError("invalid firmware selection accepted");
        }
        catch (IllegalArgumentException expected) { }
    }
}
