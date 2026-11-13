package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CancellationException;

/** Strict selection grammar prevents ambiguous original-file associations. */
public final class FirmwareInputsSmoke {
    public static void main(String[] args) throws Exception {
        Path path = Files.createTempFile("firmware-input-selection-", ".json");
        int checks = 0;
        String row = "{\"id\":\"flash\",\"fileBytesIndex\":0,\"path\":\"firmware λ.bin\"}";
        String valid = "{\"schema\":1,\"inputs\":[" + row + "]}";
        try {
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
}
