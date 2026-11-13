// Validate and explicitly store an analyst MMIO profile in the current program.
// @category DWARF

import ghidra.app.script.GhidraScript;
import ghidradwarfforge.GhidraMmioProfile;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class GhidraDwarfForgeMmioProfile extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (currentProgram == null) throw new IllegalStateException("Open the program to configure its MMIO profile");
        String[] args = getScriptArgs();
        if (args.length > 1 || args.length == 0 && isRunningHeadless()) {
            throw new IllegalArgumentException("Supply one analyst MMIO selection JSON file");
        }
        Path path = args.length == 1 ? Path.of(args[0]) : askFile("Select analyst MMIO profile", "Apply").toPath();
        byte[] bytes;
        try (var input = Files.newInputStream(path)) { bytes = input.readNBytes(65537); }
        if (bytes.length > 65536) throw new IllegalArgumentException("MMIO selection exceeds 64 KiB");
        String text = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString();
        int transaction = currentProgram.startTransaction("Apply explicit MMIO profile");
        boolean commit = false;
        try {
            GhidraMmioProfile.read(currentProgram, text, monitor);
            monitor.checkCancelled();
            currentProgram.getOptions(GhidraMmioProfile.OPTIONS).setString(GhidraMmioProfile.SELECTION, text);
            commit = true;
        }
        finally { currentProgram.endTransaction(transaction, commit); }
        println("MMIO profile applied to the current program; save the program to retain it. No device access performed.");
    }
}
