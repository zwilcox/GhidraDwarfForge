// Verify that decompilation did not fill an intentionally undecoded listing gap.
// @category DWARF.Tests

import java.nio.file.Files;
import java.nio.file.Path;

import ghidra.app.script.GhidraScript;
import ghidradwarfforge.AddressNormalizer;
import ghidradwarfforge.GhidraImageBase;

public class VerifyOpaqueListing extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2 || !(args[1].equals("gap") || args[1].equals("complete"))) {
            throw new IllegalArgumentException("expected compiler labels and listing profile");
        }
        long delta = AddressNormalizer.rebaseDelta(currentProgram.getImageBase().getOffset(),
            GhidraImageBase.originalImageBase(currentProgram));
        for (String line : Files.readAllLines(Path.of(args[0]))) {
            String[] parts = line.split(" ");
            if (!parts[0].equals("opaque_before")) {
                continue;
            }
            var address = toAddr(Math.addExact(Long.decode(parts[1]), delta));
            var function = getFunctionContaining(address);
            if (function == null || !function.getName().equals("opaque_value") ||
                    !function.getBody().contains(address, address.add(3)) ||
                    getInt(address) != 0xd4000001 ||
                    (getInstructionAt(address) == null) != args[1].equals("gap")) {
                throw new IllegalStateException("export changed the curated listing or code bytes");
            }
            println("opaque-listing-preservation=PASS profile=" + args[1] + " body=" + function.getBody());
            return;
        }
        throw new IllegalArgumentException("missing syscall label");
    }
}
