// Remove only a data definition in a read-only test session, then export twice.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import java.util.Arrays;

public class ExportArmMixedUnknownData extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) throw new IllegalArgumentException("link-entry data-offset output");
        var image = ghidradwarfforge.elf.ElfImage.read(
            java.nio.file.Path.of(currentProgram.getExecutablePath()));
        long delta = currentProgram.getImageBase().getOffset() - image.preferredImageBase();
        var entry = toAddr(Math.addExact(Long.decode(args[0]), delta));
        int offset = Integer.parseInt(args[1]);
        if (offset != 4 && offset != 48) throw new IllegalArgumentException("split data offset");
        var function = getFunctionAt(entry);
        var address = entry.add(offset);
        var data = getDataAt(address);
        if (function == null || !function.getName().equals("recovered_mixed_body") ||
                function.getBody().intersects(address, address.add(3)) ||
                data == null || !data.isDefined() || data.getLength() != 4) {
            throw new AssertionError("expected defined data outside curated function");
        }
        byte[] before = getBytes(entry, 52);
        currentProgram.getListing().clearCodeUnits(address, address.add(3), false);
        for (int at = 0; at < 4; at++) {
            var unknown = currentProgram.getListing().getCodeUnitAt(address.add(at));
            if (!(unknown instanceof ghidra.program.model.listing.Data cleared) || cleared.isDefined()) {
                throw new AssertionError("data remains defined");
            }
        }
        if (!Arrays.equals(before, getBytes(entry, 52))) throw new AssertionError("memory changed");
        println("mixed-unknown-data-offset=" + offset);
        runScript("RepeatLiveAbiExport.java", new String[] {args[2]});
        if (!Arrays.equals(before, getBytes(entry, 52))) throw new AssertionError("export changed memory");
        println("mixed-unknown-data-export=PASS");
    }
}
