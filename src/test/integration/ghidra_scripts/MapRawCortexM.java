// Explicit compiler-reference fixture map; not automatic firmware inference.
// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.math.BigInteger;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;

public class MapRawCortexM extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (getScriptArgs().length != 2 && getScriptArgs().length != 3) {
            throw new IllegalArgumentException("curation.json labels.json [separate-ram-input]");
        }
        var manifest = new Gson().fromJson(Files.readString(Path.of(getScriptArgs()[0])), JsonObject.class);
        var labels = new Gson().fromJson(Files.readString(Path.of(getScriptArgs()[1])), JsonObject.class);
        var memory = currentProgram.getMemory();
        if (memory.getBlocks().length != 1 || memory.getAllFileBytes().size() != 1) {
            throw new AssertionError("fixture must begin with one raw input block");
        }
        var flash = memory.getBlocks()[0];
        if (flash.getStart().getOffset() != 0) throw new AssertionError("expected raw flash at zero");
        flash.setName("flash");
        flash.setPermissions(true, false, true);
        long data = labels.get("_sdata").getAsLong();
        long endData = labels.get("_edata").getAsLong();
        long bss = labels.get("_sbss").getAsLong();
        long endBss = labels.get("_ebss").getAsLong();
        long source = labels.get("_sidata").getAsLong();
        var dataBytes = memory.getAllFileBytes().getFirst();
        long dataOffset = source;
        if (getScriptArgs().length == 3) {
            Path separate = Path.of(getScriptArgs()[2]);
            if (Files.size(separate) != endData - data) throw new AssertionError("separate RAM input size changed");
            try (var input = Files.newInputStream(separate)) {
                dataBytes = memory.createFileBytes(separate.getFileName().toString(), 0,
                    Files.size(separate), input, monitor);
            }
            dataOffset = 0;
        }
        var initialized = memory.createInitializedBlock("ram-initialization", toAddr(data),
            dataBytes, dataOffset, endData - data, false);
        initialized.setPermissions(true, true, false);
        var unknown = memory.createUninitializedBlock("unknown-ram", toAddr(bss), endBss - bss, false);
        unknown.setPermissions(true, true, false);
        currentProgram.getProgramContext().setValue(currentProgram.getRegister("TMode"),
            flash.getStart(), flash.getEnd(), BigInteger.ONE);
        for (var element : manifest.getAsJsonArray("functions")) {
            monitor.checkCancelled();
            var row = element.getAsJsonObject();
            var entry = toAddr(row.get("entry").getAsLong());
            var body = new AddressSet();
            for (var item : row.getAsJsonArray("ranges")) {
                var range = item.getAsJsonArray();
                body.add(toAddr(range.get(0).getAsLong()), toAddr(range.get(1).getAsLong() - 1));
            }
            if (!new DisassembleCommand(entry, body, true).applyTo(currentProgram, monitor)) {
                throw new AssertionError("raw fixture failed to decode " + row.get("name"));
            }
            currentProgram.getFunctionManager().createFunction(row.get("name").getAsString(),
                entry, body, SourceType.USER_DEFINED);
        }
        println("raw-cortex-map=PASS flashBytes=" + flash.getSize());
    }
}
