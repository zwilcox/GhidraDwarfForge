// Save independently compiler-evidenced adjustment thunks in the stripped fixture.
// @category DWARF.Tests

import com.google.gson.JsonParser;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraImageBase;
import java.nio.file.Files;
import java.nio.file.Path;

public class PrepareAdjustmentThunks extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (getScriptArgs().length != 1) throw new IllegalArgumentException("thunks.json");
        var evidence = JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();
        long delta = currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram);
        var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        int count = 0;
        for (var item : evidence.getAsJsonArray("thunks")) {
            monitor.checkCancelled();
            var row = item.getAsJsonObject();
            var target = getFunctionAt(space.getAddress(row.get("target").getAsLong() + delta));
            if (target == null || target.isThunk()) throw new AssertionError("fixture target is not an existing local definition");
            String targetName = target.getName(true), signature = target.getPrototypeString(true, true);
            var entry = space.getAddress(row.get("address").getAsLong() + delta);
            disassemble(entry);
            var thunk = getFunctionAt(entry);
            if (thunk == null) thunk = createFunction(entry, row.get("name").getAsString());
            if (thunk == null) throw new AssertionError("cannot create compiler-evidenced adjustment thunk");
            thunk.setBody(new AddressSet(entry, entry.add(row.get("size").getAsLong() - 1)));
            thunk.setThunkedFunction(target);
            thunk.setName(row.get("name").getAsString(), SourceType.USER_DEFINED);
            thunk.setParentNamespace(currentProgram.getGlobalNamespace());
            if (!thunk.isThunk() || thunk.getThunkedFunction(false).getID() != target.getID() ||
                    !target.getName(true).equals(targetName) || !target.getPrototypeString(true, true).equals(signature)) {
                throw new AssertionError("saved thunk changed its target identity or signature");
            }
            count++;
        }
        if (count != 3) throw new AssertionError("adjustment thunk fixture is incomplete");
        println("adjustment-thunks-curation=PASS count=" + count);
    }
}
