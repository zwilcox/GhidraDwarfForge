// Rebases the imported fixture before analyst edits and export.
// @category DWARF.Tests

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class RebaseFixtureProgram extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 1) {
            throw new IllegalArgumentException(
                "usage: RebaseFixtureProgram <signed-delta>");
        }
        long delta = Long.decode(arguments[0]);
        if (delta == 0) {
            throw new IllegalArgumentException("fixture rebase delta must be nonzero");
        }
        Address previous = currentProgram.getImageBase();
        Address rebased = previous.addNoWrap(delta);
        currentProgram.setImageBase(rebased, true);
        println("Rebased fixture image from " + previous + " to " + rebased +
            " by " + arguments[0]);
    }
}
