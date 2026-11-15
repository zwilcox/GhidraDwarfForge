// Rebase an owned fixture after saving inheritance; do not refresh its evidence.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidradwarfforge.GhidraInheritanceBindings;

public class RebaseInheritanceFixture extends GhidraScript {
    @Override
    protected void run() throws Exception {
        var before = GhidraInheritanceBindings.read(currentProgram, monitor, this::println);
        if (before.status() != GhidraInheritanceBindings.Status.VALID) throw new AssertionError("missing saved inheritance");
        currentProgram.setImageBase(currentProgram.getImageBase().add(0x200000), true);
        var after = GhidraInheritanceBindings.read(currentProgram, monitor, this::println);
        if (!before.equals(after)) throw new AssertionError("rebase changed saved inheritance");
        println("inheritance-rebase=PASS");
    }
}
