// Curate source-known code after importing deliberately contradictory ELF symbols.
// @category DWARF.Tests
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.symbol.SourceType;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;

public class PrepareArmMixedConflict extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3 || !args[2].equals("split")) {
            throw new IllegalArgumentException("link-entry rebase split");
        }
        var image = ghidradwarfforge.elf.ElfImage.read(Path.of(currentProgram.getExecutablePath()));
        long delta = currentProgram.getImageBase().getOffset() - image.preferredImageBase();
        var entry = toAddr(Math.addExact(Long.decode(args[0]), delta));
        String expected = "000000eacefaedfe030080e204308fe2013083e213ff2fe1" +
            "053000bf00a31847070080e204209fe5020080e01eff2fe134120000";
        if (!HexFormat.of().formatHex(getBytes(entry, 52)).equals(expected)) {
            throw new AssertionError("conflicting-symbol fixture instruction bytes changed");
        }
        var extent = new AddressSet(entry, entry.add(51));
        var functions = currentProgram.getFunctionManager().getFunctions(extent, true);
        var remove = new ArrayList<ghidra.program.model.address.Address>();
        while (functions.hasNext()) remove.add(functions.next().getEntryPoint());
        for (var at : remove) currentProgram.getFunctionManager().removeFunction(at);
        currentProgram.getListing().clearCodeUnits(entry, entry.add(51), false);
        int[] offsets = {0, 8, 12, 16, 20, 24, 26, 28, 30, 32, 36, 40, 44};
        for (int offset : offsets) {
            var at = entry.add(offset);
            boolean thumb = offset >= 24 && offset < 32;
            int length = thumb ? 2 : 4;
            var end = at.add(length - 1);
            currentProgram.getProgramContext().setValue(currentProgram.getRegister("TMode"),
                at, end, thumb ? BigInteger.ONE : BigInteger.ZERO);
            if (!new DisassembleCommand(at, new AddressSet(at, end), false).applyTo(currentProgram, monitor) ||
                    getInstructionAt(at) == null || getInstructionAt(at).getLength() != length) {
                throw new AssertionError("source-known instruction failed to decode at " + at);
            }
        }
        createData(entry.add(4), UnsignedIntegerDataType.dataType);
        createData(entry.add(48), UnsignedIntegerDataType.dataType);
        currentProgram.getFunctionManager().createFunction("mixed_body", entry,
            new AddressSet(entry, entry.add(3)), SourceType.USER_DEFINED);
        // The ordinary preparation script independently checks the resulting
        // instruction widths/modes and constructs the two explicit body ranges.
        runScript("PrepareArmMixedBody.java", args);
        println("mixed-conflict-curation=PASS");
    }
}
