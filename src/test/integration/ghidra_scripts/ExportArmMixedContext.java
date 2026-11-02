// Exercise supported context edits in a disposable, read-only program session.
// @category DWARF.Tests
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.code.InstructionDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.ContextChangeException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public class ExportArmMixedContext extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 4) throw new IllegalArgumentException("link-entry input output control");
        currentProgram.setExecutablePath(Path.of(args[1]).toRealPath().toString());
        var image = ghidradwarfforge.elf.ElfImage.read(Path.of(args[1]));
        long delta = currentProgram.getImageBase().getOffset() - image.preferredImageBase();
        var entry = toAddr(Math.addExact(Long.decode(args[0]), delta));
        var at = entry.add(12);
        var end = at.add(3);
        var function = getFunctionAt(entry);
        var instruction = getInstructionAt(at);
        var mode = currentProgram.getRegister("TMode");
        if (function == null || !function.getName().equals("recovered_mixed_body") ||
                !(instruction instanceof InstructionDB decoded) || instruction.getLength() != 4 ||
                !BigInteger.ZERO.equals(currentProgram.getProgramContext().getValue(mode, at, false)) ||
                !BigInteger.ZERO.equals(decoded.getOriginalPrototypeContext(mode.getBaseRegister())
                    .getRegisterValue(mode).getUnsignedValue())) {
            throw new AssertionError("expected intact split-body ARM instruction");
        }
        byte[] bytes = getBytes(entry, 52);
        String body = function.getBody().toString();
        String text = instruction.toString();
        Path output = Path.of(args[2]);
        if (args[3].equals("mapping") || args[3].equals("function-tag")) {
            runScript("RepeatLiveAbiExport.java", new String[] {output.toString()});
        }
        else if (args[3].equals("context")) {
            runScript("RepeatLiveAbiExport.java", new String[] {output.toString()});
            byte[] accepted = Files.readAllBytes(output);
            byte[] acceptedSource = Files.readAllBytes(Path.of(output + ".c"));
            try {
                currentProgram.getProgramContext().setValue(mode, at, end, BigInteger.ONE);
                throw new AssertionError("Ghidra allowed context edit over a decoded instruction");
            }
            catch (ContextChangeException expected) {
                if (!expected.getMessage().equals("Context register change conflicts with one or more instructions")) {
                    throw expected;
                }
                println("mixed-context-write-rejected=PASS");
            }
            if (getInstructionAt(at).getLength() != 4 ||
                    !BigInteger.ZERO.equals(currentProgram.getProgramContext().getValue(mode, at, false))) {
                throw new AssertionError("rejected write changed the listing");
            }
            // The supported editing sequence removes the instruction first.
            // No proxy, reflection or context-lock override fabricates stale state.
            currentProgram.getListing().clearCodeUnits(at, end, false);
            currentProgram.getProgramContext().setValue(mode, at, end, BigInteger.ONE);
            for (int offset = 0; offset < 4; offset++) {
                var address = at.add(offset);
                if (getInstructionContaining(address) != null ||
                        !BigInteger.ONE.equals(currentProgram.getProgramContext().getValue(mode, address, false))) {
                    throw new AssertionError("context edit did not leave the required undecoded hole");
                }
            }
            runScript("RepeatLiveAbiExport.java", new String[] {output.toString()});
            Files.copy(output, Path.of(output + ".omitted"));
            Files.copy(Path.of(output + ".c"), Path.of(output + ".omitted.c"));
            currentProgram.getProgramContext().setValue(mode, at, end, BigInteger.ZERO);
            if (!new DisassembleCommand(at, new AddressSet(at, end), false).applyTo(currentProgram, monitor) ||
                    getInstructionAt(at).getLength() != 4 || !getInstructionAt(at).toString().equals(text)) {
                throw new AssertionError("original instruction was not restored");
            }
            runScript("RepeatLiveAbiExport.java", new String[] {output.toString()});
            if (!Arrays.equals(accepted, Files.readAllBytes(output)) ||
                    !Arrays.equals(acceptedSource, Files.readAllBytes(Path.of(output + ".c")))) {
                throw new AssertionError("context restoration did not restore deterministic outputs");
            }
            Files.copy(output, Path.of(output + ".restored"));
            Files.copy(Path.of(output + ".c"), Path.of(output + ".restored.c"));
            // Retain the rejected-evidence output for the omission GDB oracle.
            Files.write(output, Files.readAllBytes(Path.of(output + ".omitted")));
            Files.write(Path.of(output + ".c"), Files.readAllBytes(Path.of(output + ".omitted.c")));
            println("mixed-context-restoration=PASS");
        }
        else throw new IllegalArgumentException("unknown mixed mode control");
        if (!Arrays.equals(bytes, getBytes(entry, 52)) || !body.equals(function.getBody().toString())) {
            throw new AssertionError("control changed original bytes or function ranges");
        }
        println("mixed-context-export=PASS control=" + args[3]);
    }
}
