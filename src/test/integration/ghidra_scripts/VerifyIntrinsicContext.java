// Independently observe actual native token operations, including same-spelled ordinary calls.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.pcode.PcodeOp;
import ghidradwarfforge.GhidraSourceContext;
import com.google.gson.GsonBuilder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;

public class VerifyIntrinsicContext extends GhidraScript {
    @Override protected void run() throws Exception {
        var observations = new TreeMap<String, Object>();
        var decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) throw new AssertionError("cannot open native decompiler");
            for (var iterator = currentProgram.getFunctionManager().getFunctions(true); iterator.hasNext();) {
                var function = iterator.next();
                if (!List.of("ordinary_context", "intrinsic_context", "halt_baddata", "cpuid_basic_info").contains(function.getName())) continue;
                var result = decompiler.decompileFunction(function, 60, monitor);
                if (!result.decompileCompleted()) throw new AssertionError(result.getErrorMessage());
                var tokens = new ArrayList<Object>();
                var intrinsicAddresses = new java.util.TreeSet<Long>();
                var calls = new java.util.TreeSet<String>();
                for (var line : DecompilerUtils.toLines(result.getCCodeMarkup())) {
                    for (var token : line.getAllTokens()) {
                        var op = token.getPcodeOp();
                        if (op == null) continue;
                        if (op.getOpcode() == PcodeOp.CALLOTHER) {
                            var address = op.getSeqnum().getTarget();
                            var instruction = currentProgram.getListing().getInstructionAt(address);
                            if (instruction == null || !instruction.getMnemonicString().equalsIgnoreCase("CPUID"))
                                throw new AssertionError("intrinsic token does not identify the fixture's CPUID");
                            intrinsicAddresses.add(address.getOffset());
                        }
                        if (op.getOpcode() == PcodeOp.CALL) calls.add(token.getText());
                        tokens.add(new TreeMap<>(java.util.Map.of("text", token.getText(), "opcode", op.getMnemonic(),
                            "address", op.getSeqnum().getTarget().getOffset(), "line", line.getLineNumber())));
                    }
                }
                if (function.getName().equals("intrinsic_context")) {
                    if (intrinsicAddresses.size() != 1) throw new AssertionError("missing real intrinsic token");
                }
                else if (!intrinsicAddresses.isEmpty()) throw new AssertionError("ordinary function became an intrinsic");
                if (function.getName().equals("ordinary_context") &&
                        !calls.containsAll(List.of("halt_baddata", "cpuid_basic_info")))
                    throw new AssertionError("same-spelled ordinary CALL controls missing: " + calls);
                observations.put(function.getName(), new TreeMap<>(java.util.Map.of("entry", function.getEntryPoint().getOffset(),
                    "intrinsicAddresses", intrinsicAddresses, "tokens", tokens, "source", result.getDecompiledFunction().getC())));
            }
            if (observations.size() != 4) throw new AssertionError("fixture function inventory incomplete");
            observations.put("origin", GhidraSourceContext.class.getProtectionDomain().getCodeSource().getLocation().toString());
            Files.writeString(Path.of(getScriptArgs()[0]), new GsonBuilder().setPrettyPrinting().create().toJson(observations) + "\n");
        }
        finally { decompiler.dispose(); }
        println("intrinsic-context-observation=PASS");
    }
}
