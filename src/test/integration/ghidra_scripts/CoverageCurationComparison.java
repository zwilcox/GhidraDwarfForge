// Export actual before/rebase/curation/rename states without persisting fixture edits.
// @category DWARF.Tests

import com.google.gson.JsonParser;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraImageBase;
import ghidradwarfforge.GhidraLexicalScopes;
import java.nio.file.Files;
import java.nio.file.Path;

public class CoverageCurationComparison extends GhidraScript {
    @Override
    protected void run() throws Exception {
        var args = getScriptArgs();
        if (args.length != 3) throw new IllegalArgumentException("input labels new-output-directory");
        var input = Path.of(args[0]);
        var labels = JsonParser.parseString(Files.readString(Path.of(args[1]))).getAsJsonObject();
        var output = Files.createDirectory(Path.of(args[2]));
        export(input, output, "before");
        long originalBase = GhidraImageBase.originalImageBase(currentProgram);
        currentProgram.setImageBase(currentProgram.getImageBase().add(0x1000000), true);
        export(input, output, "rebased");
        long delta = currentProgram.getImageBase().getOffset() - originalBase;
        var function = getFunctionAt(toAddr(labels.get("scoped").getAsLong() + delta));
        if (function == null) throw new AssertionError("rebased function missing");
        var snapshot = GhidraLexicalScopes.read(function, monitor, message -> { throw new AssertionError(message); }).orElseThrow();
        var inner = snapshot.locals().stream().filter(local -> local.block().equals("inner")).findFirst().orElseThrow();
        var use = toAddr(labels.get("inner_live").getAsLong() + delta);
        var instruction = getInstructionAt(use);
        if (instruction == null || java.util.Arrays.stream(instruction.getPcode()).anyMatch(op -> op.getOpcode() == PcodeOp.STORE)) {
            throw new AssertionError("curation fixture requires a decoded use, not a stack definition");
        }
        // A saved use at a non-definition instruction cannot prove initialization.
        // Lexical visibility is explicitly retained and must not shrink with storage.
        ((ghidra.program.model.listing.LocalVariable) inner.variable()).setFirstUseOffset(Math.toIntExact(use.subtract(function.getEntryPoint())));
        GhidraLexicalScopes.save(function, snapshot.evidence(), snapshot.blocks(), snapshot.locals(), monitor);
        export(input, output, "curated");
        inner.variable().setName("edited_inner", SourceType.USER_DEFINED);
        GhidraLexicalScopes.save(function, snapshot.evidence(), snapshot.blocks(), snapshot.locals(), monitor);
        export(input, output, "renamed");
        println("coverage-curation-export=PASS phases=4");
    }

    private void export(Path input, Path root, String phase) throws Exception {
        runScript("GhidraDwarfForge.java", new String[] {"--packaged-natives", "--input=" + input,
            "--output=" + root.resolve(phase + ".dbg")});
    }
}
