// Exercise the normal entry point with analyst knowledge, rebasing and real staged cancellation.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.WrappingTaskMonitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CancellationException;

public class ProductionUnwindControls extends GhidraScript {
    @Override protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 4) throw new IllegalArgumentException("consumer producer output-directory original-hex-range");
        Path output = Path.of(args[2]).resolve("curated.dbg");
        var function = getGlobalFunctions("cfi_outer").getFirst();
        currentProgram.getListing().setComment(function.getEntryPoint(), CommentType.PLATE, "UNWIND_ANALYST_NOTE λ */ kept");
        var equate = currentProgram.getEquateTable().createEquate("UNWIND_TEST_DEPTH", 3);
        boolean attached = false;
        for (var instructions = currentProgram.getListing().getInstructions(function.getBody(), true); instructions.hasNext() && !attached;) {
            var instruction = instructions.next();
            for (int operand = 0; operand < instruction.getNumOperands() && !attached; operand++) {
                for (var object : instruction.getOpObjects(operand)) {
                    if (object instanceof Scalar scalar && scalar.getValue() == 3) {
                        equate.addReference(instruction.getAddress(), operand); attached = true; break;
                    }
                }
            }
        }
        if (!attached) throw new AssertionError("no independent scalar-three operand in outer fixture");
        String[] options = {"--libdwarf=" + args[0], "--libdwarfp=" + args[1], "--output=" + output,
            "--synthesize-unwind=conditioned", "--unwind-stack-separation=" + args[3],
            "--unwind-relocated-pointers=fixed", "--gdb-loader", "--source-context=both"};
        List<Path> generation = List.of(output, Path.of(output + ".c"), Path.of(output + ".unwind.json"), Path.of(output + ".gdb.py"));
        runScript("GhidraDwarfForge.java", options);
        String source = Files.readString(generation.get(1));
        if (!source.contains("UNWIND_ANALYST_NOTE") || !source.contains("UNWIND_TEST_DEPTH")) throw new AssertionError("curated source lost knowledge");
        var original = new java.util.ArrayList<byte[]>();
        for (Path path : generation) original.add(Files.readAllBytes(path));
        long modification = currentProgram.getModificationNumber();
        for (String stage : List.of("ghidradwarfforge.unwind.GhidraUnwindRecovery", "ghidradwarfforge.dwarf.DwarfDebugFrame",
                "ghidradwarfforge.output.UnwindEvidenceJson", "ghidradwarfforge.elf.GdbCompanion")) {
            for (boolean failure : List.of(false, true)) {
                TaskMonitor saved = monitor;
                int[] polls = {0};
                monitor = new WrappingTaskMonitor(saved) {
                    @Override public synchronized boolean isCancelled() {
                        if (super.isCancelled()) return true;
                        if (polls[0] >= 5) return !failure;
                        if (StackWalker.getInstance().walk(frames -> frames.anyMatch(frame -> frame.getClassName().equals(stage))) && ++polls[0] == 5) {
                            if (failure) throw new InjectedFailure();
                            return true;
                        }
                        return false;
                    }
                    @Override public void checkCancelled() throws CancelledException {
                        if (isCancelled()) throw new CancelledException();
                    }
                };
                boolean caught = false;
                try { runScript("GhidraDwarfForge.java", options); }
                catch (CancelledException | CancellationException expected) { if (failure) throw expected; caught = true; }
                catch (InjectedFailure expected) { if (!failure) throw expected; caught = true; }
                finally { monitor = saved; }
                if (!caught || polls[0] != 5) throw new AssertionError("production control did not reach " + stage);
                requireSame(generation, original);
                if (modification != currentProgram.getModificationNumber()) throw new AssertionError("export changed curated program");
                try (var files = Files.list(output.getParent())) {
                    if (files.anyMatch(path -> path.getFileName().toString().startsWith(".forge-"))) throw new AssertionError("production cancellation leaked staging");
                }
                println("production-unwind-control=PASS stage=" + stage + " failure=" + failure);
            }
        }
        runScript("GhidraDwarfForge.java", options);
        requireSame(generation, original);
        currentProgram.setImageBase(currentProgram.getImageBase().add(0x400000), true);
        options[2] = "--output=" + Path.of(args[2]).resolve("rebased.dbg");
        runScript("GhidraDwarfForge.java", options);
        println("production-unwind-controls=PASS controls=8 exports=3");
    }

    private static void requireSame(List<Path> paths, List<byte[]> expected) throws Exception {
        for (int index = 0; index < paths.size(); index++) {
            if (!Arrays.equals(expected.get(index), Files.readAllBytes(paths.get(index)))) throw new AssertionError("production generation changed");
        }
    }
    private static final class InjectedFailure extends IllegalStateException {
        InjectedFailure() { super("controlled production unwind failure"); }
    }
}
