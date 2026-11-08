// Exercise genuine native failures against the saved annotation fixture.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.CommentType;
import ghidra.util.task.TaskMonitorAdapter;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParser;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

public class VerifyAnalystAnnotationFailures extends GhidraScript {
    private static Map<String, Object> observation(DecompileResults result) {
        var row = new LinkedHashMap<String, Object>();
        row.put("completed", result.decompileCompleted());
        row.put("cancelled", result.isCancelled());
        row.put("error", result.getErrorMessage());
        row.put("source", result.getDecompiledFunction() == null ? null : result.getDecompiledFunction().getC());
        row.put("hasMarkup", result.getCCodeMarkup() != null);
        return row;
    }

    @Override
    protected void run() throws Exception {
        var args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("labels.json observations.json");
        var labels = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
        long delta = Math.subtractExact(currentProgram.getImageBase().getOffset(),
            labels.getAsJsonObject("_imageBase").get("address").getAsLong());
        var entry = toAddr(Math.addExact(labels.getAsJsonObject("annotation_failure").get("address").getAsLong(), delta));
        var function = getFunctionAt(entry);
        if (function == null || !function.getName().equals("annotation_failure")) {
            throw new AssertionError("saved failure fixture missing");
        }
        var rows = new LinkedHashMap<String, Object>();
        var normal = new DecompInterface();
        var limited = new DecompInterface();
        try {
            if (!normal.openProgram(currentProgram)) throw new AssertionError(normal.getLastMessage());
            var before = normal.decompileFunction(function, 30, monitor);
            if (!before.decompileCompleted() || before.getDecompiledFunction() == null) {
                throw new AssertionError("normal reference did not produce source");
            }
            rows.put("normalBefore", observation(before));
            var options = new DecompileOptions();
            options.setMaxInstructions(1);
            if (!limited.setOptions(options) || !limited.openProgram(currentProgram)) {
                throw new AssertionError("cannot configure native instruction limit");
            }
            var failed = limited.decompileFunction(function, 30, monitor);
            if (failed.decompileCompleted() || failed.isCancelled() || failed.getDecompiledFunction() != null ||
                    failed.getCCodeMarkup() != null || !failed.getErrorMessage().contains("maximum allowable instructions")) {
                throw new AssertionError("not the expected genuine instruction-limit failure: " + failed.getErrorMessage());
            }
            rows.put("instructionLimit", observation(failed));
            if (!limited.setOptions(new DecompileOptions())) throw new AssertionError("cannot restore native options");
            limited.flushCache();
            var recovered = limited.decompileFunction(function, 30, monitor);
            if (!observation(before).equals(observation(recovered))) {
                throw new AssertionError("failed native interface did not recover after restoring its instruction budget");
            }
            rows.put("normalAfterFailure", observation(recovered));
            var comments = new LinkedHashMap<String, String>();
            for (var category : CommentType.values()) {
                var text = currentProgram.getListing().getComment(category, entry);
                if (text == null || !text.startsWith("FORGE_ANNOTATION:failed-function:" + category + " ")) {
                    throw new AssertionError("failed-function annotation missing: " + category);
                }
                comments.put(category.toString(), text);
            }
            rows.put("failedFunctionComments", comments);
            var cancelled = new TaskMonitorAdapter(true);
            cancelled.cancel();
            if (!cancelled.isCancelled()) throw new AssertionError("inactive cancellation control");
            normal.flushCache();
            var stopped = normal.decompileFunction(function, 30, cancelled);
            if (!stopped.isCancelled() || stopped.decompileCompleted() || stopped.getDecompiledFunction() != null ||
                    stopped.getCCodeMarkup() != null) throw new AssertionError("cancelled native call retained source");
            rows.put("cancelled", observation(stopped));
            var after = normal.decompileFunction(function, 30, monitor);
            if (!observation(before).equals(observation(after))) {
                throw new AssertionError("normal native output changed after failure/cancellation");
            }
            rows.put("normalAfter", observation(after));
        }
        finally {
            limited.dispose();
            normal.dispose();
        }
        Files.writeString(Path.of(args[1]), new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(rows) + "\n");
        println("analyst-annotation-failures=PASS instruction-limit cancellation recovery comments=5");
    }
}
