package ghidradwarfforge.output;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/** Real selected checker, production supervision/parser/binding, explicitly limited test host. */
public final class StrictDwarfCheckProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 8) throw new IllegalArgumentException(
            "report original sidecar source helper raw-checker configuration existing-result-directory");
        var host = new AttachmentReceiptStoreSmoke.Host();
        var binding = AttachmentExportBinding.observe(Path.of(args[0]), Path.of(args[1]), Path.of(args[2]),
            Path.of(args[3]), host, () -> false);
        var result = StrictDwarfCheck.run(binding, host, new ValidatorSupervisor(Path.of(args[4])),
            Path.of(args[5]), Path.of(args[6]), Path.of(args[7]), () -> false);
        var json = new JsonObject();
        json.addProperty("status", "PASS");
        json.addProperty("scope", "strict-check-component; test-only host; not attachment approval");
        var inputs = new JsonObject();
        for (var entry : binding.files().entrySet()) {
            var input = new JsonObject();
            input.addProperty("path", entry.getValue().path().toString());
            input.addProperty("sha256", entry.getValue().digest().sha256());
            inputs.add(entry.getKey(), input);
        }
        json.add("inputs", inputs);
        json.addProperty("configuration", result.configuration().path().toString());
        json.addProperty("configurationSha256", result.configuration().digest().sha256());
        json.add("sidecarCheck", run(result.sidecar()));
        if (result.original() != null) json.add("originalCheck", run(result.original()));
        var diagnostics = new JsonArray();
        result.corroboratedDiagnostics().forEach(diagnostics::add);
        json.add("corroboratedDiagnostics", diagnostics);
        if (result.inheritedFrame() != null) {
            var frame = new JsonObject();
            frame.addProperty("address", result.inheritedFrame().address());
            frame.addProperty("bytes", result.inheritedFrame().bytes());
            frame.addProperty("sha256", result.inheritedFrame().sha256());
            frame.addProperty("originalOffset", result.inheritedFrame().originalOffset());
            frame.addProperty("fromProgramHeaders", result.inheritedFrame().fromProgramHeaders());
            json.add("frame", frame);
        }
        if (result.originalView() != null) {
            var view = new JsonObject();
            view.addProperty("path", result.originalView().path().toString());
            view.addProperty("sha256", result.originalView().digest().sha256());
            json.add("originalFrameView", view);
        }
        Files.writeString(Path.of(args[7]).resolve("result.json"), json + "\n", StandardOpenOption.CREATE_NEW);
        System.out.println("strict-dwarf-check=PASS corroborated-diagnostics=" + result.corroboratedDiagnostics().size());
    }

    private static JsonObject run(ValidatorSupervisor.Evidence evidence) {
        var result = new JsonObject();
        result.addProperty("directory", evidence.directory().toString());
        result.addProperty("toolSha256", evidence.toolSha256());
        result.addProperty("helperSha256", evidence.helperSha256());
        result.addProperty("stdoutSha256", evidence.stdoutDigest().sha256());
        result.addProperty("stderrSha256", evidence.stderrDigest().sha256());
        var command = new JsonArray();
        evidence.command().forEach(command::add);
        result.add("command", command);
        return result;
    }
}
