// Check imported object semantics and add a parameter-name negative control.
// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Map;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.AutoParameterType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.GhidraClass;
import ghidradwarfforge.GhidraClassBindings;

public class PrepareObjectParameter extends GhidraScript {
    @Override
    protected void run() throws Exception {
        boolean explicitBinding = getScriptArgs().length > 1 && getScriptArgs()[1].equals("explicit");
        var evidence = new ArrayList<Object>();
        int methods = 0;
        int ordinary = 0;
        for (var function : currentProgram.getFunctionManager().getFunctions(true)) {
            monitor.checkCancelled();
            if (function.getName().equals("inspect_object")) {
                methods++;
                var objects = java.util.Arrays.stream(function.getParameters())
                    .filter(p -> p.getAutoParameterType() == AutoParameterType.THIS).toList();
                if (objects.size() != 1 || !objects.get(0).isAutoParameter()) {
                    throw new AssertionError("missing unique imported THIS parameter");
                }
                var object = objects.get(0);
                if (explicitBinding) {
                    if (!(function.getParentNamespace() instanceof GhidraClass owner) ||
                            !(object.getFormalDataType() instanceof Pointer pointer) ||
                            !(pointer.getDataType() instanceof Structure layout)) {
                        throw new AssertionError("missing current class/layout identity");
                    }
                    GhidraClassBindings.save(currentProgram, owner, layout,
                        "Fixture analyst confirms the compiler object layout", monitor);
                    var saved = GhidraClassBindings.read(currentProgram, owner.getID(), monitor, this::println);
                    if (saved.status() != GhidraClassBindings.Status.VALID || saved.binding().type() != layout) {
                        throw new AssertionError("explicit class identity did not persist");
                    }
                    evidence.add(Map.of("classId", owner.getID(), "typeId", saved.binding().typeId(),
                        "binding", saved.status().name()));
                }
                evidence.add(Map.of("function", function.getName(true), "parameter", object.getName(),
                    "type", object.getFormalDataType().getPathName(), "auto", object.getAutoParameterType().name(),
                    "hasSymbol", object.getSymbol() != null));
            }
            if (function.getName().equals("ordinary_object")) {
                ordinary++;
                if (function.getParameterCount() != 1 || function.getParameter(0).isAutoParameter()) {
                    throw new AssertionError("unexpected ordinary signature");
                }
                function.getParameter(0).setName("this", SourceType.USER_DEFINED);
                evidence.add(Map.of("function", function.getName(true), "parameter", "this", "auto", "NONE"));
            }
        }
        if (methods != 1 || ordinary != 1) {
            throw new AssertionError("fixture functions missing");
        }
        Files.writeString(Path.of(getScriptArgs()[0]), new GsonBuilder().setPrettyPrinting().create()
            .toJson(Map.of("javaVersion", System.getProperty("java.version"), "parameters", evidence,
                "explicitBinding", explicitBinding)) + "\n");
        println("object-parameter-preparation=PASS");
    }
}
