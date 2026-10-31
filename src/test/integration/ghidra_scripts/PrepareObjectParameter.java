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
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.listing.GhidraClass;
import ghidradwarfforge.GhidraClassBindings;

public class PrepareObjectParameter extends GhidraScript {
    @Override
    protected void run() throws Exception {
        boolean explicitBinding = getScriptArgs().length > 1 && getScriptArgs()[1].equals("explicit");
        String control = getScriptArgs().length > 1 ? getScriptArgs()[1] : "inferred";
        boolean invalidBinding = control.equals("stale") || control.equals("conflict");
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
                if (explicitBinding || invalidBinding) {
                    if (!(function.getParentNamespace() instanceof GhidraClass owner) ||
                            !(object.getFormalDataType() instanceof Pointer pointer) ||
                            !(pointer.getDataType() instanceof Structure layout)) {
                        throw new AssertionError("missing current class/layout identity");
                    }
                    Structure bound = layout;
                    if (invalidBinding) {
                        var unrelated = new StructureDataType(new CategoryPath("/ForgeControls"), "UnrelatedLayout", 0);
                        unrelated.add(IntegerDataType.dataType, "first", null);
                        unrelated.add(IntegerDataType.dataType, "second", null);
                        bound = (Structure) currentProgram.getDataTypeManager().addDataType(unrelated,
                            DataTypeConflictHandler.DEFAULT_HANDLER);
                    }
                    GhidraClassBindings.save(currentProgram, owner, bound,
                        "Fixture analyst confirms the compiler object layout", monitor);
                    if (control.equals("stale")) {
                        if (!currentProgram.getDataTypeManager().remove(bound, monitor)) {
                            throw new AssertionError("could not retire saved type identity");
                        }
                    }
                    var saved = GhidraClassBindings.read(currentProgram, owner.getID(), monitor, this::println);
                    var expectedStatus = control.equals("stale") ? GhidraClassBindings.Status.REJECTED :
                        GhidraClassBindings.Status.VALID;
                    if (saved.status() != expectedStatus || (saved.binding() != null && saved.binding().type() != bound)) {
                        throw new AssertionError("explicit class identity did not persist");
                    }
                    if (((Pointer) object.getFormalDataType()).getDataType() != layout) {
                        throw new AssertionError("negative binding changed the current parameter type");
                    }
                    evidence.add(Map.of("classId", owner.getID(), "control", control,
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
                "explicitBinding", explicitBinding, "bindingControl", invalidBinding ? control : "none")) + "\n");
        println("object-parameter-preparation=PASS");
    }
}
