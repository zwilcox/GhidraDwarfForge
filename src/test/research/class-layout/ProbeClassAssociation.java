// Research only: show why an automatic THIS type is not a saved class/type key.
// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Map;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.AutoParameterType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class ProbeClassAssociation extends GhidraScript {
    private Map<String, Object> observe(Function method, String phase) throws Exception {
        // Recompute automatic storage instead of reading a cached earlier type.
        method.setCallingConvention("default");
        method.setCallingConvention("__thiscall");
        var objects = java.util.Arrays.stream(method.getParameters())
            .filter(p -> p.getAutoParameterType() == AutoParameterType.THIS).toList();
        if (objects.size() != 1 || !(objects.get(0).getFormalDataType() instanceof Pointer pointer)) {
            throw new AssertionError("missing automatic THIS pointer");
        }
        var target = pointer.getDataType();
        return Map.of("phase", phase, "functionId", method.getID(),
            "classId", method.getParentNamespace().getID(), "typePath", target.getPathName(),
            "typeId", currentProgram.getDataTypeManager().getID(target),
            "length", target.getLength(), "description", target.getDescription());
    }

    @Override
    protected void run() throws Exception {
        Function method = null;
        for (var function : currentProgram.getFunctionManager().getFunctions(true)) {
            if (function.getName().equals("ordinary_object")) method = function;
        }
        if (method == null) throw new AssertionError("fixture function absent");
        var observations = new ArrayList<Map<String, Object>>();
        var owner = currentProgram.getSymbolTable().createClass(currentProgram.getGlobalNamespace(),
            "AssociationProbe", SourceType.USER_DEFINED);
        method.setParentNamespace(owner);
        currentProgram.setPreferredRootNamespaceCategoryPath("/probe_missing");
        observations.add(observe(method, "placeholder"));
        var manager = currentProgram.getDataTypeManager();
        for (String category : java.util.List.of("/probe_a", "/probe_b")) {
            var structure = new StructureDataType(new CategoryPath(category), "AssociationProbe", 0);
            structure.add(IntegerDataType.dataType, "decoy", "unrelated research type");
            if (category.equals("/probe_b")) structure.add(IntegerDataType.dataType, "extra", "distinct identity");
            manager.addDataType(structure, DataTypeConflictHandler.DEFAULT_HANDLER);
        }
        for (String category : java.util.List.of("/probe_a", "/probe_b", "/probe_a")) {
            currentProgram.setPreferredRootNamespaceCategoryPath(category);
            observations.add(observe(method, category));
        }
        long functionId = method.getID();
        if (observations.stream().anyMatch(row -> !row.get("functionId").equals(functionId) ||
                !row.get("classId").equals(owner.getID()))) throw new AssertionError("owner identities changed");
        if (!observations.get(1).get("typePath").equals("/probe_a/AssociationProbe") ||
                !observations.get(2).get("typePath").equals("/probe_b/AssociationProbe") ||
                !observations.get(3).get("typeId").equals(observations.get(1).get("typeId")) ||
                observations.get(1).get("typeId").equals(observations.get(2).get("typeId"))) {
            throw new AssertionError("expected preference-driven type selection");
        }
        if (!observations.get(0).get("description").equals("PlaceHolder Class Structure")) {
            throw new AssertionError("missing generated placeholder");
        }
        Files.writeString(Path.of(getScriptArgs()[0]), new GsonBuilder().setPrettyPrinting().create()
            .toJson(Map.of("javaVersion", System.getProperty("java.version"), "observations", observations)) + "\n");
        println("class-association-probe=PASS");
    }
}
