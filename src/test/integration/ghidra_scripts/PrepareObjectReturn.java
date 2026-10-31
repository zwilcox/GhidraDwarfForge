// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.AutoParameterType;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraClassBindings;
import ghidradwarfforge.GhidraFunctionSymbols;
import ghidradwarfforge.GhidraTypeGraph;
import ghidradwarfforge.GhidraImageBase;

public class PrepareObjectReturn extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (getScriptArgs().length != 3 || !java.util.Set.of("curate", "observe").contains(getScriptArgs()[0])) {
            throw new IllegalArgumentException("curate|observe output.json target");
        }
        boolean curate = getScriptArgs()[0].equals("curate");
        var functions = new ArrayList<Object>();
        for (var f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (!f.getName().equals("inspect_result") && !f.getName().equals("ordinary_roles")) continue;
            if (f.getName().equals("ordinary_roles")) {
                if (f.getParameterCount() != 3 || java.util.Arrays.stream(f.getParameters()).anyMatch(p -> p.isAutoParameter())) {
                    throw new AssertionError("ordinary parameters acquired automatic identity");
                }
                if (curate) {
                    f.getParameter(0).setName("this", SourceType.USER_DEFINED);
                    f.getParameter(1).setName("__return_storage_ptr__", SourceType.USER_DEFINED);
                }
                if (!f.getParameter(0).getName().equals("this") || !f.getParameter(1).getName().equals("__return_storage_ptr__")) {
                    throw new AssertionError("analyst names did not persist");
                }
            }
            else {
                var parameters = java.util.Arrays.asList(f.getParameters());
                var objects = parameters.stream().filter(p -> p.getAutoParameterType() == AutoParameterType.THIS).toList();
                var returns = parameters.stream().filter(p -> p.getAutoParameterType() == AutoParameterType.RETURN_STORAGE_PTR).toList();
                if (objects.size() != 1 || returns.size() != 1 || f.getParameterCount() != 3) {
                    throw new AssertionError("method lacks distinct THIS and return carrier");
                }
                var object = objects.getFirst();
                var carrier = returns.getFirst();
                if (!(object.getFormalDataType() instanceof Pointer objectPointer) ||
                        !(objectPointer.getDataType() instanceof Structure layout) ||
                        !(carrier.getFormalDataType() instanceof Pointer resultPointer) ||
                        resultPointer.getDataType() != f.getReturn().getFormalDataType() || layout.getLength() != 8 ||
                        f.getReturn().getFormalDataType().getLength() != 24) {
                    throw new AssertionError("automatic identities disagree with exact formal types");
                }
                var owner = (GhidraClass) f.getParentNamespace();
                if (curate) GhidraClassBindings.save(currentProgram, owner, layout,
                    "Fixture analyst confirms the method object layout", monitor);
                if (GhidraClassBindings.read(currentProgram, owner.getID(), monitor, this::println).status() != GhidraClassBindings.Status.VALID) {
                    throw new AssertionError("class binding not retained");
                }
            }
            var row = new LinkedHashMap<String, Object>();
            row.put("name", f.getName(true));
            row.put("return", f.getReturn().getFormalDataType().getPathName());
            row.put("convention", f.getCallingConventionName());
            row.put("custom", f.hasCustomVariableStorage());
            var parameters = new ArrayList<Object>();
            for (var p : f.getParameters()) {
                var item = new LinkedHashMap<String, Object>();
                item.put("name", p.getName());
                item.put("type", p.getFormalDataType().getPathName());
                item.put("auto", p.isAutoParameter());
                item.put("kind", p.getAutoParameterType());
                item.put("storage", p.getVariableStorage().toString());
                parameters.add(item);
            }
            row.put("parameters", parameters);
            functions.add(row);
        }
        if (functions.size() != 2) throw new AssertionError("missing fixture functions");
        long delta = currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram);
        var diagnostics = new ArrayList<String>();
        var inventory = GhidraFunctionSymbols.extract(currentProgram, monitor, diagnostics::add, delta);
        var model = GhidraTypeGraph.extract(currentProgram, inventory, getScriptArgs()[2], delta, monitor, diagnostics::add);
        Files.writeString(Path.of(getScriptArgs()[1]), new GsonBuilder().setPrettyPrinting().create().toJson(
            java.util.Map.of("observations", functions, "model", model, "diagnostics", diagnostics, "rebaseDelta", delta,
                "javaVersion", System.getProperty("java.version"),
                "origin", GhidraTypeGraph.class.getProtectionDomain().getCodeSource().getLocation().toString())) + "\n");
        println("object-return-preparation=PASS");
    }
}
