// Preserve same-name canonical types and record explicit class/layout associations.
// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.AutoParameterType;
import ghidra.program.model.listing.GhidraClass;
import ghidradwarfforge.GhidraClassBindings;
import ghidradwarfforge.GhidraFunctionSymbols;
import ghidradwarfforge.GhidraTypeGraph;
import ghidradwarfforge.GhidraImageBase;

public class PrepareSameNameTypes extends GhidraScript {
    private DataType global(String name) {
        var symbols = currentProgram.getSymbolTable().getAllSymbols(true);
        while (symbols.hasNext()) {
            var symbol = symbols.next();
            if (symbol.getName(true).equals(name)) {
                var data = currentProgram.getListing().getDataAt(symbol.getAddress());
                if (data == null) throw new AssertionError("global has no listing type: " + name);
                return data.getDataType();
            }
        }
        throw new AssertionError("missing global " + name);
    }

    private DataType unwrap(DataType type) {
        while (type instanceof TypeDef alias) type = alias.getBaseDataType();
        return type;
    }

    private Map<String, Object> identity(DataType type) {
        var result = new LinkedHashMap<String, Object>();
        result.put("id", currentProgram.getDataTypeManager().getID(type));
        result.put("uid", type.getUniversalID() == null ? "" : type.getUniversalID().toString());
        result.put("path", type.getPathName());
        result.put("name", type.getName());
        result.put("size", type.getLength());
        result.put("kind", type.getClass().getSimpleName());
        if (type instanceof TypeDef alias) result.put("target", identity(alias.getBaseDataType()));
        return result;
    }

    @Override
    protected void run() throws Exception {
        if (getScriptArgs().length != 3) throw new IllegalArgumentException("inspect|curate|observe output.json target");
        String mode = getScriptArgs()[0];
        long delta = currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram);
        boolean curate = mode.equals("curate");
        var observations = new ArrayList<Object>();
        for (String name : List.of("category_small", "category_large")) {
            var type = global(name);
            var base = unwrap(type);
            if (!(type instanceof TypeDef) || !(base instanceof Structure)) {
                throw new AssertionError("expected compiler typedef/structure for " + name + ": " + identity(type));
            }
            long aliasId = currentProgram.getDataTypeManager().getID(type);
            long baseId = currentProgram.getDataTypeManager().getID(base);
            String category = name.equals("category_small") ? "/AnalystCategories/first" : "/AnalystCategories/second";
            if (curate) {
                type.setCategoryPath(new CategoryPath(category));
                base.setCategoryPath(new CategoryPath(category));
                base.setName("Packet");
                type.setName("Handle");
            }
            if (!mode.equals("inspect") && (!type.getName().equals("Handle") || !base.getName().equals("Packet") ||
                    !type.getCategoryPath().toString().equals(category))) throw new AssertionError("saved rename missing");
            if (currentProgram.getDataTypeManager().getID(type) != aliasId || currentProgram.getDataTypeManager().getID(base) != baseId) {
                throw new AssertionError("category rename replaced canonical identity");
            }
            observations.add(Map.of("variable", name, "type", identity(type)));
        }
        int methods = 0;
        for (var function : currentProgram.getFunctionManager().getFunctions(true)) {
            if (!function.getName().equals("inspect")) continue;
            methods++;
            var owner = (GhidraClass) function.getParentNamespace();
            String namespace = owner.getParentNamespace().getName();
            var actual = unwrap(global(namespace + "::object"));
            var objects = java.util.Arrays.stream(function.getParameters())
                .filter(p -> p.getAutoParameterType() == AutoParameterType.THIS).toList();
            if (objects.size() != 1 || !(objects.get(0).getFormalDataType() instanceof Pointer pointer)) {
                throw new AssertionError("missing automatic object parameter");
            }
            var parameterType = unwrap(pointer.getDataType());
            observations.add(Map.of("function", function.getName(true), "functionId", function.getID(), "entry", function.getEntryPoint().getOffset() - delta,
                "classId", owner.getID(), "layout", identity(actual), "objectParameterType", identity(parameterType)));
            if (!mode.equals("inspect")) {
                if (currentProgram.getDataTypeManager().getID(actual) != currentProgram.getDataTypeManager().getID(parameterType)) {
                    throw new AssertionError("current automatic THIS disagrees with actual global layout: " + function.getName(true));
                }
                if (curate) GhidraClassBindings.save(currentProgram, owner, (Structure) actual,
                    "Fixture analyst confirms the source-built object's exact class/layout identity", monitor);
                if (GhidraClassBindings.read(currentProgram, owner.getID(), monitor, this::println).status() != GhidraClassBindings.Status.VALID) {
                    throw new AssertionError("missing saved class/layout binding");
                }
            }
        }
        if (methods != 2) throw new AssertionError("expected two class methods, found " + methods);
        for (String name : List.of("alpha::object", "beta::object", "alpha::state", "beta::state")) {
            observations.add(Map.of("variable", name, "type", identity(global(name))));
        }
        var diagnostics = new ArrayList<String>();
        var inventory = GhidraFunctionSymbols.extract(currentProgram, monitor, diagnostics::add, delta);
        var model = GhidraTypeGraph.extract(currentProgram, inventory, getScriptArgs()[2], delta, monitor, diagnostics::add);
        Files.writeString(Path.of(getScriptArgs()[1]), new GsonBuilder().setPrettyPrinting().create().toJson(
            Map.of("javaVersion", System.getProperty("java.version"), "observations", observations,
                "model", model, "rebaseDelta", delta, "diagnostics", diagnostics,
                "origin", GhidraTypeGraph.class.getProtectionDomain().getCodeSource().getLocation().toString())) + "\n");
        println("same-name-types-preparation=" + mode + " PASS");
    }
}
