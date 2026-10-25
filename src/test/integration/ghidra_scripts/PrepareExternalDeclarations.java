// Curated external declarations have no address in the caller's image.
// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraTypeGraph;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

public class PrepareExternalDeclarations extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 4 || !(args[0].equals("curate") || args[0].equals("reopen"))) {
            throw new IllegalArgumentException("curate|reopen main-address global-address output required");
        }
        Function main = getFunctionAt(toAddr(Long.decode(args[1])));
        if (main == null) {
            throw new IllegalStateException("main was not analyzed");
        }
        var manager = currentProgram.getDataTypeManager();
        var integer = new IntegerDataType(manager);
        var longInteger = new LongDataType(manager);
        if (args[0].equals("curate")) {
            main.setName("recovered_main", SourceType.USER_DEFINED);
            main.setReturnType(integer, SourceType.USER_DEFINED);
            main.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                true, SourceType.USER_DEFINED);
            var functions = currentProgram.getFunctionManager().getExternalFunctions();
            Function imported = null;
            while (functions.hasNext()) {
                Function function = functions.next();
                if (function.getName().equals("imported_adjust")) {
                    if (imported != null) {
                        throw new IllegalStateException("ambiguous imported function");
                    }
                    imported = function;
                }
            }
            if (imported == null) {
                throw new IllegalStateException("imported function was not recovered");
            }
            imported.setReturnType(longInteger, SourceType.USER_DEFINED);
            imported.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                true, SourceType.USER_DEFINED,
                new ParameterImpl("value", integer, currentProgram, SourceType.USER_DEFINED));
            Function unused = currentProgram.getExternalManager().addExtFunction(
                "analyst_library", "never_called", null, SourceType.USER_DEFINED).getFunction();
            unused.setReturnType(integer, SourceType.USER_DEFINED);
            unused.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                true, SourceType.USER_DEFINED,
                new ParameterImpl("cookie", new PointerDataType(VoidDataType.dataType, manager),
                    currentProgram, SourceType.USER_DEFINED));
            unused.setVarArgs(true);
            unused.setNoReturn(true);
            currentProgram.getExternalManager().addExtFunction(
                "analyst_library", "unknown_signature", null, SourceType.USER_DEFINED);
            var global = toAddr(Long.decode(args[2]));
            DataUtilities.createData(currentProgram, global, longInteger, longInteger.getLength(),
                DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
            currentProgram.getSymbolTable().createLabel(global, "observed_result", SourceType.USER_DEFINED).setPrimary();
        }
        var model = GhidraTypeGraph.extract(currentProgram,
            List.of(new FunctionSymbol(main.getName(), main.getEntryPoint().getOffset(),
                main.getBody().getNumAddresses())), "x86_64", 0, monitor, this::println);
        var result = new LinkedHashMap<String, Object>();
        result.put("phase", args[0]);
        result.put("javaVersion", System.getProperty("java.version"));
        result.put("exporterOrigin", GhidraTypeGraph.class.getProtectionDomain().getCodeSource().getLocation().toExternalForm());
        result.put("model", model);
        var external = new ArrayList<Object>();
        var iterator = currentProgram.getFunctionManager().getExternalFunctions();
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Function function = iterator.next();
            var row = new LinkedHashMap<String, Object>();
            row.put("name", function.getName(true));
            row.put("source", function.getSignatureSource().name());
            row.put("externalAddress", function.getEntryPoint().isExternalAddress());
            row.put("references", function.getSymbol().getReferenceCount());
            external.add(row);
        }
        result.put("externals", external);
        Files.writeString(Path.of(args[3]), new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(result) + "\n",
            StandardOpenOption.CREATE_NEW);
        println("EXTERNAL_DECLARATIONS " + args[0]);
    }
}
