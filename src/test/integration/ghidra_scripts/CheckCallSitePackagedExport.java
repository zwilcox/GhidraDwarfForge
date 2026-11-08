// Exercise the installed production script with explicit fixture-only analyst curation.
// @category DWARF.Tests
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.framework.data.DefaultProjectData;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.ProjectLocator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.AddressNormalizer;
import ghidradwarfforge.GhidraImageBase;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter;
import ghidradwarfforge.nativeapi.PackagedNativeLibraries;
import ghidradwarfforge.output.FileDigests;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class CheckCallSitePackagedExport extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 5) throw new IllegalArgumentException("input new-output-directory rebase-shift expected-module saved-project-parent");
        if (currentProgram != null) throw new AssertionError("fixture must open its own read-only project view");
        var project = new DefaultProjectData(new ProjectLocator(args[4], "Calls"), false, false);
        try {
            var file = Objects.requireNonNull(project.getFile("/input"));
            if (file.isInWritableProject()) throw new AssertionError("fixture project must be read-only");
            var program = (Program) file.getReadOnlyDomainObject(this, DomainFile.DEFAULT_VERSION, monitor);
            try {
                currentProgram = program;
                checkPackaged(args);
            }
            finally {
                currentProgram = null;
                state.setCurrentProgram(null);
                program.release(this);
            }
        }
        finally { project.close(); }
    }

    private void checkPackaged(String[] args) throws Exception {
        Path input = Path.of(args[0]).toRealPath(), output = Path.of(args[1]).toAbsolutePath();
        Path expectedModule = Path.of(args[3]).toRealPath();
        Path module = Application.getModuleRootDir("GhidraDwarfForge").getFile(false).toPath().toRealPath();
        Path origin = Path.of(MinimalDwarfSidecarExporter.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();
        if (!module.equals(expectedModule) || !origin.equals(module.resolve("lib/GhidraDwarfForge.jar").toRealPath())) {
            throw new AssertionError("exporter did not load from the expected installed JAR");
        }
        var libraries = PackagedNativeLibraries.resolve();
        var elf = ElfImage.read(input);
        if (elf.machine() != 62 && elf.machine() != 183) throw new AssertionError("unexpected fixture target");
        Files.createDirectory(output);
        String originalHash = hash(input);
        int transaction = currentProgram.startTransaction("temporary packaged call-site fixture curation");
        try {
            long shift = Long.decode(args[2]);
            if (shift != 0) currentProgram.setImageBase(currentProgram.getImageBase().add(shift), true);
            long delta = AddressNormalizer.rebaseDelta(currentProgram.getImageBase().getOffset(),
                GhidraImageBase.originalImageBase(currentProgram));
            if (elf.machine() == 62) correctDriverBody();
            var curated = new ArrayList<Object>();
            var namedThunks = new ArrayList<String>();
            for (var function : currentProgram.getFunctionManager().getFunctions(true)) {
                monitor.checkCancelled();
                if (!function.getName().startsWith("cs_")) continue;
                if (function.isThunk()) {
                    // Normal extraction intentionally requires an explicit analyst
                    // name for a memory thunk. Do not bypass that product policy.
                    String name = function.getName();
                    if (!List.of("cs_forward", "cs_indirect").contains(name)) throw new AssertionError("unexpected fixture thunk");
                    // Ghidra 12.0.3 returns early when setName receives the
                    // unchanged name; explicitly adopt the existing name.
                    function.getSymbol().setSource(SourceType.USER_DEFINED);
                    namedThunks.add(name);
                }
                if (!function.getName().equals("cs_checkpoint")) {
                    var parameters = new ArrayList<Parameter>();
                    parameters.add(new ParameterImpl(function.getName().equals("cs_driver") ? "scenario" : "value",
                        IntegerDataType.dataType, currentProgram));
                    if (List.of("cs_recursive", "cs_tail_recursive").contains(function.getName())) {
                        parameters.add(new ParameterImpl("depth", IntegerDataType.dataType, currentProgram));
                    }
                    function.replaceParameters(parameters, Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        true, SourceType.USER_DEFINED);
                }
                var ranges = new ArrayList<Object>();
                for (var range : function.getBody()) ranges.add(Map.of("first", range.getMinAddress().toString(),
                    "last", range.getMaxAddress().toString()));
                curated.add(Map.of("name", function.getName(), "entry", function.getEntryPoint().toString(),
                    "body", ranges, "nameSource", function.getSymbol().getSource().name(),
                    "signatureSource", function.getSignatureSource().name()));
            }
            if (curated.size() != 13 || namedThunks.size() != 2) throw new AssertionError("incomplete call-site fixture curation");
            Path sidecar = output.resolve("input.dbg"), source = output.resolve("input.dbg.c");
            export(input, sidecar);
            String sidecarHash = hash(sidecar), sourceHash = hash(source);
            export(input, sidecar);
            if (!sidecarHash.equals(hash(sidecar)) || !sourceHash.equals(hash(source))) {
                throw new AssertionError("normal packaged export is not byte deterministic");
            }
            if (!originalHash.equals(hash(input))) throw new AssertionError("normal packaged export changed the original");
            try (var files = Files.list(output)) {
                if (files.anyMatch(p -> !p.equals(sidecar) && !p.equals(source))) throw new AssertionError("unexpected output or leaked temporary file");
            }
            var result = new LinkedHashMap<String, Object>();
            result.put("status", "PASS_PACKAGED_CALL_SITE_EXPORT");
            result.put("scope", "Real installed script, native pair and decompilation; fixture curation is rolled back");
            result.put("readOnlyProject", true);
            result.put("java", System.getProperty("java.version"));
            result.put("classOrigin", origin.toString());
            result.put("jarSha256", hash(origin));
            result.put("scriptSha256", hash(module.resolve("ghidra_scripts/GhidraDwarfForge.java")));
            result.put("consumerSha256", hash(libraries.consumer()));
            result.put("producerSha256", hash(libraries.producer()));
            result.put("inputSha256", originalHash);
            result.put("sidecarSha256", sidecarHash);
            result.put("sourceSha256", sourceHash);
            result.put("rebaseDelta", delta);
            result.put("correctedDriverBody", elf.machine() == 62);
            result.put("analystNamedThunks", namedThunks);
            result.put("functions", curated);
            Files.writeString(output.resolve("export.json"), new GsonBuilder().setPrettyPrinting().create().toJson(result) + "\n",
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            println("packaged-call-site-export=PASS functions=" + curated.size());
        }
        finally {
            currentProgram.endTransaction(transaction, false);
        }
    }

    private void export(Path input, Path sidecar) throws Exception {
        runScript("GhidraDwarfForge.java", new String[] { "--packaged-natives", "--input=" + input, "--output=" + sidecar });
    }

    private String hash(Path path) throws Exception {
        return FileDigests.read(path, monitor::isCancelled).sha256();
    }

    /** Same explicit source-known body correction as the independent recovered-plan probe. */
    private void correctDriverBody() throws Exception {
        var names = new java.util.HashMap<String, Function>();
        for (var function : currentProgram.getFunctionManager().getFunctions(true)) names.put(function.getName(), function);
        var driver = Objects.requireNonNull(names.get("cs_driver"));
        var cold = Objects.requireNonNull(names.get("cs_driver.cold"));
        var zero = Objects.requireNonNull(names.get("caseD_0"));
        var jump = currentProgram.getListing().getInstructionContaining(cold.getBody().getMaxAddress());
        if (jump.getDefaultFlows().length != 1) throw new AssertionError("cold case has no exact epilogue target");
        var epilogue = currentProgram.getFunctionManager().getFunctionAt(jump.getDefaultFlows()[0]);
        if (epilogue == null || !epilogue.getName().startsWith("FUN_")) throw new AssertionError("missing split epilogue");
        var body = new AddressSet(driver.getBody());
        for (var fragment : List.of(cold, zero, epilogue)) {
            body.add(fragment.getBody());
            if (!currentProgram.getFunctionManager().removeFunction(fragment.getEntryPoint())) throw new AssertionError("cannot curate fragment");
        }
        driver.setBody(body);
    }
}
