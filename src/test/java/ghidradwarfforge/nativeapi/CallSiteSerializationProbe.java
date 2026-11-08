package ghidradwarfforge.nativeapi;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonParser;
import ghidradwarfforge.calls.CallSitePlan;
import ghidradwarfforge.calls.CallValue;
import ghidradwarfforge.elf.DebugSectionCompression;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.locations.VariableStorageModel.*;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;

/** Compiler-derived serialization controls, deliberately independent of Ghidra extraction. */
public final class CallSiteSerializationProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 7) throw new IllegalArgumentException("consumer producer input output model target variant");
        var json = JsonParser.parseString(Files.readString(Path.of(args[4]))).getAsJsonObject();
        String variant = args[6];
        if (!List.of("complete", "partial", "tails", "failed", "empty", "no-values", "cancel").contains(variant)) {
            throw new IllegalArgumentException("unknown serialization control");
        }
        int register = args[5].equals("x86_64") ? 5 : 0;
        String registerName = args[5].equals("x86_64") ? "RDI" : "x0";
        var integer = new TypeGraph.TypeRef("int");
        var types = new TypeGraph(List.of(new TypeGraph.BaseType("int", "int", 4, TypeGraph.BaseEncoding.SIGNED)));
        var functions = new ArrayList<FunctionSymbol>();
        var byName = new HashMap<String, FunctionSymbol>();
        var signatures = new ArrayList<ProgramTypeModel.FunctionSignature>();
        var locations = new ArrayList<VariableLocation>();
        var texts = new ArrayList<SyntheticSourceFile.FunctionText>();
        for (var element : json.getAsJsonArray("functions")) {
            var f = element.getAsJsonObject();
            String name = f.get("name").getAsString();
            long address = f.get("address").getAsLong(), size = f.get("size").getAsLong();
            var symbol = new FunctionSymbol(name, address, size);
            functions.add(symbol);
            byName.put(name, symbol);
            boolean parameter = List.of("cs_leaf", "cs_normal", "cs_tail_first", "cs_tail_middle").contains(name);
            if (parameter) {
                signatures.add(new ProgramTypeModel.FunctionSignature(name, address, integer,
                    List.of(new TypeGraph.Parameter("value", integer, false)), List.of(),
                    false, false, "default", "USER_DEFINED"));
                // The incoming parameter is known only at entry. Never claim its
                // destination register still holds the parameter after modification.
                locations.add(new VariableLocation(name, address, "value", VariableKind.PARAMETER, 4,
                    List.of(new LocationRange(address, address + 1,
                        TargetRegisterMap.forTarget(args[5]).register(registerName, 0, 32),
                        new Evidence(Confidence.IMPORTED, "compiler ABI serialization control at entry only")),
                        new LocationRange(address + 1, address + size,
                            new UnavailableStorage(OmissionReason.UNKNOWN_LIFETIME, "body storage is outside this control"),
                            new Evidence(Confidence.IMPORTED, "no current-value claim beyond entry")))));
            }
            boolean failed = variant.equals("failed") && name.equals("cs_tail_middle");
            texts.add(new SyntheticSourceFile.FunctionText(name, address,
                failed ? null : "int " + name + "(void) { /* synthetic serialization control */ return 0; }\n",
                failed ? "controlled decompilation failure" : null));
        }
        var inventories = new ArrayList<CallSitePlan.FunctionCalls>();
        for (var element : json.getAsJsonArray("inventories")) {
            var f = element.getAsJsonObject();
            String caller = f.get("caller").getAsString();
            var sites = new ArrayList<CallSitePlan.Site>();
            for (var call : f.getAsJsonArray("sites")) {
                var c = call.getAsJsonObject();
                var callee = byName.get(c.get("callee").getAsString());
                var arguments = new ArrayList<CallSitePlan.Argument>();
                if (c.has("value") && !variant.equals("no-values")) {
                    int value = c.get("value").getAsInt();
                    CallValue expression = caller.equals("cs_driver") ? new CallValue.Literal(value, 8) :
                        CallValue.extend(CallValue.binary(CallValue.Op.ADD,
                            CallValue.slice(new CallValue.Incoming(register, 8), 0, 4),
                            new CallValue.Literal(value, 4), 4), false, 8);
                    arguments.add(new CallSitePlan.Argument(0, "value", "int", register, expression));
                }
                sites.add(new CallSitePlan.Site(c.get("pc").getAsLong(), c.get("returnPc").getAsLong(),
                    c.get("tail").getAsBoolean(), callee.address(), arguments));
            }
            var completeness = caller.equals("cs_driver") || variant.equals("partial") ?
                CallSitePlan.Completeness.PARTIAL : variant.equals("tails") ?
                CallSitePlan.Completeness.ALL_TAILS : CallSitePlan.Completeness.ALL_CALLS;
            inventories.add(new CallSitePlan.FunctionCalls(byName.get(caller).address(), completeness, sites));
        }
        var plan = variant.equals("empty") ? CallSitePlan.EMPTY : new CallSitePlan(inventories);
        var model = new ProgramTypeModel(types, signatures, List.of(), new VariableStorageModel(locations));
        var source = SyntheticSourceFile.build("call-site serialization control", "fixture", texts);
        var exporter = new MinimalDwarfSidecarExporter(DebugSectionCompression.NONE, Map.of(), null, plan);
        Path output = Path.of(args[3]);
        var polls = new java.util.concurrent.atomic.AtomicInteger();
        exporter.export(Path.of(args[2]), output, Path.of(args[0]), Path.of(args[1]), functions, source, model,
            output.getFileName() + ".c", () -> { polls.incrementAndGet(); return false; });
        if (variant.equals("cancel")) {
            int total = polls.get();
            if (total < 10 || total > 2000) throw new AssertionError("unexpected cancellation check count " + total);
            byte[] sentinel = "preserve existing sidecar on cancellation".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            for (int at = 1; at <= total; at++) {
                Files.write(output, sentinel);
                polls.set(0);
                final int stop = at;
                try {
                    exporter.export(Path.of(args[2]), output, Path.of(args[0]), Path.of(args[1]), functions, source, model,
                        output.getFileName() + ".c", () -> polls.incrementAndGet() >= stop);
                    throw new AssertionError("ignored cancellation at " + stop);
                }
                catch (java.util.concurrent.CancellationException expected) {
                    if (!java.util.Arrays.equals(sentinel, Files.readAllBytes(output))) {
                        throw new AssertionError("cancellation replaced original output at " + stop);
                    }
                }
            }
            try (var files = Files.list(output.getParent())) {
                if (files.anyMatch(path -> path.getFileName().toString().endsWith(".tmp"))) {
                    throw new AssertionError("temporary output leaked on cancellation");
                }
            }
            // A successful lifecycle after cancellation also checks producer cleanup.
            exporter.export(Path.of(args[2]), output, Path.of(args[0]), Path.of(args[1]), functions, source, model);
            System.out.println("PASS_CANCEL_POLLS " + total);
        }
        source.writeAtomically(Path.of(args[3] + ".c"));
        System.out.println("PASS_SERIALIZATION_PROBE " + args[5] + " " + variant);
    }
}
