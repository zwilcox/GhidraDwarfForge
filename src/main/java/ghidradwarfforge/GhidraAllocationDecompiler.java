package ghidradwarfforge;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.function.Consumer;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileCallback;
import ghidra.app.decompiler.DecompileException;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.pcode.Encoder;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.AddressXML;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.VariableStorage;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

/** Read-only decompiler input corrections; the original function's overrides remain authoritative. */
public final class GhidraAllocationDecompiler extends DecompInterface {
    private final GhidraParameterAllocation allocation;
    private final TaskMonitor monitor;
    private final Consumer<String> diagnostic;

    public GhidraAllocationDecompiler(GhidraParameterAllocation allocation, TaskMonitor monitor,
            Consumer<String> diagnostic) {
        this.allocation = allocation;
        this.monitor = monitor;
        this.diagnostic = diagnostic;
    }

    @Override
    protected void initializeProcess() throws IOException, DecompileException {
        if (!(decompCallback instanceof AllocationCallback)) {
            decompCallback = new AllocationCallback();
        }
        super.initializeProcess();
    }

    private final class AllocationCallback extends DecompileCallback {
        AllocationCallback() {
            super(program, program.getLanguage(), program.getCompilerSpec(), getDataTypeManager());
        }

        @Override
        public void getMappedSymbols(Address address, Encoder output) throws IOException {
            Function function = program.getFunctionManager().getFunctionAt(address);
            if (function == null) {
                super.getMappedSymbols(address, output);
                return;
            }
            GhidraParameterAllocation.Resolution resolved;
            try {
                resolved = allocation.resolve(function, monitor, ignored -> { });
            }
            catch (CancelledException error) {
                throw new IOException("Allocation correction cancelled", error);
            }
            if (resolved.returnStorage() == null && HighFunction.findOverrideSpace(function) == null) {
                super.getMappedSymbols(address, output);
                return;
            }
            var original = new GhidraEncoderTree(monitor);
            super.getMappedSymbols(address, original);
            var roots = original.roots();
            if (roots.size() != 1) throw new IOException("Missing function encoding for allocation correction");
            var document = roots.get(0);
            var mapping = document.only(ELEM_MAPSYM);
            var savedFunction = mapping.only(ELEM_FUNCTION);
            try {
                var replacement = savedFunction;
                if (resolved.returnStorage() != null) {
                    var view = functionView(function, resolved);
                    var high = new HighFunction(view, program.getLanguage(), program.getCompilerSpec(), getDataTypeManager());
                    high.grabFromFunction(function.getCallingConvention().getExtrapop(), true, false);
                    var corrected = new GhidraEncoderTree(monitor);
                    high.encode(corrected, function.getSymbol().getID(), function.getParentNamespace(), address, 1);
                    var alternative = corrected.roots();
                    if (alternative.size() != 1) throw new IOException("Missing corrected allocation encoding");
                    replacement = replaceSignature(savedFunction, alternative.get(0));
                    diagnostic.accept("Applied validated allocation to read-only decompiler input for " + function.getName() +
                        "; original overrides, locals and saved program retained");
                }
                replacement = correctOverrides(function, replacement);
                document.replace(mapping, mapping.replace(savedFunction, replacement)).replay(output, monitor);
            }
            catch (CancelledException error) {
                throw new IOException("Call override allocation cancelled", error);
            }
            catch (InvalidInputException error) {
                throw new IOException("Invalid allocation-backed decompiler view", error);
            }
        }
    }

    private GhidraEncoderTree.Node correctOverrides(Function function, GhidraEncoderTree.Node encoded)
            throws IOException, CancelledException {
        var namespace = HighFunction.findOverrideSpace(function);
        if (namespace == null) return encoded;
        var symbols = program.getSymbolTable().getSymbols(namespace);
        while (symbols.hasNext()) {
            monitor.checkCancelled();
            var symbol = symbols.next();
            if (!symbol.getName().startsWith("prt")) continue;
            var override = HighFunctionDBUtil.readOverride(symbol);
            if (override == null) continue;
            var resolution = allocation.resolveSignature((FunctionSignature)override.getDataType(), monitor);
            if (resolution == null) continue;
            var address = new GhidraEncoderTree(monitor);
            AddressXML.encode(address, override.getAddress());
            var expectedAddress = address.roots().get(0);
            var overrides = encoded.only(ELEM_OVERRIDE);
            var matches = overrides.children().stream().filter(n -> n.id().equals(ELEM_PROTOOVERRIDE) &&
                n.children().contains(expectedAddress)).toList();
            if (matches.size() != 1) throw new IOException("Missing unique analyst call override");
            var prior = matches.get(0);
            var prototype = prior.only(ELEM_PROTOTYPE);
            var revised = replaceOverrideStorage(prototype, resolution, monitor);
            encoded = encoded.replace(overrides, overrides.replace(prior, prior.replace(prototype, revised)));
            diagnostic.accept("Corrected computed floating-return storage for analyst call override at " +
                override.getAddress() + "; signature and saved program retained");
        }
        return encoded;
    }

    static GhidraEncoderTree.Node replaceOverrideStorage(GhidraEncoderTree.Node prototype,
            GhidraParameterAllocation.SignatureResolution resolution, TaskMonitor monitor) throws IOException {
        var returned = prototype.only(ELEM_RETURNSYM);
        var revised = prototype.replace(returned, withStorage(returned, resolution.returnStorage(), monitor));
        var inputs = prototype.only(ELEM_INTERNALLIST);
        if (inputs.children().size() != resolution.parameters().size()) {
            throw new IOException("Analyst call override parameter count changed");
        }
        var parameters = new ArrayList<GhidraEncoderTree.Node>();
        for (int i = 0; i < inputs.children().size(); i++) {
            var parameter = inputs.children().get(i);
            if (!parameter.id().equals(ELEM_PARAM)) throw new IOException("Unexpected call override parameter");
            parameters.add(withStorage(parameter, resolution.parameters().get(i), monitor));
        }
        revised = revised.replace(inputs, new GhidraEncoderTree.Node(inputs.id(), inputs.attributes(), parameters));
        return customStorage(revised);
    }

    private static GhidraEncoderTree.Node withStorage(GhidraEncoderTree.Node symbol,
            VariableStorage storage, TaskMonitor monitor) throws IOException {
        var address = symbol.only(ELEM_ADDR);
        if (!address.attributes().isEmpty() || !address.children().isEmpty()) {
            throw new IOException("Refusing to replace explicit analyst call storage");
        }
        var encoder = new GhidraEncoderTree(monitor);
        AddressXML.encode(encoder, storage.getVarnodes(), 0);
        return symbol.replace(address, encoder.roots().get(0));
    }

    private static GhidraEncoderTree.Node customStorage(GhidraEncoderTree.Node prototype) {
        var attributes = new ArrayList<>(prototype.attributes());
        attributes.removeIf(a -> a.id().equals(ATTRIB_CUSTOM));
        attributes.add(new GhidraEncoderTree.Attribute("bool", ATTRIB_CUSTOM, true, 0, null));
        return new GhidraEncoderTree.Node(prototype.id(), attributes, prototype.children());
    }

    static GhidraEncoderTree.Node replaceSignature(GhidraEncoderTree.Node original,
            GhidraEncoderTree.Node corrected) throws IOException {
        var originalPrototype = original.only(ELEM_PROTOTYPE);
        var correctedPrototype = corrected.only(ELEM_PROTOTYPE);
        var returnSymbol = originalPrototype.only(ELEM_RETURNSYM);
        var revisedPrototype = originalPrototype.replace(returnSymbol, correctedPrototype.only(ELEM_RETURNSYM));
        revisedPrototype = customStorage(revisedPrototype);

        var localDb = original.only(ELEM_LOCALDB);
        var scope = localDb.only(ELEM_SCOPE);
        var symbols = scope.only(ELEM_SYMBOLLIST);
        var replacementSymbols = corrected.only(ELEM_LOCALDB).only(ELEM_SCOPE).only(ELEM_SYMBOLLIST);
        var locals = symbols.children().stream().filter(n -> !parameter(n)).toList();
        var replacementLocals = replacementSymbols.children().stream().filter(n -> !parameter(n)).toList();
        if (!locals.equals(replacementLocals)) throw new IOException("Allocation view unexpectedly changes local symbols");
        var children = new ArrayList<>(locals);
        children.addAll(replacementSymbols.children().stream().filter(GhidraAllocationDecompiler::parameter).toList());
        var revisedSymbols = new GhidraEncoderTree.Node(symbols.id(), symbols.attributes(), children);
        var revisedLocalDb = localDb.replace(scope, scope.replace(symbols, revisedSymbols));
        // In particular, retain the original function's override and jump-table elements.
        // HighFunction skips those when its Function is not a FunctionDB, so the
        // transient view must never replace the complete original function tree.
        return original.replace(originalPrototype, revisedPrototype).replace(localDb, revisedLocalDb);
    }

    private static boolean parameter(GhidraEncoderTree.Node node) {
        return node.id().equals(ELEM_MAPSYM) && node.children().stream().anyMatch(child ->
            child.id().equals(ELEM_SYMBOL) && Long.valueOf(0).equals(child.attribute(ATTRIB_CAT)));
    }

    static Function functionView(Function function, GhidraParameterAllocation.Resolution resolved)
            throws InvalidInputException {
        var parameters = new ArrayList<Parameter>();
        for (var parameter : function.getParameters()) {
            if (resolved.omittedAutomaticParameters().contains(parameter.getOrdinal())) {
                if (!parameter.isAutoParameter()) throw new IllegalArgumentException("Cannot omit an explicit parameter");
                continue;
            }
            var storage = resolved.storage().getOrDefault(parameter.getOrdinal(), parameter.getVariableStorage());
            final int ordinal = parameters.size();
            parameters.add((Parameter)Proxy.newProxyInstance(Parameter.class.getClassLoader(), new Class<?>[]{Parameter.class},
                (proxy, method, args) -> {
                    if (method.getName().equals("getVariableStorage")) return storage;
                    if (method.getName().equals("getOrdinal")) return ordinal;
                    try { return method.invoke(parameter, args); }
                    catch (InvocationTargetException error) { throw error.getCause(); }
                }));
        }
        var returned = new ReturnParameterImpl(function.getReturn().getFormalDataType(),
            resolved.returnStorage(), function.getProgram());
        return (Function)Proxy.newProxyInstance(Function.class.getClassLoader(), new Class<?>[]{Function.class},
            (proxy, method, args) -> {
                switch (method.getName()) {
                    case "getParameters": return parameters.toArray(Parameter[]::new);
                    case "getParameterCount": return parameters.size();
                    case "getAutoParameterCount": return (int)parameters.stream().filter(Parameter::isAutoParameter).count();
                    case "getReturn": return returned;
                    case "getReturnType": return returned.getDataType();
                    case "hasCustomVariableStorage": return true;
                    default:
                        try { return method.invoke(function, args); }
                        catch (InvocationTargetException error) { throw error.getCause(); }
                }
            });
    }
}
