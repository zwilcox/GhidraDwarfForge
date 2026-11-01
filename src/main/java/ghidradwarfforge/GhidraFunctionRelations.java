package ghidradwarfforge;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.function.Consumer;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.types.ClassScopeModel.FunctionReference;
import ghidradwarfforge.types.FunctionRelations;
import ghidradwarfforge.types.ProgramTypeModel;

/** Preserve current saved direct thunk identities without following names or guessing source origins. */
public final class GhidraFunctionRelations {
    private GhidraFunctionRelations() { }

    public static FunctionRelations extract(Program program, List<ProgramTypeModel.FunctionSignature> signatures,
            List<ProgramTypeModel.FunctionDeclaration> declarations, long rebaseDelta,
            TaskMonitor monitor, Consumer<String> diagnostic) throws CancelledException {
        var references = new HashMap<Long, FunctionReference>();
        var functions = new HashMap<Long, Function>();
        for (var signature : signatures) {
            monitor.checkCancelled();
            Function function;
            try {
                var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(
                    Math.addExact(signature.address(), rebaseDelta));
                function = program.getFunctionManager().getFunctionAt(address);
            }
            catch (ArithmeticException | IllegalArgumentException invalid) { continue; }
            if (function == null || function.isExternal() || !function.getName().equals(signature.name())) continue;
            functions.put(function.getID(), function);
            references.put(function.getID(), FunctionReference.definition(signature.name(), signature.address()));
        }
        var declared = new HashMap<String, ProgramTypeModel.FunctionDeclaration>();
        for (var declaration : declarations) declared.put(declaration.key(), declaration);
        var externals = program.getFunctionManager().getExternalFunctions();
        while (externals.hasNext()) {
            monitor.checkCancelled();
            var external = externals.next();
            String key = "external:" + Long.toUnsignedString(external.getID());
            var declaration = declared.get(key);
            if (declaration != null && declaration.name().equals(external.getName(true))) {
                references.put(external.getID(), FunctionReference.declaration(declaration.name(), key));
            }
        }
        var thunks = new ArrayList<FunctionRelations.Thunk>();
        for (long id : functions.keySet().stream().sorted().toList()) {
            monitor.checkCancelled();
            var function = functions.get(id);
            if (!function.isThunk()) continue;
            Function target = function.getThunkedFunction(false);
            if (target == null || target.getProgram() != program || !references.containsKey(target.getID())) {
                diagnostic.accept("Omitted thunk relationship for " + function.getName(true) + ": direct saved target is not exported");
                continue;
            }
            try {
                thunks.add(new FunctionRelations.Thunk(id, references.get(id), target.getID(), references.get(target.getID()),
                    "Saved Ghidra direct thunk identity; no source, locations or original compiler provenance inherited"));
            }
            catch (IllegalArgumentException invalid) {
                diagnostic.accept("Omitted thunk relationship for " + function.getName(true) + ": " + invalid.getMessage());
            }
            if (thunks.size() > 65536) {
                diagnostic.accept("Omitted thunk relationships: bounded relationship inventory exceeded");
                return FunctionRelations.empty();
            }
        }
        monitor.checkCancelled();
        try { return new FunctionRelations(thunks); }
        catch (IllegalArgumentException invalid) {
            diagnostic.accept("Omitted inconsistent thunk relationships: " + invalid.getMessage());
            return FunctionRelations.empty();
        }
    }
}
