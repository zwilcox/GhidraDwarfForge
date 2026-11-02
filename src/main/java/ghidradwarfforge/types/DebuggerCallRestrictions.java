package ghidradwarfforge.types;

import java.util.ArrayList;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

import ghidradwarfforge.types.ProgramTypeModel.FunctionDeclaration;
import ghidradwarfforge.types.ProgramTypeModel.FunctionSignature;

/** Restrict debugger calls without changing recovered types, storage or ownership. */
public final class DebuggerCallRestrictions {
    private DebuggerCallRestrictions() {
    }

    public static ProgramTypeModel applyAll(ProgramTypeModel model, String restriction,
            BooleanSupplier cancelled, Consumer<String> diagnostic) {
        checkCancelled(cancelled);
        if (model == null) return null;
        if (restriction.isEmpty()) {
            return model;
        }
        var functions = new ArrayList<FunctionSignature>();
        for (var function : model.functions()) {
            checkCancelled(cancelled);
            functions.add(new FunctionSignature(function.name(), function.address(),
                function.returnType(), function.parameters(), function.locals(),
                function.variadic(), function.noReturn(), function.callingConvention(),
                function.signatureSource(), function.nonDefaultCallingConvention(),
                combine(function.debuggerCallRestriction(), restriction), function.effectiveCallingConvention()));
            diagnostic.accept("Debugger-injected calls disabled for " + function.name() +
                ": " + restriction);
        }
        var declarations = new ArrayList<FunctionDeclaration>();
        for (var declaration : model.functionDeclarations()) {
            checkCancelled(cancelled);
            declarations.add(new FunctionDeclaration(declaration.key(), declaration.name(),
                declaration.returnType(), declaration.parameters(), declaration.variadic(),
                declaration.noReturn(), declaration.callingConvention(),
                declaration.signatureSource(), declaration.nonDefaultCallingConvention(),
                combine(declaration.debuggerCallRestriction(), restriction), declaration.effectiveCallingConvention()));
            diagnostic.accept("Debugger-injected calls disabled for " + declaration.name() +
                ": " + restriction);
        }
        var nodes = new ArrayList<TypeGraph.TypeNode>();
        for (var node : model.types().nodes()) {
            checkCancelled(cancelled);
            if (node instanceof TypeGraph.SubroutineType subroutine) {
                nodes.add(subroutine.restrictDebuggerCalls(restriction));
                diagnostic.accept("Debugger-injected calls disabled for function type " +
                    subroutine.name() + ": " + restriction);
            }
            else {
                nodes.add(node);
            }
        }
        checkCancelled(cancelled);
        return new ProgramTypeModel(nodes.equals(model.types().nodes()) ? model.types() : new TypeGraph(nodes), functions, model.globals(),
            model.variableStorage(), model.functionStatics(), declarations, model.lexicalScopes(), model.classScopes(), model.functionRelations());
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("debugger call classification cancelled");
    }

    private static String combine(String existing, String restriction) {
        if (existing.isEmpty() || existing.equals(restriction)) {
            return restriction;
        }
        return existing.endsWith("; " + restriction) ? existing : existing + "; " + restriction;
    }
}
