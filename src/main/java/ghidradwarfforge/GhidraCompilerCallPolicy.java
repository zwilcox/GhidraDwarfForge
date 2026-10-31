package ghidradwarfforge;

import java.util.ArrayList;
import java.util.function.Consumer;

import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.nativeapi.DwarfTarget;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.ProgramTypeModel.FunctionDeclaration;
import ghidradwarfforge.types.ProgramTypeModel.FunctionSignature;

/** Preserve curated knowledge while restricting an unverified compiler/ELF call ABI. */
public final class GhidraCompilerCallPolicy {
    private GhidraCompilerCallPolicy() {
    }

    /** The caller supplies the target already checked against the original ELF and Program. */
    public static ProgramTypeModel apply(Program program, DwarfTarget target,
            ProgramTypeModel model, TaskMonitor monitor, Consumer<String> diagnostic)
            throws CancelledException {
        monitor.checkCancelled();
        String restriction = target.compilerSpecCallRestriction(
            program.getCompilerSpec().getCompilerSpecID().toString());
        if (restriction.isEmpty()) {
            return model;
        }
        var functions = new ArrayList<FunctionSignature>();
        for (var function : model.functions()) {
            monitor.checkCancelled();
            functions.add(new FunctionSignature(function.name(), function.address(),
                function.returnType(), function.parameters(), function.locals(),
                function.variadic(), function.noReturn(), function.callingConvention(),
                function.signatureSource(), function.nonDefaultCallingConvention(),
                combine(function.debuggerCallRestriction(), restriction)));
            diagnostic.accept("Debugger-injected calls disabled for " + function.name() +
                ": " + restriction);
        }
        var declarations = new ArrayList<FunctionDeclaration>();
        for (var declaration : model.functionDeclarations()) {
            monitor.checkCancelled();
            declarations.add(new FunctionDeclaration(declaration.key(), declaration.name(),
                declaration.returnType(), declaration.parameters(), declaration.variadic(),
                declaration.noReturn(), declaration.callingConvention(),
                declaration.signatureSource(), declaration.nonDefaultCallingConvention(),
                combine(declaration.debuggerCallRestriction(), restriction)));
            diagnostic.accept("Debugger-injected calls disabled for " + declaration.name() +
                ": " + restriction);
        }
        var nodes = new ArrayList<TypeGraph.TypeNode>();
        for (var node : model.types().nodes()) {
            monitor.checkCancelled();
            if (node instanceof TypeGraph.SubroutineType subroutine) {
                nodes.add(subroutine.restrictDebuggerCalls(restriction));
                diagnostic.accept("Debugger-injected calls disabled for function type " +
                    subroutine.name() + ": " + restriction);
            }
            else {
                nodes.add(node);
            }
        }
        monitor.checkCancelled();
        return new ProgramTypeModel(nodes.equals(model.types().nodes()) ? model.types() : new TypeGraph(nodes), functions, model.globals(),
            model.variableStorage(), model.functionStatics(), declarations, model.lexicalScopes(), model.classScopes());
    }

    private static String combine(String existing, String restriction) {
        if (existing.isEmpty() || existing.equals(restriction)) {
            return restriction;
        }
        return existing.endsWith("; " + restriction) ? existing : existing + "; " + restriction;
    }
}
