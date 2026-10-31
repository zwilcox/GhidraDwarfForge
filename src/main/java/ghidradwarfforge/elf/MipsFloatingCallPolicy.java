package ghidradwarfforge.elf;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.ProgramTypeModel.FunctionDeclaration;
import ghidradwarfforge.types.ProgramTypeModel.FunctionSignature;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.Parameter;
import ghidradwarfforge.types.TypeGraph.TypeNode;
import ghidradwarfforge.types.TypeGraph.TypeRef;

/** Restrict floating debugger calls whose original MIPS ABI has no verified transfer profile. */
public final class MipsFloatingCallPolicy {
    private MipsFloatingCallPolicy() {
    }

    public static ProgramTypeModel apply(ElfImage image, ProgramTypeModel model,
            BooleanSupplier cancelled, Consumer<String> diagnostic) throws IOException {
        checkCancelled(cancelled);
        if (image.machine() != 8 || model == null) {
            return model;
        }
        var abi = MipsAbiFlags.observe(image, cancelled);
        var types = model.types().byKey();
        var functions = new ArrayList<FunctionSignature>();
        var declarations = new ArrayList<FunctionDeclaration>();
        boolean changed = false;
        for (var function : model.functions()) {
            checkCancelled(cancelled);
            String restriction = restriction(types, function.returnType(), function.parameters(),
                function.variadic(), abi, cancelled);
            if (restriction.isEmpty()) {
                functions.add(function);
                continue;
            }
            changed = true;
            functions.add(new FunctionSignature(function.name(), function.address(), function.returnType(),
                function.parameters(), function.locals(), function.variadic(), function.noReturn(),
                function.callingConvention(), function.signatureSource(), function.nonDefaultCallingConvention(),
                combine(function.debuggerCallRestriction(), restriction)));
            diagnostic.accept("Debugger-injected calls disabled for " + function.name() + ": " + restriction);
        }
        for (var declaration : model.functionDeclarations()) {
            checkCancelled(cancelled);
            String restriction = restriction(types, declaration.returnType(), declaration.parameters(),
                declaration.variadic(), abi, cancelled);
            if (restriction.isEmpty()) {
                declarations.add(declaration);
                continue;
            }
            changed = true;
            declarations.add(new FunctionDeclaration(declaration.key(), declaration.name(), declaration.returnType(),
                declaration.parameters(), declaration.variadic(), declaration.noReturn(), declaration.callingConvention(),
                declaration.signatureSource(), declaration.nonDefaultCallingConvention(),
                combine(declaration.debuggerCallRestriction(), restriction)));
            diagnostic.accept("Debugger-injected calls disabled for " + declaration.name() + ": " + restriction);
        }
        var nodes = new ArrayList<TypeNode>();
        for (var node : model.types().nodes()) {
            checkCancelled(cancelled);
            if (node instanceof TypeGraph.SubroutineType subroutine) {
                String restriction = restriction(types, subroutine.returnType(), subroutine.parameters(),
                    subroutine.variadic(), abi, cancelled);
                if (!restriction.isEmpty()) {
                    nodes.add(subroutine.restrictDebuggerCalls(restriction));
                    changed = true;
                    diagnostic.accept("Debugger-injected calls disabled for function type " +
                        subroutine.name() + ": " + restriction);
                    continue;
                }
            }
            nodes.add(node);
        }
        checkCancelled(cancelled);
        return changed ? new ProgramTypeModel(nodes.equals(model.types().nodes()) ? model.types() : new TypeGraph(nodes), functions, model.globals(), model.variableStorage(),
            model.functionStatics(), declarations, model.lexicalScopes(), model.classScopes(), model.functionRelations()) : model;
    }

    private static String restriction(Map<String, TypeNode> types, TypeRef result, List<Parameter> parameters,
            boolean variadic, MipsAbiFlags.Observation abi, BooleanSupplier cancelled) {
        var selected = new ArrayList<TypeRef>();
        selected.add(result);
        for (var parameter : parameters) {
            checkCancelled(cancelled);
            selected.add(parameter.type());
        }
        boolean floating = false;
        for (var reference : selected) {
            var visited = new HashSet<String>();
            TypeNode node = types.get(reference.key());
            while (node instanceof TypeGraph.TypedefType || node instanceof TypeGraph.QualifiedType) {
                checkCancelled(cancelled);
                if (!visited.add(node.key()) || visited.size() > 64) {
                    return "MIPS signature type aliases cannot be classified within the bounded ABI policy";
                }
                node = types.get(node instanceof TypeGraph.TypedefType alias ? alias.target().key() :
                    ((TypeGraph.QualifiedType) node).target().key());
            }
            if (node instanceof TypeGraph.BaseType base && base.encoding() == TypeGraph.BaseEncoding.FLOAT) {
                floating = true;
                if (base.byteSize() != 4 && base.byteSize() != 8) {
                    return "MIPS floating debugger calls have no validated " + base.byteSize() + "-byte transfer";
                }
            }
        }
        if ((floating || variadic) && !abi.fp32PairContract()) {
            return "MIPS floating or variadic debugger calls require the verified explicit O32 FP32 ABI profile; " +
                "FPXX and other profiles do not establish correct GDB floating argument/return transfer (" +
                abi.detail() + ")";
        }
        return "";
    }

    private static String combine(String existing, String restriction) {
        return existing.isEmpty() || existing.equals(restriction) ? restriction :
            existing.endsWith("; " + restriction) ? existing : existing + "; " + restriction;
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) {
            throw new CancellationException("MIPS floating call classification cancelled");
        }
    }
}
