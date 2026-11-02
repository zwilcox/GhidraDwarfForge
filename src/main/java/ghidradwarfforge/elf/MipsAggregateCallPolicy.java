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

/** Classify MIPS aggregate-return calls independently of floating scalar transfer. */
public final class MipsAggregateCallPolicy {
    private MipsAggregateCallPolicy() {
    }

    public static ProgramTypeModel apply(ElfImage image, ProgramTypeModel model,
            BooleanSupplier cancelled, Consumer<String> diagnostic) throws IOException {
        checkCancelled(cancelled);
        if (image.machine() != 8 || model == null) {
            return model;
        }
        var abi = MipsAbiFlags.observe(image, cancelled);
        boolean integerProfile = integerProfile(image, abi);
        var types = model.types().byKey();
        var functions = new ArrayList<FunctionSignature>();
        var declarations = new ArrayList<FunctionDeclaration>();
        boolean changed = false;
        for (var function : model.functions()) {
            checkCancelled(cancelled);
            String restriction = restriction(types, function.returnType(), function.parameters(),
                function.variadic(), integerProfile, cancelled);
            if (restriction.isEmpty()) {
                functions.add(function);
                continue;
            }
            changed = true;
            functions.add(new FunctionSignature(function.name(), function.address(), function.returnType(),
                function.parameters(), function.locals(), function.variadic(), function.noReturn(),
                function.callingConvention(), function.signatureSource(), function.nonDefaultCallingConvention(),
                combine(function.debuggerCallRestriction(), restriction), function.effectiveCallingConvention()));
            diagnostic.accept("Debugger-injected calls disabled for " + function.name() + ": " + restriction);
        }
        for (var declaration : model.functionDeclarations()) {
            checkCancelled(cancelled);
            String restriction = restriction(types, declaration.returnType(), declaration.parameters(),
                declaration.variadic(), integerProfile, cancelled);
            if (restriction.isEmpty()) {
                declarations.add(declaration);
                continue;
            }
            changed = true;
            declarations.add(new FunctionDeclaration(declaration.key(), declaration.name(), declaration.returnType(),
                declaration.parameters(), declaration.variadic(), declaration.noReturn(), declaration.callingConvention(),
                declaration.signatureSource(), declaration.nonDefaultCallingConvention(),
                combine(declaration.debuggerCallRestriction(), restriction), declaration.effectiveCallingConvention()));
            diagnostic.accept("Debugger-injected calls disabled for " + declaration.name() + ": " + restriction);
        }
        var nodes = new ArrayList<TypeNode>();
        for (var node : model.types().nodes()) {
            checkCancelled(cancelled);
            if (node instanceof TypeGraph.SubroutineType subroutine) {
                String restriction = restriction(types, subroutine.returnType(), subroutine.parameters(),
                    subroutine.variadic(), integerProfile, cancelled);
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

    private static boolean integerProfile(ElfImage image, MipsAbiFlags.Observation observation) {
        if (image.is64Bit() || (image.type() != 2 && image.type() != 3) ||
                (image.flags() & ~7L) != 0x70001000L ||
                observation.status() != MipsAbiFlags.Status.AVAILABLE) {
            return false;
        }
        var fields = observation.fields().orElseThrow();
        return fields.version() == 0 && fields.isaLevel() == 32 && fields.isaRevision() == 2 &&
            fields.gprSize() == 1 && fields.cpr1Size() == 1 && fields.cpr2Size() == 0 &&
            (fields.fpAbi() == 1 || fields.fpAbi() == 5) && fields.isaExtension() == 0 &&
            fields.ases() == 0 && (fields.flags1() & ~1L) == 0 && fields.flags2() == 0;
    }

    private static String restriction(Map<String, TypeNode> types, TypeRef result, List<Parameter> parameters,
            boolean variadic, boolean integerProfile, BooleanSupplier cancelled) {
        TypeNode returned = plain(types, result, cancelled);
        if (!(returned instanceof TypeGraph.AggregateType)) {
            return "";
        }
        if (!integerProfile) {
            return "MIPS aggregate-return debugger calls require the verified O32 MIPS32r2 integer-transfer profile";
        }
        if (variadic) {
            return "MIPS aggregate-return variadic calls have no validated argument transfer";
        }
        for (var parameter : parameters) {
            checkCancelled(cancelled);
            if (parameter.returnStorage()) {
                continue;
            }
            TypeNode node = plain(types, parameter.type(), cancelled);
            boolean word = node != null && node.byteSize() > 0 && node.byteSize() <= 4;
            boolean integer = node instanceof TypeGraph.BaseType base &&
                (base.encoding() == TypeGraph.BaseEncoding.SIGNED ||
                    base.encoding() == TypeGraph.BaseEncoding.UNSIGNED ||
                    base.encoding() == TypeGraph.BaseEncoding.SIGNED_CHAR ||
                    base.encoding() == TypeGraph.BaseEncoding.UNSIGNED_CHAR ||
                    base.encoding() == TypeGraph.BaseEncoding.BOOLEAN);
            boolean pointer = node instanceof TypeGraph.IndirectionType indirect &&
                indirect.kind() == TypeGraph.IndirectionKind.POINTER && indirect.byteSize() == 4;
            if (!word || !(integer || pointer || node instanceof TypeGraph.EnumType)) {
                return "MIPS aggregate-return debugger calls require classified word-sized integer/pointer arguments; " +
                    "wide and other arguments have no validated hidden-return transfer";
            }
        }
        return "";
    }

    private static TypeNode plain(Map<String, TypeNode> types, TypeRef reference,
            BooleanSupplier cancelled) {
        var visited = new HashSet<String>();
        TypeNode node = types.get(reference.key());
        while (node instanceof TypeGraph.TypedefType || node instanceof TypeGraph.QualifiedType) {
            checkCancelled(cancelled);
            if (!visited.add(node.key()) || visited.size() > 64) {
                return null;
            }
            node = types.get(node instanceof TypeGraph.TypedefType alias ? alias.target().key() :
                ((TypeGraph.QualifiedType) node).target().key());
        }
        return node;
    }

    private static String combine(String existing, String restriction) {
        return existing.isEmpty() || existing.equals(restriction) ? restriction :
            existing.endsWith("; " + restriction) ? existing : existing + "; " + restriction;
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) {
            throw new CancellationException("MIPS aggregate call classification cancelled");
        }
    }
}
