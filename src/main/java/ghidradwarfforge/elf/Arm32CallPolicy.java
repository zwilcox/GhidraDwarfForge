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
import ghidradwarfforge.types.TypeGraph.TypeNode;
import ghidradwarfforge.types.TypeGraph.TypeRef;

/** Explicit selected Ghidra PCS versus the original ELF's automatic GDB PCS. */
public final class Arm32CallPolicy {
    private Arm32CallPolicy() { }

    public static ProgramTypeModel apply(ElfImage image, ProgramTypeModel model,
            BooleanSupplier cancelled, Consumer<String> diagnostic) throws IOException {
        check(cancelled);
        if (image.machine() != 40 || model == null) return model;
        var abi = Arm32CallAbi.observe(image, cancelled);
        var types = model.types().byKey();
        var functions = new ArrayList<FunctionSignature>();
        var declarations = new ArrayList<FunctionDeclaration>();
        var nodes = new ArrayList<TypeNode>();
        for (var function : model.functions()) {
            var restriction = restriction(types, function.returnType(), function.parameters(),
                function.effectiveCallingConvention(), function.variadic(), abi, cancelled);
            boolean unmapped = function.nonDefaultCallingConvention() && !restriction.isEmpty();
            functions.add(new FunctionSignature(function.name(), function.address(), function.returnType(),
                function.parameters(), function.locals(), function.variadic(), function.noReturn(),
                function.callingConvention(), function.signatureSource(), unmapped,
                combine(function.debuggerCallRestriction(), restriction), function.effectiveCallingConvention()));
            report(function.name(), function.nonDefaultCallingConvention(), restriction, diagnostic);
        }
        for (var declaration : model.functionDeclarations()) {
            var restriction = restriction(types, declaration.returnType(), declaration.parameters(),
                declaration.effectiveCallingConvention(), declaration.variadic(), abi, cancelled);
            boolean unmapped = declaration.nonDefaultCallingConvention() && !restriction.isEmpty();
            declarations.add(new FunctionDeclaration(declaration.key(), declaration.name(), declaration.returnType(),
                declaration.parameters(), declaration.variadic(), declaration.noReturn(), declaration.callingConvention(),
                declaration.signatureSource(), unmapped, combine(declaration.debuggerCallRestriction(), restriction),
                declaration.effectiveCallingConvention()));
            report(declaration.name(), declaration.nonDefaultCallingConvention(), restriction, diagnostic);
        }
        for (var node : model.types().nodes()) {
            check(cancelled);
            if (node instanceof TypeGraph.SubroutineType function) {
                var restriction = restriction(types, function.returnType(), function.parameters(),
                    function.callingConvention(), function.variadic(), abi, cancelled);
                nodes.add(new TypeGraph.SubroutineType(function.key(), function.name(), function.byteSize(),
                    function.returnType(), function.parameters(), function.variadic(), function.callingConvention(),
                    combine(function.debuggerCallRestriction(), restriction),
                    function.nonDefaultCallingConvention() && !restriction.isEmpty()));
                report("function type " + function.name(), function.nonDefaultCallingConvention(), restriction, diagnostic);
            }
            else nodes.add(node);
        }
        check(cancelled);
        return new ProgramTypeModel(nodes.equals(model.types().nodes()) ? model.types() : new TypeGraph(nodes),
            functions, model.globals(), model.variableStorage(), model.functionStatics(), declarations,
            model.lexicalScopes(), model.classScopes(), model.functionRelations());
    }

    private static String restriction(Map<String, TypeNode> types, TypeRef result,
            List<TypeGraph.Parameter> parameters, String convention, boolean variadic,
            Arm32CallAbi.Observation abi, BooleanSupplier cancelled) {
        check(cancelled);
        if (!abi.valid()) return abi.restriction();
        var selected = switch (convention) {
            case "__stdcall", "default" -> Arm32CallAbi.Pcs.VFP;
            case "__stdcall_softfp" -> Arm32CallAbi.Pcs.BASE;
            default -> Arm32CallAbi.Pcs.UNKNOWN;
        };
        if (selected == Arm32CallAbi.Pcs.UNKNOWN) return "ARM selected calling convention has no audited PCS mapping";
        if (parameters.size() > 4096) return "ARM signature exceeds the parameter classification budget";
        var references = new ArrayList<TypeRef>();
        references.add(result);
        int hidden = 0;
        for (var parameter : parameters) {
            check(cancelled);
            if (parameter.returnStorage()) {
                var returned = resolve(types, result, cancelled);
                var carrier = resolve(types, parameter.type(), cancelled);
                if (++hidden > 1 || !integerStructure(types, returned, cancelled) || returned.byteSize() <= 4 ||
                        !(carrier instanceof TypeGraph.IndirectionType pointer) || pointer.byteSize() != 4 ||
                        pointer.kind() != TypeGraph.IndirectionKind.POINTER ||
                        !returned.equals(resolve(types, pointer.target(), cancelled))) {
                    return "ARM hidden return storage disagrees with the classified aggregate result";
                }
                continue;
            }
            if (parameter.artificial()) return "ARM automatic parameter role needs separate call classification";
            references.add(parameter.type());
        }
        boolean floating = false;
        for (int index = 0; index < references.size(); index++) {
            var node = resolve(types, references.get(index), cancelled);
            if (node instanceof TypeGraph.VoidType && index == 0) continue;
            // Existing compiler/Forge aggregate-return fixtures cover these integer layouts.
            // They do not classify aggregate arguments or homogeneous floating aggregates.
            if (index == 0 && integerStructure(types, node, cancelled)) continue;
            if (node instanceof TypeGraph.IndirectionType pointer && pointer.byteSize() == 4) continue;
            if (node instanceof TypeGraph.EnumType enumeration && scalarWidth(enumeration.byteSize())) continue;
            if (!(node instanceof TypeGraph.BaseType base) || !scalarWidth(base.byteSize())) {
                return "ARM aggregate, vector or opaque call type needs separate transfer classification";
            }
            switch (base.encoding()) {
                case FLOAT -> {
                    if (base.byteSize() != 4 && base.byteSize() != 8) return "ARM floating call width is not validated";
                    floating = true;
                }
                case SIGNED, SIGNED_CHAR, UNSIGNED, UNSIGNED_CHAR, BOOLEAN, ADDRESS, UTF -> { }
            }
        }
        if (floating) {
            if (abi.declared() == Arm32CallAbi.Pcs.COMPATIBLE && !variadic) {
                return "ARM compatible-only build attributes disallow nonvariadic floating signatures";
            }
            var consumer = variadic ? Arm32CallAbi.Pcs.BASE : abi.consumer();
            if (selected != consumer) {
                return "ARM selected " + selected + " floating PCS differs from automatic GDB " + consumer +
                    "; per-function PCS cannot be expressed to this consumer by DW_CC_normal";
            }
        }
        return "";
    }

    private static boolean scalarWidth(long bytes) {
        return bytes == 1 || bytes == 2 || bytes == 4 || bytes == 8;
    }

    private static boolean integerStructure(Map<String, TypeNode> types, TypeNode node, BooleanSupplier cancelled) {
        if (!(node instanceof TypeGraph.AggregateType aggregate) ||
                aggregate.kind() != TypeGraph.AggregateKind.STRUCTURE ||
                aggregate.members().isEmpty() || aggregate.members().size() > 3) return false;
        long offset = 0;
        for (var member : aggregate.members()) {
            check(cancelled);
            var field = resolve(types, member.type(), cancelled);
            if (member.bitSize() != 0 || member.byteOffset() != offset ||
                    !(field instanceof TypeGraph.BaseType base) ||
                    (base.byteSize() != 4 && base.byteSize() != 8) ||
                    (base.encoding() != TypeGraph.BaseEncoding.SIGNED && base.encoding() != TypeGraph.BaseEncoding.UNSIGNED)) {
                return false;
            }
            offset += base.byteSize();
        }
        return offset == aggregate.byteSize();
    }

    private static TypeNode resolve(Map<String, TypeNode> types, TypeRef reference, BooleanSupplier cancelled) {
        var visited = new HashSet<String>();
        TypeNode node = types.get(reference.key());
        while (node instanceof TypeGraph.TypedefType || node instanceof TypeGraph.QualifiedType) {
            check(cancelled);
            if (!visited.add(node.key()) || visited.size() > 64) return null;
            TypeNode next = types.get(node instanceof TypeGraph.TypedefType alias ? alias.target().key() :
                ((TypeGraph.QualifiedType) node).target().key());
            if (next == null || node.byteSize() != next.byteSize()) return null;
            node = next;
        }
        return node;
    }

    private static String combine(String old, String added) {
        if (added.isEmpty() || old.equals(added) || old.endsWith("; " + added)) return old;
        return old.isEmpty() ? added : old + "; " + added;
    }

    private static void report(String name, boolean previouslyUnmapped, String restriction, Consumer<String> diagnostic) {
        if (!restriction.isEmpty()) diagnostic.accept("Debugger-injected calls disabled for " + name + ": " + restriction);
        else if (previouslyUnmapped) diagnostic.accept("Audited ARM PCS mapping for " + name +
            "; independent custom-storage/compiler restrictions remain in force");
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("ARM call classification cancelled");
    }
}
