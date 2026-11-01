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

/** Bounded N32/N64 call transfers, independently gated by ELF metadata and signature layout. */
public final class MipsWideCallPolicy {
    private MipsWideCallPolicy() {
    }

    public static ProgramTypeModel apply(ElfImage image, ProgramTypeModel model,
            BooleanSupplier cancelled, Consumer<String> diagnostic) throws IOException {
        checkCancelled(cancelled);
        if (!isWideCandidate(image) || model == null) {
            return model;
        }
        String profile = metadataRestriction(image, cancelled);
        var types = model.types().byKey();
        var functions = new ArrayList<FunctionSignature>();
        var declarations = new ArrayList<FunctionDeclaration>();
        boolean changed = false;
        for (var function : model.functions()) {
            checkCancelled(cancelled);
            String restriction = restriction(types, function.returnType(), function.parameters(),
                function.variadic(), profile, image.is64Bit() ? 8 : 4, cancelled);
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
                declaration.variadic(), profile, image.is64Bit() ? 8 : 4, cancelled);
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
                    subroutine.variadic(), profile, image.is64Bit() ? 8 : 4, cancelled);
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

    /** ELF64 MIPS and ABI2 inputs must never fall through to the O32 policy. */
    public static boolean isWideCandidate(ElfImage image) {
        return image.machine() == 8 && (image.is64Bit() || (image.flags() & 0x20) != 0);
    }

    public static String programRestriction(ElfImage image, String language, String compiler,
            BooleanSupplier cancelled) throws IOException {
        String metadata = metadataRestriction(image, cancelled);
        if (!metadata.isEmpty()) return metadata;
        String endian = image.byteOrder() == java.nio.ByteOrder.BIG_ENDIAN ? "BE" : "LE";
        String expectedLanguage = "MIPS:" + endian + ":64:" + (image.is64Bit() ? "default" : "64-32addr");
        String expectedCompiler = image.is64Bit() ? "default" : "n32";
        return expectedLanguage.equals(language) && expectedCompiler.equals(compiler) ? "" :
            "MIPS N32/N64 debugger calls require matching ELF, language and compiler: expected " +
                expectedLanguage + "/" + expectedCompiler + ", selected " + language + "/" + compiler;
    }

    public static String metadataRestriction(ElfImage image, BooleanSupplier cancelled) throws IOException {
        checkCancelled(cancelled);
        byte[] header = image.headerBytes();
        int osAbi = Byte.toUnsignedInt(header[7]);
        if (!isWideCandidate(image) || (image.type() != 2 && image.type() != 3) ||
                (image.flags() & ~7L) != (image.is64Bit() ? 0x80000000L : 0x80000020L) ||
                (osAbi != 0 && osAbi != 3) || Byte.toUnsignedInt(header[8]) > 1) {
            return "MIPS ELF metadata has no validated N32/N64 MIPS64r2 debugger call profile";
        }
        var observation = MipsAbiFlags.observe(image, cancelled);
        if (observation.status() != MipsAbiFlags.Status.AVAILABLE) {
            return "MIPS N32/N64 debugger calls require an unambiguous typed ABI record: " + observation.detail();
        }
        var fields = observation.fields().orElseThrow();
        return fields.version() == 0 && fields.isaLevel() == 64 && fields.isaRevision() == 2 &&
            fields.gprSize() == 2 && fields.cpr1Size() == 2 && fields.cpr2Size() == 0 &&
            fields.fpAbi() == 1 && fields.isaExtension() == 0 && fields.ases() == 0 &&
            (fields.flags1() & ~1L) == 0 && fields.flags2() == 0 ? "" :
            "MIPS N32/N64 debugger calls require the explicit MIPS64r2 64-bit GPR/FPR hard-float ABI profile";
    }

    private static String restriction(Map<String, TypeNode> types, TypeRef result, List<Parameter> parameters,
            boolean variadic, String profile, int pointerBytes, BooleanSupplier cancelled) {
        if (!profile.isEmpty()) return profile;
        if (variadic) return "MIPS N32/N64 variadic debugger calls have no validated transfer";
        if (!transfer(types, result, pointerBytes, true, cancelled)) {
            return "MIPS N32/N64 return type has no validated debugger transfer";
        }
        int hidden = 0;
        for (var parameter : parameters) {
            checkCancelled(cancelled);
            if (parameter.returnStorage()) {
                TypeNode node = plain(types, parameter.type(), cancelled);
                TypeNode returned = plain(types, result, cancelled);
                if (++hidden > 1 || !(returned instanceof TypeGraph.AggregateType) || returned.byteSize() <= 16 ||
                        !(node instanceof TypeGraph.IndirectionType pointer) ||
                        pointer.kind() != TypeGraph.IndirectionKind.POINTER || pointer.byteSize() != pointerBytes ||
                        !returned.equals(plain(types, pointer.target(), cancelled))) {
                    return "MIPS N32/N64 hidden return storage disagrees with the result type";
                }
                continue;
            }
            if (parameter.artificial() || !transfer(types, parameter.type(), pointerBytes, false, cancelled)) {
                return "MIPS N32/N64 parameter type has no validated debugger transfer";
            }
        }
        return "";
    }

    private static boolean transfer(Map<String, TypeNode> types, TypeRef reference, int pointerBytes,
            boolean result, BooleanSupplier cancelled) {
        TypeNode node = plain(types, reference, cancelled);
        if (node instanceof TypeGraph.VoidType) return result;
        if (node instanceof TypeGraph.BaseType base) {
            return integer(base) || (base.encoding() == TypeGraph.BaseEncoding.FLOAT &&
                (base.byteSize() == 4 || base.byteSize() == 8));
        }
        if (node instanceof TypeGraph.EnumType enumeration) return integerSize(enumeration.byteSize());
        if (node instanceof TypeGraph.IndirectionType pointer) {
            return pointer.kind() == TypeGraph.IndirectionKind.POINTER && pointer.byteSize() == pointerBytes;
        }
        // First wider aggregate envelope: two/three contiguous integer doublewords.
        // Mixed FP, packed, nested, union and wider aggregate transfers need their
        // own compiler/GDB evidence before widening this isolated classification.
        if (!(node instanceof TypeGraph.AggregateType aggregate) ||
                aggregate.kind() != TypeGraph.AggregateKind.STRUCTURE ||
                (aggregate.byteSize() != 16 && aggregate.byteSize() != 24) ||
                aggregate.members().size() != aggregate.byteSize() / 8) return false;
        long offset = 0;
        for (var member : aggregate.members()) {
            checkCancelled(cancelled);
            TypeNode field = plain(types, member.type(), cancelled);
            if (member.bitSize() != 0 || member.byteOffset() != offset ||
                    !(field instanceof TypeGraph.BaseType base) || base.byteSize() != 8 || !integer(base)) return false;
            offset += 8;
        }
        return true;
    }

    private static boolean integer(TypeGraph.BaseType base) {
        return integerSize(base.byteSize()) && switch (base.encoding()) {
            case SIGNED, UNSIGNED, SIGNED_CHAR, UNSIGNED_CHAR, BOOLEAN -> true;
            default -> false;
        };
    }

    private static boolean integerSize(long size) {
        return size == 1 || size == 2 || size == 4 || size == 8;
    }

    private static TypeNode plain(Map<String, TypeNode> types, TypeRef reference,
            BooleanSupplier cancelled) {
        var visited = new HashSet<String>();
        TypeNode node = types.get(reference.key());
        while (node instanceof TypeGraph.TypedefType || node instanceof TypeGraph.QualifiedType) {
            checkCancelled(cancelled);
            if (!visited.add(node.key()) || visited.size() > 64) return null;
            TypeNode next = types.get(node instanceof TypeGraph.TypedefType alias ? alias.target().key() :
                ((TypeGraph.QualifiedType) node).target().key());
            if (next == null || node.byteSize() != next.byteSize()) return null;
            node = next;
        }
        return node;
    }

    private static String combine(String existing, String restriction) {
        return existing.isEmpty() || existing.equals(restriction) ? restriction :
            existing.endsWith("; " + restriction) ? existing : existing + "; " + restriction;
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) {
            throw new CancellationException("MIPS wide call classification cancelled");
        }
    }
}
