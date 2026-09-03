package ghidradwarfforge.types;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Native-independent canonical type graph. References use stable keys instead
 * of nested Java objects, so recursive types never recurse during traversal.
 */
public record TypeGraph(List<TypeNode> nodes) {
    public enum BaseEncoding {
        ADDRESS, BOOLEAN, FLOAT, SIGNED, SIGNED_CHAR, UNSIGNED, UNSIGNED_CHAR, UTF
    }

    public enum AggregateKind {
        STRUCTURE, UNION
    }

    public enum IndirectionKind {
        POINTER, LVALUE_REFERENCE, RVALUE_REFERENCE
    }

    public enum Qualifier {
        ATOMIC, CONST, RESTRICT, VOLATILE
    }

    public record TypeRef(String key) {
        public TypeRef {
            requireText(key, "type reference key");
        }
    }

    public sealed interface TypeNode permits VoidType, BaseType, IndirectionType,
            QualifiedType, ArrayType, TypedefType, EnumType, AggregateType,
            SubroutineType, OpaqueType {
        String key();

        String name();

        long byteSize();

        List<TypeRef> references();
    }

    public record VoidType(String key) implements TypeNode {
        public VoidType {
            requireText(key, "void key");
        }

        @Override
        public String name() {
            return "void";
        }

        @Override
        public long byteSize() {
            return 0;
        }

        @Override
        public List<TypeRef> references() {
            return List.of();
        }
    }

    public record BaseType(String key, String name, long byteSize,
            BaseEncoding encoding) implements TypeNode {
        public BaseType {
            common(key, name, byteSize, false);
            if (encoding == null) {
                throw new IllegalArgumentException("base encoding is required");
            }
        }

        @Override
        public List<TypeRef> references() {
            return List.of();
        }
    }

    public record IndirectionType(String key, String name, long byteSize,
            IndirectionKind kind, TypeRef target) implements TypeNode {
        public IndirectionType {
            common(key, name, byteSize, false);
            if (kind == null || target == null) {
                throw new IllegalArgumentException("indirection kind/target are required");
            }
        }

        @Override
        public List<TypeRef> references() {
            return List.of(target);
        }
    }

    public record QualifiedType(String key, String name, long byteSize,
            List<Qualifier> qualifiers, TypeRef target) implements TypeNode {
        public QualifiedType {
            common(key, name, byteSize, true);
            if (target == null || qualifiers == null || qualifiers.isEmpty()) {
                throw new IllegalArgumentException("qualified type requires qualifiers/target");
            }
            qualifiers = qualifiers.stream().distinct().sorted().toList();
        }

        @Override
        public List<TypeRef> references() {
            return List.of(target);
        }
    }

    public record ArrayType(String key, String name, long byteSize, TypeRef element,
            long elementCount) implements TypeNode {
        public ArrayType {
            common(key, name, byteSize, true);
            if (element == null || elementCount < 0) {
                throw new IllegalArgumentException("invalid array element/count");
            }
        }

        @Override
        public List<TypeRef> references() {
            return List.of(element);
        }
    }

    public record TypedefType(String key, String name, long byteSize,
            TypeRef target) implements TypeNode {
        public TypedefType {
            common(key, name, byteSize, true);
            if (target == null) {
                throw new IllegalArgumentException("typedef target is required");
            }
        }

        @Override
        public List<TypeRef> references() {
            return List.of(target);
        }
    }

    public record Enumerator(String name, long value) {
        public Enumerator {
            requireText(name, "enumerator name");
        }
    }

    public record EnumType(String key, String name, long byteSize, boolean signed,
            List<Enumerator> values) implements TypeNode {
        public EnumType {
            common(key, name, byteSize, false);
            values = List.copyOf(values);
        }

        @Override
        public List<TypeRef> references() {
            return List.of();
        }
    }

    /**
     * Aggregate member layout as reported by Ghidra. A zero {@code bitSize}
     * denotes an ordinary (non-bit-field) member. For a bit field,
     * {@code storageBitOffset} is retained separately from the byte offset so a
     * target-aware DWARF writer can apply the correct endian convention.
     */
    public record Member(String name, TypeRef type, long byteOffset, int bitSize,
            int storageBitOffset) {
        public Member {
            requireText(name, "member name");
            if (type == null || byteOffset < 0 || bitSize < 0 ||
                    storageBitOffset < 0 || (bitSize == 0 && storageBitOffset != 0)) {
                throw new IllegalArgumentException("invalid aggregate member");
            }
        }

        public Member(String name, TypeRef type, long byteOffset) {
            this(name, type, byteOffset, 0, 0);
        }
    }

    public record AggregateType(String key, String name, long byteSize,
            AggregateKind kind, List<Member> members) implements TypeNode {
        public AggregateType {
            common(key, name, byteSize, true);
            if (kind == null) {
                throw new IllegalArgumentException("aggregate kind is required");
            }
            members = List.copyOf(members);
        }

        @Override
        public List<TypeRef> references() {
            return members.stream().map(Member::type).toList();
        }
    }

    public record Parameter(String name, TypeRef type, boolean artificial) {
        public Parameter {
            if (name == null || type == null) {
                throw new IllegalArgumentException("invalid subroutine parameter");
            }
        }
    }

    public record SubroutineType(String key, String name, long byteSize,
            TypeRef returnType, List<Parameter> parameters,
            boolean variadic) implements TypeNode {
        public SubroutineType {
            common(key, name, byteSize, true);
            if (returnType == null) {
                throw new IllegalArgumentException("subroutine return type is required");
            }
            parameters = List.copyOf(parameters);
        }

        @Override
        public List<TypeRef> references() {
            List<TypeRef> result = new ArrayList<>();
            result.add(returnType);
            parameters.stream().map(Parameter::type).forEach(result::add);
            return List.copyOf(result);
        }
    }

    public record OpaqueType(String key, String name, long byteSize,
            String diagnostic) implements TypeNode {
        public OpaqueType {
            common(key, name, byteSize, true);
            requireText(diagnostic, "opaque-type diagnostic");
        }

        @Override
        public List<TypeRef> references() {
            return List.of();
        }
    }

    public TypeGraph {
        if (nodes == null) {
            throw new IllegalArgumentException("type nodes are required");
        }
        Map<String, TypeNode> byKey = new HashMap<>();
        for (TypeNode node : nodes) {
            if (node == null || byKey.put(node.key(), node) != null) {
                throw new IllegalArgumentException("null or duplicate type node");
            }
        }
        for (TypeNode node : nodes) {
            for (TypeRef reference : node.references()) {
                if (!byKey.containsKey(reference.key())) {
                    throw new IllegalArgumentException("type " + node.key() +
                        " refers to missing type " + reference.key());
                }
            }
        }
        nodes = nodes.stream().sorted(Comparator.comparing(TypeNode::key)).toList();
    }

    public Map<String, TypeNode> byKey() {
        Map<String, TypeNode> result = new LinkedHashMap<>();
        for (TypeNode node : nodes) {
            result.put(node.key(), node);
        }
        return Collections.unmodifiableMap(result);
    }

    private static void common(String key, String name, long byteSize,
            boolean zeroSizeAllowed) {
        requireText(key, "type key");
        requireText(name, "type name");
        if (byteSize < 0 || (!zeroSizeAllowed && byteSize == 0)) {
            throw new IllegalArgumentException("invalid byte size for " + key);
        }
    }

    private static void requireText(String value, String description) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(description + " is required");
        }
    }
}
