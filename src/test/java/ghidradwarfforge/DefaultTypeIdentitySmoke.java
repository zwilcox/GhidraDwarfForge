package ghidradwarfforge;

import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;
import java.util.Map;
import java.util.function.Consumer;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DefaultDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.util.UniversalID;
import ghidra.util.UniversalIdGenerator;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.types.TypeGraph;

/** Exercises actual Ghidra type identities without native production or a Program. */
public final class DefaultTypeIdentitySmoke {
    private DefaultTypeIdentitySmoke() {
    }

    public static void main(String[] args) throws Exception {
        UniversalIdGenerator.initialize();
        Method stableKey = Class.forName("ghidradwarfforge.GhidraTypeGraph$Extractor")
            .getDeclaredMethod("stableKey", DataType.class);
        stableKey.setAccessible(true);
        DataType generic = DefaultDataType.dataType;
        require(generic == DataType.DEFAULT && generic.getUniversalID() != null,
            "pinned generic singleton must expose its transient ID");
        String genericKey = key(stableKey, generic);
        require(genericKey.equals(
            "type:ghidra.program.model.data.DefaultDataType:/undefined:1"),
            "generic identity must use its stable class/path/length fallback");
        require(key(stableKey, generic.clone(null)).equals(genericKey) &&
                key(stableKey, generic.copy(null)).equals(genericKey),
            "singleton copies must retain the same identity");

        // Name, size, and missing manager do not justify discarding another type's ID.
        var analyst = new StructureDataType("undefined", 1);
        requireUid(stableKey, analyst);
        require(!key(stableKey, analyst).equals(genericKey),
            "analyst type named undefined must remain distinct");
        var alias = new TypedefDataType("generic_alias", generic);
        requireUid(stableKey, alias);
        require(!key(stableKey, Undefined1DataType.dataType).equals(genericKey),
            "separate undefined built-ins must remain distinct");

        // Explicit IDs model persisted/imported identity across separate objects.
        DataType imported = persisted(0x12345678L);
        DataType reopened = persisted(0x12345678L);
        DataType distinct = persisted(0x23456789L);
        requireUid(stableKey, imported);
        requireUid(stableKey, reopened);
        requireUid(stableKey, distinct);
        require(key(stableKey, imported).equals(key(stableKey, reopened)),
            "same persisted ID must keep its canonical key");
        require(!key(stableKey, imported).equals(key(stableKey, distinct)),
            "distinct persisted IDs must not collapse by matching shape or name");
        collidingLayouts();
        System.out.println("default-type-identity-smoke=PASS");
    }

    /** Actual imported Ghidra objects can share an ID without sharing a layout. */
    private static void collidingLayouts() throws Exception {
        Class<?> extractorClass = Class.forName("ghidradwarfforge.GhidraTypeGraph$Extractor");
        var constructor = extractorClass.getDeclaredConstructor(Program.class, Consumer.class);
        constructor.setAccessible(true);
        var reserve = extractorClass.getDeclaredMethod("reserve", DataType.class);
        reserve.setAccessible(true);
        var drain = extractorClass.getDeclaredMethod("drain", TaskMonitor.class);
        drain.setAccessible(true);
        var nodesField = extractorClass.getDeclaredField("nodes");
        nodesField.setAccessible(true);
        // Each run recreates the imported objects. No process-local identity may affect the result.
        String previousKeys = null;
        for (int run = 0; run < 2; run++) {
            Object extractor = constructor.newInstance(null, (Consumer<String>) ignored -> { });
            StructureDataType first = persistedLayout(1);
            StructureDataType second = persistedLayout(2);
            require(!first.isEquivalent(second), "collision fixture unexpectedly has equivalent layouts");
            var firstRef = (TypeGraph.TypeRef) reserve.invoke(extractor, first);
            require(firstRef.equals(reserve.invoke(extractor, first)), "same object acquired a second type identity");
            require(firstRef.equals(reserve.invoke(extractor, persistedLayout(1))), "equivalent imported layout was duplicated");
            var secondRef = (TypeGraph.TypeRef) reserve.invoke(extractor, second);
            require(!firstRef.equals(secondRef), "conflicting imported layouts collapsed into one type");
            require(secondRef.equals(reserve.invoke(extractor, persistedLayout(2))), "equivalent conflicting layout was duplicated");
            String keys = firstRef.key() + "\n" + secondRef.key();
            if (previousKeys != null) require(previousKeys.equals(keys), "collision keys depend on transient object identity");
            previousKeys = keys;
            try {
                reserve.invoke(extractor, persistedLayout(3));
                throw new AssertionError("ambiguous third layout silently replaced a previous type");
            }
            catch (InvocationTargetException rejected) {
                require(rejected.getCause() instanceof IllegalStateException &&
                    rejected.getCause().getMessage().contains("cannot deterministically distinguish Ghidra type"),
                    "ambiguous identity failed for an unrelated reason: " + rejected.getCause());
            }
            drain.invoke(extractor, TaskMonitor.DUMMY);
            Map<?, ?> nodes = (Map<?, ?>) nodesField.get(extractor);
            require(nodes.get(firstRef.key()) instanceof TypeGraph.AggregateType aggregate && aggregate.byteSize() == 1,
                "first imported layout was overwritten");
            require(nodes.get(secondRef.key()) instanceof TypeGraph.AggregateType aggregate && aggregate.byteSize() == 2,
                "second imported layout was overwritten");
            require(nodes.values().stream().filter(TypeGraph.AggregateType.class::isInstance).count() == 2,
                "failed reservation left a partial aggregate node");
        }
    }

    private static StructureDataType persistedLayout(int bytes) {
        return new StructureDataType(new CategoryPath("/Imported"), "collision", bytes,
            new UniversalID(0x34567890L), null, 0, 0, null);
    }

    private static DataType persisted(long id) {
        return new StructureDataType(new CategoryPath("/Imported"), "undefined", 1,
            new UniversalID(id), null, 0, 0, null);
    }

    private static String key(Method method, DataType type) throws Exception {
        return (String) method.invoke(null, type);
    }

    private static void requireUid(Method method, DataType type) throws Exception {
        require(type.getUniversalID() != null, "control must expose a persistent ID");
        require(key(method, type).equals("uid:" +
                Long.toUnsignedString(type.getUniversalID().getValue(), 16)),
            "non-default type ID must remain authoritative");
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
