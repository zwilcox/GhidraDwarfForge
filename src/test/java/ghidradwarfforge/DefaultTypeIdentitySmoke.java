package ghidradwarfforge;

import java.lang.reflect.Method;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DefaultDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.util.UniversalID;
import ghidra.util.UniversalIdGenerator;

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
        System.out.println("default-type-identity-smoke=PASS");
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
