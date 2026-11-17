package ghidradwarfforge;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.List;

import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.lang.DynamicVariableStorage;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.Storage;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;

/** Actual saved ownership boundaries for the conservative straight-line local fallback. */
final class LaterLocalOwnershipSmoke {
    private static int checks;

    static void check(ProgramDB program, Function function, LocalVariable local,
            TargetRegisterMap map, Storage rejected, List<GhidraVariableStorage.StorageInterval> expected)
            throws Exception {
        metadata(program, function, local, map, rejected, expected);
        var base = local.getRegister().getBaseRegister();
        var body = new AddressSet(function.getBody());
        byte[] original = new byte[Math.toIntExact(body.getNumAddresses())];
        program.getMemory().getBytes(body.getMinAddress(), original);
        for (OmissionReason reason : OmissionReason.values()) {
            if (reason == OmissionReason.UNKNOWN_LIFETIME) continue;
            require(GhidraVariableStorage.localPrefix(program, function, local, map,
                new UnavailableStorage(reason, "independent omission"), TaskMonitor.DUMMY).isEmpty(),
                "local fallback replaced an unrelated omission: " + reason);
        }
        require(GhidraVariableStorage.localPrefix(program, function, local, map,
            expected.get(1).storage(), TaskMonitor.DUMMY).isEmpty(), "local fallback replaced a proven location");

        // A byte immediately before or after the physical register is disjoint.
        // Every byte inside it conflicts, including bytes beyond a narrower local.
        for (int offset = -1; offset <= base.getMinimumByteSize(); offset++) {
            var node = new Varnode(base.getAddress().add(offset), 1);
            var storage = new VariableStorage(program, node);
            var other = function.addLocalVariable(new LocalVariableImpl("byte_owner", 5,
                ByteDataType.dataType, storage, false, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
            try {
                require(other != local && other.getVariableStorage().equals(storage)
                    && other.getFirstUseOffset() == 5, "database did not retain exact separate byte ownership");
                boolean overlaps = offset >= 0 && offset < base.getMinimumByteSize();
                var actual = GhidraVariableStorage.localPrefix(program, function, local, map, rejected, TaskMonitor.DUMMY);
                require(overlaps ? actual.isEmpty() : actual.equals(expected),
                    "wrong physical ownership boundary at byte " + offset);
            }
            finally { function.removeVariable(other); }
        }
        var stack = function.addLocalVariable(new LocalVariableImpl("stack_owner", IntegerDataType.dataType,
            -16, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
        try {
            require(prove(program, function, local, map, rejected).equals(expected),
                "disjoint stack object invalidated register ownership");
        }
        finally { function.removeVariable(stack); }
        var unknown = function.addLocalVariable(new LocalVariableImpl("unknown_owner", 5,
            IntegerDataType.dataType, VariableStorage.UNASSIGNED_STORAGE, true, program, SourceType.USER_DEFINED),
            SourceType.USER_DEFINED);
        try {
            require(unknown.getVariableStorage().isUnassignedStorage(), "unknown fixture gained storage");
            require(prove(program, function, local, map, rejected).equals(expected),
                "unassigned variable claimed the local's register");
        }
        finally { function.removeVariable(unknown); }

        // Both pieces are real register varnodes. A disjoint first piece must
        // not conceal a second piece overlapping the local's physical register.
        boolean x86 = local.getRegister().getName().startsWith("R");
        var separate = program.getRegister(x86 ? (local.getLength() == 4 ? "R11D" : "R11") :
            (local.getLength() == 4 ? "w10" : "x10"));
        require(separate.getBaseRegister() != base, "composite prefix must use another physical register");
        var far = new Varnode(separate.getAddress(), local.getLength());
        var overlapping = new Varnode(local.getRegister().getAddress(), local.getLength());
        var pair = new VariableStorage(program, far, overlapping);
        var composite = function.addLocalVariable(new LocalVariableImpl("composite_owner", 5,
            new ArrayDataType(ByteDataType.dataType, 2 * local.getLength(), 1), pair, false, program,
            SourceType.USER_DEFINED), SourceType.USER_DEFINED);
        try {
            require(composite.getVariableStorage().equals(pair) && pair.getVarnodeCount() == 2,
                "saved composite owner changed pieces");
            require(prove(program, function, local, map, rejected).isEmpty(),
                "later composite piece concealed overlapping ownership");
        }
        finally { function.removeVariable(composite); }

        var split = new AddressSet(body);
        split.delete(body.getMaxAddress().subtract(1), body.getMaxAddress().subtract(1));
        function.setBody(split);
        require(function.getBody().getNumAddressRanges() == 2, "fixture did not create discontiguous body");
        require(prove(program, function, local, map, rejected).isEmpty(), "straight-line fallback crossed body gap");
        function.setBody(body);
        long modifications = program.getModificationNumber();
        require(prove(program, function, local, map, rejected).equals(expected), "ownership controls changed baseline proof");
        require(program.getModificationNumber() == modifications && function.getBody().equals(body),
            "local proof mutated the program");
        byte[] after = new byte[original.length];
        program.getMemory().getBytes(body.getMinAddress(), after);
        require(Arrays.equals(original, after), "ownership proof changed machine bytes");
        System.out.println("later-local-ownership=PASS checks=" + checks);
    }

    private static void metadata(ProgramDB program, Function original, LocalVariable saved,
            TargetRegisterMap map, Storage rejected, List<GhidraVariableStorage.StorageInterval> expected)
            throws Exception {
        long modification = program.getModificationNumber();
        var storage = saved.getVariableStorage();
        var type = saved.getDataType();
        var register = saved.getRegister();
        int firstUse = saved.getFirstUseOffset();
        Object owner = new Object();
        var foreign = new ProgramDB("foreign-register-owner", program.getLanguage(),
            program.getLanguage().getCompilerSpecByID(program.getCompilerSpec().getCompilerSpecID()), owner);
        try {
            for (String defect : List.of("transparent", "wrong-function", "foreign-program", "foreign-function",
                    "invalid", "unassigned", "missing-storage", "bad-storage", "unknown-storage", "void-storage",
                    "foreign-storage", "indirect-storage", "stack-storage", "short-storage", "missing-register",
                    "wrong-register", "short-register", "zero-width", "negative-width", "short-type")) {
                Function[] function = new Function[1];
                LocalVariable[] local = new LocalVariable[1];
                function[0] = (Function) Proxy.newProxyInstance(Function.class.getClassLoader(),
                    new Class<?>[] { Function.class }, (proxy, method, args) -> {
                        if (method.getName().equals("getProgram") && defect.equals("foreign-function")) return foreign;
                        if (method.getName().equals("getAllVariables")) {
                            return Arrays.stream(original.getAllVariables())
                                .map(value -> value == saved ? local[0] : value).toArray(Variable[]::new);
                        }
                        try { return method.invoke(original, args); }
                        catch (InvocationTargetException failure) { throw failure.getCause(); }
                    });
                local[0] = (LocalVariable) Proxy.newProxyInstance(LocalVariable.class.getClassLoader(),
                    new Class<?>[] { LocalVariable.class }, (proxy, method, args) -> {
                        String name = method.getName();
                        if (name.equals("getFunction")) return defect.equals("wrong-function") ? original : function[0];
                        if (name.equals("getProgram") && defect.equals("foreign-program")) return foreign;
                        if (name.equals("isValid") && defect.equals("invalid")) return false;
                        if (name.equals("hasAssignedStorage") && defect.equals("unassigned")) return false;
                        if (name.equals("getLength")) {
                            if (defect.equals("zero-width")) return 0;
                            if (defect.equals("negative-width")) return -1;
                        }
                        if (name.equals("getDataType") && defect.equals("short-type")) return ByteDataType.dataType;
                        if (name.equals("getRegister")) {
                            if (defect.equals("missing-register")) return null;
                            if (defect.equals("wrong-register")) return program.getRegister(
                                register.getName().startsWith("R") ? (saved.getLength() == 4 ? "R11D" : "R11") :
                                    (saved.getLength() == 4 ? "w10" : "x10"));
                            if (defect.equals("short-register")) return program.getRegister(
                                register.getName().startsWith("R") ? "R10W" : "w9");
                        }
                        if (name.equals("getVariableStorage")) {
                            if (defect.equals("missing-storage")) return null;
                            if (defect.equals("bad-storage")) return VariableStorage.BAD_STORAGE;
                            if (defect.equals("unknown-storage")) return VariableStorage.UNASSIGNED_STORAGE;
                            if (defect.equals("void-storage")) return VariableStorage.VOID_STORAGE;
                            if (defect.equals("foreign-storage")) return new VariableStorage(foreign, register);
                            if (defect.equals("indirect-storage")) return new DynamicVariableStorage(program, true, storage.getVarnodes());
                            if (defect.equals("stack-storage")) return new VariableStorage(program, -16, saved.getLength());
                            if (defect.equals("short-storage")) return new VariableStorage(program,
                                new Varnode(register.getAddress(), saved.getLength() - 1));
                        }
                        try { return method.invoke(saved, args); }
                        catch (InvocationTargetException failure) { throw failure.getCause(); }
                    });
                // AArch64 w9 already is the narrowest ordinary integer register;
                // that control deliberately remains valid for the four-byte local.
                boolean unchanged = defect.equals("transparent") ||
                    (defect.equals("short-register") && register.getName().equals("w9"));
                var actual = prove(program, function[0], local[0], map, rejected);
                require(unchanged ? actual.equals(expected) : actual.isEmpty(),
                    "inconsistent saved register metadata acquired a lifetime: " + defect + " " + actual);
                require(prove(program, original, saved, map, rejected).equals(expected),
                    "metadata refusal changed subsequent local proof: " + defect);
                require(program.getModificationNumber() == modification && saved.getVariableStorage().equals(storage) &&
                    saved.getDataType().equals(type) && saved.getRegister().equals(register) && saved.getFirstUseOffset() == firstUse,
                    "register proof changed saved identity: " + defect);
            }
        }
        finally { foreign.flushEvents(); foreign.release(owner); }
    }

    static void invalidSavedOwner(ProgramDB program, Function function, LocalVariable local,
            TargetRegisterMap map, Storage rejected, List<GhidraVariableStorage.StorageInterval> expected)
            throws Exception {
        require(prove(program, function, local, map, rejected).equals(expected), "invalid-owner baseline differs");
        var bad = function.addLocalVariable(new LocalVariableImpl("invalid_owner", 5,
            IntegerDataType.dataType, VariableStorage.BAD_STORAGE, true, program, SourceType.USER_DEFINED),
            SourceType.USER_DEFINED);
        require(bad.hasAssignedStorage() && !bad.getVariableStorage().isValid(), "invalid saved fixture was normalized");
        require(prove(program, function, local, map, rejected).isEmpty(), "invalid saved owner allowed a local lifetime");
        // Leave this row until the owned database is released: deleting invalid
        // storage can leave a deleted variable in this Ghidra version's cache.
    }

    private static List<GhidraVariableStorage.StorageInterval> prove(ProgramDB program, Function function,
            LocalVariable local, TargetRegisterMap map, Storage rejected) throws Exception {
        return GhidraVariableStorage.localPrefix(program, function, local, map, rejected, TaskMonitor.DUMMY);
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
