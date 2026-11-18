package ghidradwarfforge;

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
import ghidra.program.model.listing.VariableStorage;
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
        RegisterLocalMetadataSmoke.check(program, function, local, expected,
            (owner, value) -> prove(program, owner, value, map, rejected));
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
