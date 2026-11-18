package ghidradwarfforge;

import java.nio.ByteOrder;
import java.util.List;
import java.util.Map;

import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.Register;
import ghidra.program.util.DefaultLanguageService;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.TargetRegisterMap.PairPiece;
import ghidradwarfforge.locations.TargetRegisterMap.RegisterSlice;
import ghidradwarfforge.locations.VariableStorageModel.CompositeStorage;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.locations.VariableStorageModel.Storage;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;

/** Target descriptions must agree with actual pinned language register hierarchies. */
final class RegisterProfileAgreementSmoke {
    private static int checks;

    static void check() throws Exception {
        refused(mapped(null, 4, TargetRegisterMap.forTarget("arm")), "unresolved language register must stay unavailable");
        for (String id : List.of("ARM:LE:32:v8", "ARM:LEBE:32:v8LEInstruction")) {
            Language language = language(id);
            for (int index : new int[] {0, 1, 31}) slices(language, index);
        }
        for (String endian : List.of("LE", "BE")) {
            Language language = language("MIPS:" + endian + ":32:default");
            for (int first : new int[] {0, 12, 30}) pairs(language, first, endian.equals("BE"));
        }
        oversizedPairChildren();
        System.out.println("register-profile-agreement=PASS checks=" + checks);
    }

    private static void oversizedPairChildren() throws Exception {
        // Unlike MIPS's two full-width children, this actual eight-child tree
        // isolates the child-width check from offset and total-width checks.
        // This rejection-only fixture is not a PowerPC ABI or export profile.
        var language = language("PowerPC:BE:32:default");
        var register = language.getRegister("crall");
        require(register == register.getBaseRegister() && register.getBitLength() == 64,
            "pinned condition-register container changed");
        for (int index = 0; index < 3; index++) {
            var child = language.getRegister("cr" + (7 - index));
            require(register.getChildRegisters().contains(child) && child.getBitLength() == 8 &&
                child.getLeastSignificantBitInBaseRegister() == index * 8, "pinned condition-register child changed");
        }
        for (int split : new int[] {8, 16}) {
            String second = split == 8 ? "cr6" : "cr5";
            var wrong = new TargetRegisterMap("test-only-profile", "deliberately incompatible child widths",
                Map.of("cr7", 0, second, 1), Map.of("crall", List.of(
                    new PairPiece("cr7", 0, split), new PairPiece(second, split, 64 - split))));
            refused(mapped(register, 8, wrong), "paired child cannot absorb unrelated physical siblings");
        }
        // Both listed children are physically correct, but six others remain unrepresented.
        var incomplete = new TargetRegisterMap("test-only-profile", "incomplete real child coverage",
            Map.of("cr7", 0, "cr6", 1), Map.of("crall", List.of(
                new PairPiece("cr7", 0, 8), new PairPiece("cr6", 8, 8))));
        Storage missing = mapped(register, 8, incomplete);
        refused(missing, "two valid children cannot represent the entire eight-child container");
        require(((UnavailableStorage) missing).diagnostic().contains("paired pieces do not cover its size"),
            "incomplete child coverage was rejected before verifying the real child layouts");
    }

    private static void slices(Language language, int index) {
        String name = "s" + index, parent = "d" + index / 2;
        Register register = language.getRegister(name);
        int offset = (index % 2) * 4;
        var good = new RegisterSlice(parent, 64, offset, 32, offset * 8);
        var map = sliceMap(name, good);
        Storage expected = mapped(register, 4, map);
        require(expected instanceof RegisterStorage r && r.register().dwarfNumber() == 256 + index / 2 &&
            r.bitSize() == 32 && r.valueBitOffset() == offset * 8, "known VFP half has incorrect logical bits");
        for (var wrong : List.of(
                new RegisterSlice("d" + ((index / 2 + 1) % 16), 64, offset, 32, offset * 8),
                new RegisterSlice(parent, 128, offset, 32, offset * 8),
                new RegisterSlice(parent, 64, 4 - offset, 32, offset * 8),
                new RegisterSlice(parent, 64, offset, 16, offset * 8))) {
            refused(mapped(register, 4, sliceMap(name, wrong)), "incompatible logical slice " + wrong);
        }
        refused(mapped(register, 2, map), "partial formal size cannot borrow a full logical slice");
        for (int size : new int[] {0, -1, 5, Integer.MAX_VALUE}) {
            refused(mapped(register, size, map), "invalid register extent " + size);
        }
        require(expected.equals(mapped(register, 4, map)), "rejected profile changed the valid mapping");
        require(language.getRegister(name) == register && register.getParentRegister() != null,
            "profile checks replaced a language register");
    }

    private static TargetRegisterMap sliceMap(String name, RegisterSlice slice) {
        var ordinary = TargetRegisterMap.forTarget("arm");
        return new TargetRegisterMap("arm", "test-only logical slice agreement", ordinary.dwarfNumbers(),
            Map.of(), Map.of(name, slice), ByteOrder.LITTLE_ENDIAN);
    }

    private static void pairs(Language language, int first, boolean big) {
        String low = "f" + first, high = "f" + (first + 1), name = low + "_" + (first + 1);
        String other = "f" + ((first + 2) % 32);
        Register register = language.getRegister(name);
        var lowPiece = new PairPiece(low, 0, 32);
        var highPiece = new PairPiece(high, 32, 32);
        var order = big ? List.of(highPiece, lowPiece) : List.of(lowPiece, highPiece);
        var good = pairMap(name, order, big);
        Storage expected = mapped(register, 8, good);
        require(expected instanceof CompositeStorage, "known FP32 pair must have two register pieces");
        var pieces = ((CompositeStorage) expected).pieces();
        require(pieces.size() == 2, "paired floating value lost a child");
        for (int index = 0; index < 2; index++) {
            int number = first + (big ? 1 - index : index);
            require(pieces.get(index).bitSize() == 32 && pieces.get(index).storage() instanceof RegisterStorage r &&
                r.register().dwarfNumber() == 32 + number && r.bitSize() == 32 && r.valueBitOffset() == 0,
                "pair does not follow independent object-memory order");
        }
        for (var wrong : List.of(
                List.of(new PairPiece(other, 0, 32), highPiece),
                List.of(lowPiece, new PairPiece(other, 32, 32)),
                List.of(new PairPiece(high, 0, 32), new PairPiece(low, 32, 32)),
                List.of(new PairPiece(low, 0, 16), new PairPiece(high, 16, 48)),
                List.of(lowPiece, new PairPiece(high, 32, 16)))) {
            refused(mapped(register, 8, pairMap(name, wrong, big)), "incompatible physical pair " + wrong);
        }
        refused(mapped(language.getRegister(low), 4, pairMap(low, order, big)),
            "a child register cannot impersonate the complete physical pair");
        Storage partial = mapped(register, 4, good);
        refused(partial, "half-width value cannot use the complete paired-register mapping");
        require(((UnavailableStorage) partial).diagnostic().contains("not the complete paired register"),
            "partial paired-register request failed at an unrelated check");
        require(expected.equals(mapped(register, 8, good)), "rejected pair description changed the valid mapping");
        require(language.getRegister(name) == register, "profile checks replaced a paired register");
    }

    private static TargetRegisterMap pairMap(String name, List<PairPiece> pieces, boolean big) {
        String target = big ? "mips" : "mipsel";
        return new TargetRegisterMap(target, "test-only physical pair agreement",
            TargetRegisterMap.forTarget(target).dwarfNumbers(), Map.of(name, pieces));
    }

    private static Storage mapped(Register register, int bytes, TargetRegisterMap map) {
        return GhidraVariableStorage.mappedRegister(register, bytes, map, "profile agreement fixture");
    }

    private static void refused(Storage storage, String message) {
        require(storage instanceof UnavailableStorage u && u.reason() == OmissionReason.UNSUPPORTED_STORAGE, message);
    }

    private static Language language(String name) throws Exception {
        return DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(name));
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
