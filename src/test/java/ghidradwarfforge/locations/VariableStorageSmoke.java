package ghidradwarfforge.locations;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import ghidradwarfforge.dwarf.DwarfLocationExpression;
import ghidradwarfforge.dwarf.DwarfLocationExpression.AddressOperation;
import ghidradwarfforge.dwarf.DwarfLocationExpression.Expression;
import ghidradwarfforge.dwarf.DwarfLocationExpression.GenericOperation;
import ghidradwarfforge.dwarf.DwarfLocationExpression.Omitted;
import ghidradwarfforge.locations.VariableStorageModel.CompositeStorage;
import ghidradwarfforge.locations.VariableStorageModel.Confidence;
import ghidradwarfforge.locations.VariableStorageModel.Evidence;
import ghidradwarfforge.locations.VariableStorageModel.LocationRange;
import ghidradwarfforge.locations.VariableStorageModel.MemoryStorage;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.Piece;
import ghidradwarfforge.locations.VariableStorageModel.RegisterRelativeStorage;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.locations.VariableStorageModel.StackStorage;
import ghidradwarfforge.locations.VariableStorageModel.Storage;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;
import ghidradwarfforge.locations.VariableStorageModel.VariableKind;
import ghidradwarfforge.locations.VariableStorageModel.VariableLocation;

/** Native-free storage, live-range, and target-register mapping checks. */
public final class VariableStorageSmoke {
    private VariableStorageSmoke() {
    }

    public static void main(String[] args) {
        TargetRegisterMap x86 = TargetRegisterMap.forTarget("x86_64");
        TargetRegisterMap arm = TargetRegisterMap.forTarget("aarch64");
        TargetRegisterMap arm32 = TargetRegisterMap.forTarget("arm");
        TargetRegisterMap mipsBe = TargetRegisterMap.forTarget("mips");
        TargetRegisterMap mipsLe = TargetRegisterMap.forTarget("mipsel");
        if (x86.dwarfNumbers().size() != 59 || arm.dwarfNumbers().size() != 64 ||
                arm32.dwarfNumbers().size() != 82 ||
                mipsBe.dwarfNumbers().size() != 64 ||
                !mipsBe.dwarfNumbers().equals(mipsLe.dwarfNumbers())) {
            throw new AssertionError("target mapping table is incomplete");
        }
        assertRegister(x86.register("RAX", 0, 64), 0);
        assertRegister(x86.register("RDI", 0, 64), 5);
        assertRegister(x86.register("RSP", 0, 64), 7);
        assertRegister(x86.register("XMM15", 0, 128), 32);
        assertRegister(arm.register("x30", 0, 64), 30);
        assertRegister(arm.register("sp", 0, 64), 31);
        assertRegister(arm.register("q31", 0, 128), 95);
        assertRegister(arm32.register("r0", 0, 32), 0);
        assertRegister(arm32.register("sp", 0, 32), 13);
        assertRegister(arm32.register("d31", 0, 64), 287);
        assertRegister(mipsBe.register("a0", 0, 32), 4);
        assertRegister(mipsBe.register("sp", 0, 32), 29);
        assertRegister(mipsLe.register("f31", 0, 32), 63);

        Storage unknown = x86.register("NOT_A_GHIDRA_REGISTER", 0, 64);
        if (!(unknown instanceof UnavailableStorage unavailable) ||
                unavailable.reason() != OmissionReason.UNMAPPED_REGISTER ||
                unknown.available()) {
            throw new AssertionError("unknown register became an available location");
        }

        Evidence analyst = new Evidence(Confidence.USER_DEFINED, "fixture analyst");
        Evidence analysis = new Evidence(Confidence.ANALYSIS, "fixture analysis");
        VariableLocation changing = new VariableLocation("function_b", 0x2000,
            "changing", VariableKind.LOCAL, 8, List.of(
                new LocationRange(0x2020, 0x2030, x86.register("RAX", 0, 64),
                    analysis),
                new LocationRange(0x2000, 0x2020, new StackStorage(-32), analyst)));
        if (!changing.changesLocation() || !changing.hasDefensibleLocation() ||
                changing.locations().get(0).start() != 0x2000) {
            throw new AssertionError("changing location was not retained deterministically");
        }

        Storage baseRelative = x86.registerRelative("RSP", 24);
        if (!(baseRelative instanceof RegisterRelativeStorage relative) ||
                relative.register().dwarfNumber() != 7 || relative.byteOffset() != 24) {
            throw new AssertionError("register-relative storage failed");
        }
        CompositeStorage composite = new CompositeStorage(List.of(
            new Piece(x86.register("RAX", 0, 32), 32),
            new Piece(x86.register("RDX", 0, 32), 32)));
        VariableLocation pieces = new VariableLocation("function_a", 0x1000,
            "pieces", VariableKind.PARAMETER, 8,
            List.of(new LocationRange(0x1000, 0x1010, composite, analyst)));
        VariableLocation relativeVariable = new VariableLocation("function_a", 0x1000,
            "relative", VariableKind.LOCAL, 8,
            List.of(new LocationRange(0x1000, 0x1010, baseRelative, analysis)));
        VariableLocation memory = new VariableLocation("function_a", 0x1000,
            "memory", VariableKind.LOCAL, 4, List.of(new LocationRange(0x1000,
                0x1010, new MemoryStorage(0x5000), analyst)));
        VariableLocation omitted = new VariableLocation("function_c", 0x3000,
            "optimized", VariableKind.LOCAL, 4, List.of(new LocationRange(0x3000,
                0x3010, new UnavailableStorage(OmissionReason.OPTIMIZED_AWAY,
                    "fixture optimized away"), analysis)));
        if (omitted.hasDefensibleLocation()) {
            throw new AssertionError("unavailable location was treated as defensible");
        }

        assertGenericExpression(new VariableLocation("function_a", 0x1000,
            "register", VariableKind.PARAMETER, 8, List.of(new LocationRange(0x1000,
                0x1010, x86.register("RDI", 0, 64), analyst))),
            DwarfLocationExpression.DW_OP_REGX, 5, 0);
        assertGenericExpression(relativeVariable, DwarfLocationExpression.DW_OP_BREGX,
            7, 24);
        if (!(DwarfLocationExpression.planStable(memory) instanceof Expression memoryExpr) ||
                !(memoryExpr.operations().get(0) instanceof AddressOperation addressOp) ||
                addressOp.address() != 0x5000) {
            throw new AssertionError("absolute-memory expression planning failed");
        }
        assertOmitted(changing, "location list");
        assertOmitted(omitted, "fixture optimized away");
        assertOmitted(new VariableLocation("function_a", 0x1000, "stack",
            VariableKind.LOCAL, 8, List.of(new LocationRange(0x1000, 0x1010,
                new StackStorage(-16), analyst))), "frame-base");
        if (!(DwarfLocationExpression.planStable(pieces) instanceof Expression pieceExpr) ||
                pieceExpr.operations().size() != 4 ||
                !(pieceExpr.operations().get(0) instanceof GenericOperation firstRegister) ||
                firstRegister.opcode() != DwarfLocationExpression.DW_OP_REGX ||
                firstRegister.operand1() != 0 ||
                !(pieceExpr.operations().get(1) instanceof GenericOperation firstPiece) ||
                firstPiece.opcode() != DwarfLocationExpression.DW_OP_BIT_PIECE ||
                firstPiece.operand1() != 32 || firstPiece.operand2() != 0 ||
                !(pieceExpr.operations().get(2) instanceof GenericOperation secondRegister) ||
                secondRegister.operand1() != 1 ||
                !(pieceExpr.operations().get(3) instanceof GenericOperation secondPiece) ||
                secondPiece.opcode() != DwarfLocationExpression.DW_OP_BIT_PIECE ||
                secondPiece.operand1() != 32 || secondPiece.operand2() != 0) {
            throw new AssertionError("composite register expression planning failed");
        }
        assertOmitted(new VariableLocation("function_a", 0x1000, "register-slice",
            VariableKind.LOCAL, 4, List.of(new LocationRange(0x1000, 0x1010,
                x86.register("RAX", 8, 32), analyst))), "does not exactly cover");

        List<VariableLocation> input = new ArrayList<>(List.of(changing, omitted,
            pieces, relativeVariable, memory));
        VariableStorageModel first = new VariableStorageModel(input);
        Collections.reverse(input);
        VariableStorageModel second = new VariableStorageModel(input);
        if (!first.equals(second) || !first.variables().get(0).name().equals("pieces")) {
            throw new AssertionError("variable ordering is not deterministic");
        }

        expectFailure(() -> new VariableLocation("bad", 0x4000, "overlap",
            VariableKind.LOCAL, 8, List.of(
                new LocationRange(0x4000, 0x4010, new StackStorage(-8), analysis),
                new LocationRange(0x400f, 0x4020, new StackStorage(-16), analysis))));
        expectFailure(() -> new VariableLocation("bad", 0x4000, "partial-pieces",
            VariableKind.LOCAL, 8, List.of(new LocationRange(0x4000, 0x4010,
                new CompositeStorage(List.of(
                    new Piece(x86.register("RAX", 0, 32), 32))), analysis))));
        expectFailure(() -> new CompositeStorage(List.of(new Piece(unknown, 64))));
        expectFailure(() -> TargetRegisterMap.forTarget("unsupported"));
        System.out.println("variable-storage-smoke=PASS");
    }

    private static void assertRegister(Storage storage, int expectedNumber) {
        if (!(storage instanceof RegisterStorage register) ||
                register.register().dwarfNumber() != expectedNumber) {
            throw new AssertionError("unexpected register mapping " + storage);
        }
    }

    private static void assertGenericExpression(VariableLocation variable, int opcode,
            long operand1, long operand2) {
        if (!(DwarfLocationExpression.planStable(variable) instanceof Expression expression) ||
                expression.operations().size() != 1 ||
                !(expression.operations().get(0) instanceof GenericOperation operation) ||
                operation.opcode() != opcode || operation.operand1() != operand1 ||
                operation.operand2() != operand2) {
            throw new AssertionError("unexpected expression plan for " + variable.name());
        }
    }

    private static void assertOmitted(VariableLocation variable,
            String expectedDiagnostic) {
        if (!(DwarfLocationExpression.planStable(variable) instanceof Omitted omitted) ||
                !omitted.diagnostic().contains(expectedDiagnostic)) {
            throw new AssertionError("location was not honestly omitted for " +
                variable.name());
        }
    }

    private static void expectFailure(Runnable action) {
        try {
            action.run();
            throw new AssertionError("invalid storage model was accepted");
        }
        catch (IllegalArgumentException expected) {
            // Expected validation path.
        }
    }
}
