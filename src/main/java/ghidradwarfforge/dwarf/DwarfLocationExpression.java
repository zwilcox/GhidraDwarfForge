package ghidradwarfforge.dwarf;

import java.util.ArrayList;
import java.util.List;

import ghidradwarfforge.locations.VariableStorageModel.CompositeStorage;
import ghidradwarfforge.locations.VariableStorageModel.LocationRange;
import ghidradwarfforge.locations.VariableStorageModel.MemoryStorage;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.RegisterRelativeStorage;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.locations.VariableStorageModel.StackStorage;
import ghidradwarfforge.locations.VariableStorageModel.Storage;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;
import ghidradwarfforge.locations.VariableStorageModel.VariableLocation;

/**
 * Native-independent plan for one stable DWARF variable-location expression.
 * The plan deliberately keeps address operations distinct because libdwarf's
 * producer uses a relocation-aware API for {@code DW_OP_addr}.
 */
public final class DwarfLocationExpression {
    public static final int DW_OP_REGX = 0x90;
    public static final int DW_OP_BREGX = 0x92;
    public static final int DW_OP_BIT_PIECE = 0x9d;

    public sealed interface Result permits Expression, Omitted {
    }

    public sealed interface Operation permits GenericOperation, AddressOperation {
    }

    /** Operands are passed to libdwarf's audited dwarf_add_expr_gen_a API. */
    public record GenericOperation(int opcode, long operand1,
            long operand2) implements Operation {
        public GenericOperation {
            if (opcode < 0 || opcode > 0xff) {
                throw new IllegalArgumentException("DWARF opcode must fit one byte");
            }
        }
    }

    /** Relocation-aware absolute link-time address operation. */
    public record AddressOperation(long address) implements Operation {
        public AddressOperation {
            if (address < 0) {
                throw new IllegalArgumentException("DWARF address must be nonnegative");
            }
        }
    }

    public record Expression(List<Operation> operations) implements Result {
        public Expression {
            if (operations == null || operations.isEmpty()) {
                throw new IllegalArgumentException("location expression requires operations");
            }
            operations = List.copyOf(operations);
        }
    }

    public record Omitted(OmissionReason reason, String diagnostic) implements Result {
        public Omitted {
            if (reason == null || diagnostic == null || diagnostic.isBlank()) {
                throw new IllegalArgumentException("location omission requires a reason");
            }
        }
    }

    private DwarfLocationExpression() {
    }

    /**
     * Plans a location only when every modeled live range uses the same available
     * storage. Changing or partially unavailable ranges require a location list.
     */
    public static Result planStable(VariableLocation variable) {
        if (variable == null) {
            throw new IllegalArgumentException("variable location is required");
        }
        Storage first = variable.locations().get(0).storage();
        for (LocationRange range : variable.locations()) {
            if (!first.equals(range.storage())) {
                return omitted("changing or partially unavailable storage requires " +
                    "a DWARF location list");
            }
        }
        if (first instanceof UnavailableStorage unavailable) {
            return new Omitted(unavailable.reason(), unavailable.diagnostic());
        }
        long expectedBits = Math.multiplyExact(variable.byteSize(), 8L);
        if (first instanceof RegisterStorage register) {
            if (register.valueBitOffset() != 0 || register.bitSize() != expectedBits) {
                return omitted("register slice does not exactly cover variable " +
                    variable.name());
            }
            return expression(new GenericOperation(DW_OP_REGX,
                register.register().dwarfNumber(), 0));
        }
        if (first instanceof RegisterRelativeStorage relative) {
            return expression(new GenericOperation(DW_OP_BREGX,
                relative.register().dwarfNumber(), relative.byteOffset()));
        }
        if (first instanceof MemoryStorage memory) {
            return expression(new AddressOperation(memory.address()));
        }
        if (first instanceof StackStorage) {
            return omitted("Ghidra stack coordinates require a proven frame-base " +
                "translation before DWARF emission");
        }
        if (first instanceof CompositeStorage composite) {
            List<Operation> operations = new ArrayList<>();
            for (var piece : composite.pieces()) {
                if (!(piece.storage() instanceof RegisterStorage register) ||
                        register.bitSize() != piece.bitSize()) {
                    return omitted("composite piece is not one exact register slice");
                }
                operations.add(new GenericOperation(DW_OP_REGX,
                    register.register().dwarfNumber(), 0));
                operations.add(new GenericOperation(DW_OP_BIT_PIECE,
                    piece.bitSize(), register.valueBitOffset()));
            }
            return new Expression(operations);
        }
        return omitted("unsupported variable storage " + first.getClass().getName());
    }

    private static Expression expression(Operation operation) {
        return new Expression(List.of(operation));
    }

    private static Omitted omitted(String diagnostic) {
        return new Omitted(OmissionReason.UNSUPPORTED_STORAGE, diagnostic);
    }
}
