package ghidradwarfforge.dwarf;

import java.io.ByteArrayOutputStream;
import ghidradwarfforge.targets.CxxAbiProfile;
import ghidradwarfforge.types.InheritanceModel.VirtualBase;

/** DWARF 5 member expressions; the evaluator supplies the containing subobject address. */
public final class DwarfInheritanceExpression {
    private DwarfInheritanceExpression() { }

    public static byte[] virtualBase(CxxAbiProfile abi, VirtualBase base, long objectBytes) {
        abi.requireVirtualBase(base.vptrOffset(), base.slotOffset(), objectBytes);
        var out = new ByteArrayOutputStream();
        if (base.vptrOffset() != 0) {
            out.write(0x23); // DW_OP_plus_uconst: displacement is relative to this vptr's subobject.
            uleb(out, base.vptrOffset());
        }
        out.write(0x12); // DW_OP_dup
        out.write(0x06); // DW_OP_deref: vtable address point
        out.write(0x11); // DW_OP_consts: signed byte offset to vbase entry
        long value = base.slotOffset();
        boolean more;
        do {
            int part = (int) value & 0x7f;
            value >>= 7;
            more = !((value == 0 && (part & 0x40) == 0) || (value == -1 && (part & 0x40) != 0));
            out.write(part | (more ? 0x80 : 0));
        } while (more);
        out.write(0x22); // DW_OP_plus
        out.write(0x06); // DW_OP_deref: signed ptrdiff_t displacement (target word width)
        out.write(0x22); // DW_OP_plus: address of virtual base, not a stack value
        return out.toByteArray();
    }

    public static byte[] virtualSlot(int slot) {
        if (slot < 0 || slot >= 65536) throw new IllegalArgumentException("invalid virtual slot");
        var out = new ByteArrayOutputStream();
        out.write(0x10); // DW_OP_constu: index of function entry
        uleb(out, slot);
        return out.toByteArray();
    }

    private static void uleb(ByteArrayOutputStream out, long value) {
        do {
            int part = (int) value & 0x7f;
            value >>>= 7;
            out.write(part | (value == 0 ? 0 : 0x80));
        } while (value != 0);
    }
}
