package ghidradwarfforge.dwarf;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/** Native-free regression for section-offset removal and ref4 adjustment. */
public final class Dwarf32InfoRepairSmoke {
    private Dwarf32InfoRepairSmoke() {
    }

    public static void main(String[] args) {
        byte[] abbrev = bytes(
            1, 0x11, 1,
            0x03, 0x08,
            0x10, 0x17,
            0x55, 0x17,
            0x13, 0x0b,
            0, 0,
            2, 0x0f, 0,
            0x49, 0x13,
            0, 0,
            3, 0x34, 0,
            0x02, 0x17,
            0, 0,
            0);
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(1);
        body.writeBytes("u\0".getBytes(StandardCharsets.UTF_8));
        body.writeBytes(new byte[8]);
        body.writeBytes(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(12).array());
        body.write(0x1d);
        body.write(3);
        body.writeBytes(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(44).array());
        int rawPointerOffset = 12 + body.size();
        body.write(2);
        writeInt(body, rawPointerOffset, ByteOrder.LITTLE_ENDIAN);
        body.write(0);

        byte[] info = new byte[12 + body.size()];
        ByteBuffer header = ByteBuffer.wrap(info).order(ByteOrder.LITTLE_ENDIAN);
        header.putInt(0, info.length - 4);
        header.putShort(4, (short) 5);
        info[6] = 1;
        info[7] = 8;
        header.putInt(8, 0);
        System.arraycopy(body.toByteArray(), 0, info, 12, body.size());

        byte[] repaired = Dwarf32InfoRepair.repair(info, abbrev, 8,
            ByteOrder.LITTLE_ENDIAN);
        if (repaired.length != info.length - 12 ||
                ByteBuffer.wrap(repaired).order(ByteOrder.LITTLE_ENDIAN).getInt(0) !=
                    repaired.length - 4) {
            throw new AssertionError("unit length was not repaired");
        }
        int repairedPointerOffset = rawPointerOffset - 12;
        if (ByteBuffer.wrap(repaired).order(ByteOrder.LITTLE_ENDIAN).getInt(19) != 12) {
            throw new AssertionError("DW_AT_ranges section offset was not preserved");
        }
        if (ByteBuffer.wrap(repaired).order(ByteOrder.LITTLE_ENDIAN).getInt(25) != 44) {
            throw new AssertionError("DW_AT_location section offset was not preserved");
        }
        int reference = ByteBuffer.wrap(repaired).order(ByteOrder.LITTLE_ENDIAN)
            .getInt(repairedPointerOffset + 1);
        if (reference != repairedPointerOffset) {
            throw new AssertionError("DW_FORM_ref4 was not adjusted: " + reference);
        }
        if (!java.util.Arrays.equals(info,
                Dwarf32InfoRepair.repair(info, abbrev, 4, ByteOrder.LITTLE_ENDIAN))) {
            throw new AssertionError("ELF32 data should be unchanged");
        }
        System.out.println("dwarf32-info-repair-smoke=PASS");
    }

    private static byte[] bytes(int... values) {
        byte[] result = new byte[values.length];
        for (int index = 0; index < values.length; index++) {
            result[index] = (byte) values[index];
        }
        return result;
    }

    private static void writeInt(ByteArrayOutputStream output, int value,
            ByteOrder order) {
        byte[] bytes = ByteBuffer.allocate(4).order(order).putInt(value).array();
        output.writeBytes(bytes);
    }
}
