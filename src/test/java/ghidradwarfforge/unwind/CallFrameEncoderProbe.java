package ghidradwarfforge.unwind;

import java.nio.ByteOrder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.TreeMap;
import java.util.TreeSet;

import ghidradwarfforge.dwarf.DwarfDebugFrame;
import ghidradwarfforge.elf.DebugSectionCompression;
import ghidradwarfforge.elf.MatchedElfSidecarWriter;
import ghidradwarfforge.unwind.CallFramePlan.*;

/** Test-only plan protocol. No extraction inference or native producer is involved. */
public final class CallFrameEncoderProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 5) throw new IllegalArgumentException("plan input output raw-frame compression");
        List<String> lines = Files.readAllLines(Path.of(args[0]));
        String[] header = lines.getFirst().split(" ");
        int width = Integer.parseInt(header[0]);
        var order = switch (header[1]) {
            case "little" -> ByteOrder.LITTLE_ENDIAN;
            case "big" -> ByteOrder.BIG_ENDIAN;
            default -> throw new IllegalArgumentException("unknown byte order");
        };
        int returnRegister = Integer.parseInt(header[2]);
        var registers = new TreeSet<Integer>();
        for (String part : header[3].split(",")) {
            if (!registers.add(Integer.parseInt(part))) throw new IllegalArgumentException("duplicate register");
        }
        var frames = new ArrayList<Frame>();
        var rows = new ArrayList<Row>();
        long address = 0;
        long size = 0;
        for (String line : lines.subList(1, lines.size())) {
            String[] fields = line.split(" ");
            if (fields[0].equals("frame")) {
                if (size != 0) frames.add(new Frame(address, size, rows));
                rows = new ArrayList<>();
                address = Long.parseUnsignedLong(fields[1], 16);
                size = Long.parseLong(fields[2], 16);
            }
            else if (fields[0].equals("row")) {
                var rules = new TreeMap<Integer, Rule>();
                for (String rule : fields[4].split(",")) {
                    String[] parts = rule.split(":");
                    int register = Integer.parseInt(parts[0]);
                    Rule value = switch (parts[1]) {
                        case "u" -> new Undefined();
                        case "s" -> new SameValue();
                        case "m" -> new AtCfaOffset(Long.parseLong(parts[2]));
                        case "v" -> new CfaValue(Long.parseLong(parts[2]));
                        case "r" -> new InRegister(Integer.parseInt(parts[2]));
                        default -> throw new IllegalArgumentException("unknown rule");
                    };
                    if (rules.put(register, value) != null) throw new IllegalArgumentException("duplicate rule");
                }
                rows.add(new Row(Long.parseUnsignedLong(fields[1], 16),
                    new Cfa(Integer.parseInt(fields[2]), Long.parseLong(fields[3])), rules));
            }
            else throw new IllegalArgumentException("unknown plan record");
        }
        if (size != 0) frames.add(new Frame(address, size, rows));
        byte[] bytes = DwarfDebugFrame.build(new CallFramePlan(width, order, returnRegister, registers, frames), () -> false);
        // The repository's strict checker requires a completed CU. This
        // fixture-only CU identifies the explicit test plan, not original C
        // source, and supplies no lines, types or recovered unwind evidence.
        byte[] producer = "GhidraDwarfForge explicit CFI test\0".getBytes(StandardCharsets.UTF_8);
        byte[] name = "plan.txt\0".getBytes(StandardCharsets.UTF_8);
        long low = frames.stream().mapToLong(Frame::address).min().orElse(0);
        long high = frames.stream().mapToLong(frame -> frame.address() + frame.size()).max().orElse(0);
        ByteBuffer info = ByteBuffer.allocate(12 + 1 + producer.length + name.length + width + 8).order(order);
        info.putInt(info.capacity() - 4).putShort((short) 5).put((byte) 1).put((byte) width).putInt(0);
        info.put((byte) 1).put(producer).put(name);
        if (width == 8) info.putLong(low); else info.putInt((int) low);
        info.putLong(high - low);
        byte[] abbrev = { 1, 0x11, 0, 0x25, 8, 3, 8, 0x11, 1, 0x12, 7, 0, 0, 0 };
        var sections = new LinkedHashMap<String, byte[]>();
        sections.put(".debug_info", info.array());
        sections.put(".debug_abbrev", abbrev);
        sections.put(".debug_frame", bytes);
        new MatchedElfSidecarWriter(DebugSectionCompression.parse(args[4])).write(
            Path.of(args[1]), Path.of(args[2]), sections);
        Files.write(Path.of(args[3]), bytes);
    }
}
