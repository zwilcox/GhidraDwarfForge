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
        if (args.length < 5 || args.length > 8 || args.length >= 7 && !args[6].equals("from-original") ||
                args.length == 8 && !args[7].equals("controls")) {
            throw new IllegalArgumentException("plan input output raw-frame compression [original-prefix [from-original [controls]]]");
        }
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
        var initialRules = new TreeMap<Integer, Rule>();
        String[] initialFields = lines.get(1).split(" ");
        if (!initialFields[0].equals("initial")) throw new IllegalArgumentException("missing explicit CIE rules");
        for (String item : initialFields[1].split(",")) {
            String[] parts = item.split(":");
            int register = Integer.parseInt(parts[0]);
            Rule rule = switch (parts[1]) {
                case "u" -> new Undefined();
                case "s" -> new SameValue();
                case "m" -> new AtCfaOffset(Long.parseLong(parts[2]));
                case "v" -> new CfaValue(Long.parseLong(parts[2]));
                case "r" -> new InRegister(Integer.parseInt(parts[2]));
                default -> throw new IllegalArgumentException("unknown initial rule");
            };
            if (initialRules.put(register, rule) != null) throw new IllegalArgumentException("duplicate initial rule");
        }
        var frames = new ArrayList<Frame>();
        var rows = new ArrayList<Row>();
        long address = 0;
        long size = 0;
        for (String line : lines.subList(2, lines.size())) {
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
        var plan = new CallFramePlan(width, order, returnRegister, registers, initialRules, frames);
        byte[] bytes = args.length >= 6 ? DwarfDebugFrame.append(Files.readAllBytes(Path.of(args[5])), plan, () -> false) :
            DwarfDebugFrame.build(plan, () -> false);
        // The repository's strict checker requires a completed CU. This
        // fixture-only CU identifies the explicit test plan, not original C
        // source, and supplies no lines, types or recovered unwind evidence.
        byte[] producer = "GhidraDwarfForge explicit CFI test\0".getBytes(StandardCharsets.UTF_8);
        byte[] name = "plan.txt\0".getBytes(StandardCharsets.UTF_8);
        long low = frames.stream().mapToLong(Frame::address).min().orElse(0);
        long high = frames.stream().mapToLong(frame -> frame.address() + frame.size()).max().orElse(0);
        if (args.length >= 6) {
            for (var frame : OriginalFrameRanges.read(bytes, order, width,
                    OriginalFrameRanges.Format.DEBUG_FRAME, 0, () -> false).frames()) {
                low = Math.min(low, frame.address());
                high = Math.max(high, frame.address() + frame.size());
            }
        }
        ByteBuffer info = ByteBuffer.allocate(12 + 1 + producer.length + name.length + width + 8).order(order);
        info.putInt(info.capacity() - 4).putShort((short) 5).put((byte) 1).put((byte) width).putInt(0);
        info.put((byte) 1).put(producer).put(name);
        if (width == 8) info.putLong(low); else info.putInt((int) low);
        info.putLong(high - low);
        byte[] abbrev = { 1, 0x11, 0, 0x25, 8, 3, 8, 0x11, 1, 0x12, 7, 0, 0, 0 };
        var sections = new LinkedHashMap<String, byte[]>();
        sections.put(".debug_info", info.array());
        sections.put(".debug_abbrev", abbrev);
        var writer = new MatchedElfSidecarWriter(DebugSectionCompression.parse(args[4]));
        if (args.length >= 7) {
            var image = ghidradwarfforge.elf.ElfImage.read(Path.of(args[1]));
            int[] polls = {0};
            writer.writeWithFrames(image, Path.of(args[2]), sections, List.of(), plan,
                () -> { polls[0]++; return false; }, System.out::println);
            if (args.length == 8) writerControls(writer, image, Path.of(args[1]), Path.of(args[2]), sections, plan, bytes, polls[0]);
        }
        else {
            sections.put(".debug_frame", bytes);
            writer.write(Path.of(args[1]), Path.of(args[2]), sections);
        }
        Files.write(Path.of(args[3]), bytes);
    }

    private static void writerControls(MatchedElfSidecarWriter writer, ghidradwarfforge.elf.ElfImage image,
            Path input, Path output, Map<String, byte[]> sections, CallFramePlan plan, byte[] frameBytes, int polls) throws Exception {
        byte[] expected = Files.readAllBytes(output);
        byte[] original = Files.readAllBytes(input);
        byte[] sentinel = {11, 22, 33, 44};
        Path destination = output.resolveSibling(output.getFileName() + ".cancelled");
        for (int stop = 1; stop <= polls; stop++) {
            int selected = stop;
            int[] count = {0};
            Files.write(destination, sentinel);
            try {
                writer.writeWithFrames(image, destination, sections, List.of(), plan,
                    () -> ++count[0] == selected, ignored -> { });
                throw new AssertionError("writer ignored cancellation at " + stop);
            }
            catch (java.util.concurrent.CancellationException accepted) { }
            if (!java.util.Arrays.equals(sentinel, Files.readAllBytes(destination))) {
                throw new AssertionError("cancellation replaced an existing destination");
            }
            try (var files = Files.list(destination.toAbsolutePath().getParent())) {
                if (files.anyMatch(path -> path.getFileName().toString().startsWith(".ghidra-dwarf-forge-"))) {
                    throw new AssertionError("cancelled writer retained a staging file");
                }
            }
        }
        var raw = new LinkedHashMap<>(sections);
        raw.put(".debug_frame", frameBytes);
        try {
            writer.write(image, destination, raw, List.of(), () -> false);
            throw new AssertionError("ordinary writer accepted original-frame collision");
        }
        catch (IllegalArgumentException accepted) {
            if (!accepted.getMessage().contains("conflicts with original")) throw accepted;
        }
        try {
            writer.writeWithFrames(image, destination, raw, List.of(), plan, () -> false, ignored -> { });
            throw new AssertionError("writer accepted a plan plus supplied frame bytes");
        }
        catch (IllegalArgumentException accepted) {
            if (!accepted.getMessage().contains("cannot accompany")) throw accepted;
        }
        var wrongLayout = new CallFramePlan(plan.addressBytes() == 8 ? 4 : 8, plan.order(), plan.returnRegister(),
            plan.registers(), plan.initialRules(), plan.frames());
        try {
            writer.writeWithFrames(image, destination, sections, List.of(), wrongLayout, () -> false, ignored -> { });
            throw new AssertionError("writer accepted a mismatched target layout");
        }
        catch (IllegalArgumentException accepted) {
            if (!accepted.getMessage().contains("target layout differs")) throw accepted;
        }
        try {
            writer.writeWithFrames(image, destination.resolve("unwritable.dbg"), sections, List.of(), plan, () -> false, ignored -> { });
            throw new AssertionError("writer accepted a non-directory destination parent");
        }
        catch (java.io.IOException accepted) { }
        var source = ghidradwarfforge.elf.OriginalFrameSources.inspect(image, () -> false).sources().stream()
            .filter(item -> item.name().equals(".debug_frame") || item.name().equals(".zdebug_frame")).findFirst().orElseThrow();
        var range = source.records().frames().getFirst();
        var row = plan.frames().getFirst().rows().getFirst();
        var overlap = new CallFramePlan(plan.addressBytes(), plan.order(), plan.returnRegister(), plan.registers(),
            plan.initialRules(), List.of(new Frame(range.address(), range.size(),
                List.of(new Row(range.address(), row.cfa(), row.rules())))));
        try {
            writer.writeWithFrames(image, destination, sections, List.of(), overlap, () -> false, ignored -> { });
            throw new AssertionError("writer accepted original coverage overlap");
        }
        catch (IllegalArgumentException accepted) {
            if (!accepted.getMessage().contains("overlaps original unwind")) throw accepted;
        }
        if (!java.util.Arrays.equals(sentinel, Files.readAllBytes(destination))) {
            throw new AssertionError("rejected writer operation replaced destination");
        }
        var empty = new CallFramePlan(plan.addressBytes(), plan.order(), plan.returnRegister(), plan.registers(),
            plan.initialRules(), List.of());
        Path preservedOnly = output.resolveSibling(output.getFileName() + ".preserved-only");
        writer.writeWithFrames(image, preservedOnly, sections, List.of(), empty, () -> false, ignored -> { });
        var preserved = ghidradwarfforge.elf.OriginalFrameSources.inspect(
            ghidradwarfforge.elf.ElfImage.read(preservedOnly), () -> false).sources().stream()
            .filter(item -> item.name().equals(source.name())).findFirst().orElseThrow();
        if (!preserved.storedSha256().equals(source.storedSha256()) ||
                !preserved.decodedSha256().equals(source.decodedSha256()) || preserved.offset() != source.offset()) {
            throw new AssertionError("empty frame plan changed original frame storage");
        }
        writer.writeWithFrames(image, output, sections, List.of(), plan, () -> false, ignored -> { });
        if (!java.util.Arrays.equals(expected, Files.readAllBytes(output)) ||
                !java.util.Arrays.equals(original, Files.readAllBytes(input))) {
            throw new AssertionError("cancelled/rejected writer poisoned retry or changed original");
        }
        System.out.println("qualified-frame-writer-controls=PASS cancellations=" + polls);
    }
}
