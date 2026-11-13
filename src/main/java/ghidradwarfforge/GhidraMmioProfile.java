package ghidradwarfforge;

import com.google.gson.Gson;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.output.FileDigests;
import ghidradwarfforge.output.MmioSelection;
import ghidradwarfforge.types.TypeGraph;
import java.io.IOException;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.BooleanSupplier;

/** Reads explicit saved-program views without altering data objects or their settings. */
public final class GhidraMmioProfile {
    public static final String OPTIONS = "GhidraDwarfForge";
    public static final String SELECTION = "MMIO profile JSON";
    private record Bound(MmioSelection.View view, DataType type, String alias) { }
    private final MmioSelection selection;
    private final Map<MmioSelection.View, Bound> bound;

    private GhidraMmioProfile(MmioSelection selection, Map<MmioSelection.View, Bound> bound) {
        this.selection = selection;
        this.bound = Map.copyOf(bound);
    }

    public static GhidraMmioProfile read(Program program, TaskMonitor monitor) throws IOException, CancelledException {
        return read(program, program.getOptions(OPTIONS).getString(SELECTION, null), monitor);
    }

    public static GhidraMmioProfile read(Program program, String text, TaskMonitor monitor) throws IOException, CancelledException {
        var selected = MmioSelection.read(text, monitor::isCancelled);
        if (!selected.language().equals(program.getLanguageID().getIdAsString())) {
            throw new IOException("saved MMIO profile language differs from program");
        }
        var bound = new LinkedHashMap<MmioSelection.View, Bound>();
        var space = program.getAddressFactory().getDefaultAddressSpace();
        for (var r : selected.registers()) {
            monitor.checkCancelled();
            var address = program.getAddressFactory().getAddress(r.address());
            if (address == null || !address.getAddressSpace().equals(space) || address.getAddressSpace().isOverlaySpace()) {
                throw new IOException("MMIO address must identify ordinary default-space memory: " + r.name());
            }
            var block = program.getMemory().getBlock(address);
            if (block == null || !block.isLoaded() || block.isMapped() ||
                    r.width() - 1 > block.getEnd().subtract(address)) {
                throw new IOException("MMIO register requires one proven ordinary memory block: " + r.name());
            }
            var runtime = new java.math.BigInteger(r.runtimeAddress().substring(2), 16);
            if (runtime.mod(java.math.BigInteger.valueOf(r.width())).signum() != 0 ||
                    runtime.add(java.math.BigInteger.valueOf(r.width())).compareTo(java.math.BigInteger.ONE.shiftLeft(space.getSize())) > 0) {
                throw new IOException("unaligned or overflowing MMIO runtime address: " + r.name());
            }
            for (var view : r.views()) {
                monitor.checkCancelled();
                DataType type = program.getDataTypeManager().getDataType(view.datatype());
                if (type == null || type.getLength() <= 0 || type.getLength() > r.width() - view.offset()) {
                    throw new IOException("missing or oversized saved MMIO type: " + view.datatype());
                }
                String identity = type.getPathName() + "\n" + type.getUniversalID() + "\n" +
                    String.join(",", view.qualifiers().stream().sorted().toList());
                bound.put(view, new Bound(view, type, "__forge_mmio_" + digest(identity)));
            }
        }
        return new GhidraMmioProfile(selected, bound);
    }

    /** Use the same extractor/cache as ordinary program types, preserving canonical identity. */
    public void contribute(BiFunction<DataType, List<TypeGraph.Qualifier>, TypeGraph.TypeRef> reserve,
            Map<String, TypeGraph.TypeNode> nodes, TaskMonitor monitor) throws CancelledException {
        for (var b : bound.values().stream().sorted(java.util.Comparator.comparing(Bound::alias)).toList()) {
            monitor.checkCancelled();
            var qualifiers = b.view().qualifiers().stream().sorted()
                .map(q -> TypeGraph.Qualifier.valueOf(q.toUpperCase(java.util.Locale.ROOT))).toList();
            var target = reserve.apply(b.type(), qualifiers);
            var node = new TypeGraph.TypedefType("mmio-witness:" + b.alias(), b.alias(), b.type().getLength(), target);
            var previous = nodes.putIfAbsent(node.key(), node);
            if (previous != null && !previous.equals(node)) throw new IllegalArgumentException("conflicting MMIO type witness");
        }
    }

    public void validateAliases(TypeGraph graph, TaskMonitor monitor) throws CancelledException {
        var counts = new java.util.HashMap<String, Integer>();
        for (var node : graph.nodes()) {
            monitor.checkCancelled();
            counts.merge(node.name(), 1, Integer::sum);
        }
        for (var b : bound.values()) {
            monitor.checkCancelled();
            if (counts.getOrDefault(b.alias(), 0) != 1) {
                throw new IllegalArgumentException("MMIO type witness collides with a program type");
            }
        }
    }

    public String render(ElfImage elf, Path stagedSidecar, BooleanSupplier cancelled) throws IOException {
        var result = new LinkedHashMap<String, Object>();
        result.put("schema", 1);
        result.put("sidecar_sha256", FileDigests.read(stagedSidecar, cancelled).sha256());
        result.put("architecture", selection.architecture());
        result.put("address_bits", elf.is64Bit() ? 64 : 32);
        result.put("byteorder", elf.byteOrder() == ByteOrder.LITTLE_ENDIAN ? "little" : "big");
        result.put("transport", selection.transport());
        var registers = new ArrayList<Map<String, Object>>();
        for (var r : selection.registers()) {
            if (cancelled.getAsBoolean()) throw new java.util.concurrent.CancellationException("MMIO profile rendering cancelled");
            if (new java.math.BigInteger(r.runtimeAddress().substring(2), 16).add(java.math.BigInteger.valueOf(r.width()))
                    .compareTo(java.math.BigInteger.ONE.shiftLeft(elf.is64Bit() ? 64 : 32)) > 0) {
                throw new IOException("MMIO runtime address exceeds the exported target width");
            }
            var row = new LinkedHashMap<String, Object>();
            row.put("name", r.name());
            row.put("address", r.runtimeAddress());
            row.put("width", r.width());
            row.put("read_effect", r.readEffect());
            var views = new ArrayList<Map<String, Object>>();
            for (var v : r.views()) {
                var view = new LinkedHashMap<String, Object>();
                view.put("name", v.name());
                view.put("type", bound.get(v).alias());
                view.put("offset", v.offset());
                views.add(view);
            }
            row.put("views", views);
            registers.add(row);
        }
        result.put("registers", registers);
        String json = new Gson().toJson(result) + "\n";
        if (json.getBytes(StandardCharsets.UTF_8).length > 65536) {
            throw new IOException("rendered MMIO profile exceeds the debugger's 64 KiB limit");
        }
        return json;
    }

    private static String digest(String text) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8))); }
        catch (NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
    }
}
