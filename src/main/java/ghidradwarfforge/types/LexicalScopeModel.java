package ghidradwarfforge.types;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import ghidradwarfforge.locations.VariableStorageModel.Confidence;
import ghidradwarfforge.locations.VariableStorageModel.Evidence;
import ghidradwarfforge.locations.VariableStorageModel.LocationRange;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;
import ghidradwarfforge.locations.VariableStorageModel.VariableLocation;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;

/** Lexical visibility normalized to ELF addresses; deliberately separate from location proof. */
public record LexicalScopeModel(long functionAddress, List<FunctionRange> body,
        List<Block> blocks, List<Local> locals, String evidence) {
    public record Key(long functionAddress, String blockId) { }

    public record Block(String id, String parent, List<FunctionRange> ranges) {
        public Block {
            if (id == null || id.isBlank() || parent == null) throw invalid("invalid lexical block identity");
            ranges = checkedRanges(ranges);
        }
    }

    public record Local(String savedName, String block, String displayName) {
        public Local {
            if (savedName == null || savedName.isBlank() || block == null ||
                    displayName == null || displayName.isBlank()) throw invalid("invalid scoped local");
        }
    }

    public LexicalScopeModel {
        if (functionAddress < 0 || evidence == null || evidence.isBlank() || blocks == null || locals == null) {
            throw invalid("missing lexical evidence");
        }
        body = checkedRanges(body);
        if (body.stream().noneMatch(range -> range.contains(functionAddress))) throw invalid("missing function entry");
        var byId = new HashMap<String, Block>();
        for (Block block : blocks) {
            if (byId.put(block.id(), block) != null) throw invalid("duplicate lexical block");
            if (!contains(body, block.ranges())) throw invalid("lexical block outside function");
        }
        var depths = new HashMap<String, Integer>();
        for (Block block : blocks) {
            var visited = new HashSet<String>();
            Block current = block;
            while (current != null) {
                if (!visited.add(current.id())) throw invalid("cyclic lexical ownership");
                if (current.parent().isEmpty()) break;
                Block parent = byId.get(current.parent());
                if (parent == null || !contains(parent.ranges(), current.ranges())) throw invalid("invalid lexical parent");
                current = parent;
            }
            depths.put(block.id(), visited.size());
        }
        Map<String, List<FunctionRange>> siblings = new HashMap<>();
        for (Block block : blocks) siblings.computeIfAbsent(block.parent(), unused -> new ArrayList<>()).addAll(block.ranges());
        for (var ranges : siblings.values()) checkedRanges(ranges);
        var localNames = new HashSet<String>();
        Map<String, HashSet<String>> displayNames = new HashMap<>();
        for (Local local : locals) {
            if (!localNames.add(local.savedName()) || (!local.block().isEmpty() && !byId.containsKey(local.block())) ||
                    !displayNames.computeIfAbsent(local.block(), unused -> new HashSet<>()).add(local.displayName())) {
                throw invalid("ambiguous lexical local ownership");
            }
        }
        blocks = blocks.stream().sorted(Comparator.comparingInt((Block block) -> depths.get(block.id()))
            .thenComparing(Block::id)).toList();
        locals = locals.stream().sorted(Comparator.comparing(Local::savedName)).toList();
    }

    public Local local(String name) {
        return locals.stream().filter(local -> local.savedName().equals(name)).findFirst().orElse(null);
    }

    public List<FunctionRange> visibility(Local local) {
        return local.block().isEmpty() ? body : blocks.stream().filter(block -> block.id().equals(local.block()))
            .findFirst().orElseThrow().ranges();
    }

    /** Restrict, never extend, available locations; expose unproved visibility as unavailable. */
    public VariableLocation restrict(VariableLocation location) {
        Local local = local(location.name());
        if (local == null) return location;
        if (location.functionAddress() != functionAddress) throw invalid("wrong scoped function");
        var ranges = new ArrayList<LocationRange>();
        for (FunctionRange visible : visibility(local)) {
            long cursor = visible.address();
            for (LocationRange old : location.locations()) {
                long start = Math.max(visible.address(), old.start());
                long end = Math.min(visible.endExclusive(), old.end());
                if (end <= start) continue;
                if (cursor < start) ranges.add(unavailable(cursor, start));
                ranges.add(new LocationRange(start, end, old.storage(), old.evidence()));
                cursor = end;
            }
            if (cursor < visible.endExclusive()) ranges.add(unavailable(cursor, visible.endExclusive()));
        }
        return new VariableLocation(location.functionName(), location.functionAddress(), location.name(),
            location.kind(), location.byteSize(), ranges);
    }

    private LocationRange unavailable(long start, long end) {
        return new LocationRange(start, end, new UnavailableStorage(OmissionReason.UNKNOWN_LIFETIME,
            "no proven location inside explicitly recorded lexical scope"),
            new Evidence(Confidence.USER_DEFINED, "Saved lexical ownership only; " + evidence));
    }

    public static boolean contains(List<FunctionRange> outer, List<FunctionRange> inner) {
        for (FunctionRange child : inner) {
            long cursor = child.address();
            for (FunctionRange range : outer) {
                if (range.endExclusive() <= cursor) continue;
                if (range.address() > cursor) break;
                cursor = Math.min(child.endExclusive(), range.endExclusive());
                if (cursor == child.endExclusive()) break;
            }
            if (cursor != child.endExclusive()) return false;
        }
        return true;
    }

    private static List<FunctionRange> checkedRanges(List<FunctionRange> ranges) {
        if (ranges == null || ranges.isEmpty()) throw invalid("empty lexical range set");
        var ordered = ranges.stream().sorted(Comparator.comparingLong(FunctionRange::address)).toList();
        long end = -1;
        for (FunctionRange range : ordered) {
            if (range.address() < end) throw invalid("overlapping lexical ranges");
            end = range.endExclusive();
        }
        return ordered;
    }

    private static IllegalArgumentException invalid(String message) {
        return new IllegalArgumentException(message);
    }
}
