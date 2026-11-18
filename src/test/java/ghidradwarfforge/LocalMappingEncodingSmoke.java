package ghidradwarfforge;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.UnaryOperator;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.AttributeId;
import ghidra.program.model.pcode.ElementId;
import ghidra.program.model.pcode.Encoder;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeDataTypeManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/** Mutate real saved encodings at the parser boundary, without claiming Ghidra emits these corruptions. */
final class LocalMappingEncodingSmoke {
    private static int checks;

    static void run(Program program, Function function, boolean stack) throws Exception {
        var high = new HighFunction(function, program.getLanguage(), program.getCompilerSpec(),
            new PcodeDataTypeManager(program, name -> name));
        high.getLocalSymbolMap().grabFromFunction(false);
        var symbols = high.getLocalSymbolMap().getSymbols();
        HighSymbol saved = null;
        while (symbols.hasNext()) {
            var symbol = symbols.next();
            if (symbol.getName().equals("value")) saved = symbol;
        }
        require(saved != null, "canonical saved symbol missing");
        var capture = new GhidraEncoderTree(TaskMonitor.DUMMY);
        HighSymbol.encodeMapSym(capture, saved);
        require(capture.roots().size() == 1, "one saved mapping root");
        var root = capture.roots().getFirst();
        var baseline = read(root, TaskMonitor.DUMMY);
        require(baseline.valid && baseline.count == 3 && baseline.entries == 3, "real saved encoding accepted");
        int address = index(root, ElementId.ELEM_ADDR);
        int rangeList = index(root, ElementId.ELEM_RANGELIST);
        var addr = root.children().get(address);
        var ranges = root.children().get(rangeList);
        require(ranges.children().size() == (stack ? 0 : 1), "saved stack/register range shape");

        reject(new GhidraEncoderTree.Node(ElementId.ELEM_SYMBOL, root.attributes(), root.children()), "foreign root");
        reject(edit(root, address, n -> new GhidraEncoderTree.Node(ElementId.ELEM_RANGE, n.attributes(), n.children())),
            "unsupported direct mapping child");
        reject(edit(root, address, n -> new GhidraEncoderTree.Node(n.id(), n.attributes(), List.of(addr))), "nested storage");
        for (AttributeId field : List.of(AttributeId.ATTRIB_OFFSET, AttributeId.ATTRIB_SIZE, AttributeId.ATTRIB_SPACE)) {
            reject(edit(root, address, n -> without(n, field)), "missing storage " + field.name());
        }
        for (long bytes : new long[] {-1, 0, (long) Integer.MAX_VALUE + 1}) {
            reject(edit(root, address, n -> number(n, AttributeId.ATTRIB_SIZE, bytes)), "invalid storage size " + bytes);
        }
        reject(edit(root, address, n -> attribute(n, new GhidraEncoderTree.Attribute("space",
            AttributeId.ATTRIB_SPACE, program.getAddressFactory().getConstantSpace(), 0, null))), "constant storage");
        reject(edit(root, address, n -> attribute(n, new GhidraEncoderTree.Attribute("space-id",
            AttributeId.ATTRIB_SPACE, null, 0, "unresolved"))), "unresolved storage space");
        var duplicate = new ArrayList<>(root.children());
        duplicate.add(address, addr);
        reject(new GhidraEncoderTree.Node(root.id(), root.attributes(), duplicate), "two addresses for one range list");
        var orphan = new ArrayList<>(root.children());
        orphan.remove(address);
        reject(new GhidraEncoderTree.Node(root.id(), root.attributes(), orphan), "range list without address");
        var dangling = new ArrayList<>(root.children());
        dangling.add(addr);
        reject(new GhidraEncoderTree.Node(root.id(), root.attributes(), dangling), "unfinished address");

        if (!stack) {
            var range = ranges.children().getFirst();
            reject(edit(root, rangeList, n -> new GhidraEncoderTree.Node(n.id(), n.attributes(), List.of())), "missing definition");
            reject(edit(root, rangeList, n -> new GhidraEncoderTree.Node(n.id(), n.attributes(), List.of(range, range))),
                "multiple definition ranges");
            reject(editRange(root, rangeList, n -> new GhidraEncoderTree.Node(ElementId.ELEM_SYMBOL, n.attributes(), n.children())),
                "non-range definition element");
            for (AttributeId field : List.of(AttributeId.ATTRIB_FIRST, AttributeId.ATTRIB_LAST, AttributeId.ATTRIB_SPACE)) {
                reject(editRange(root, rangeList, n -> without(n, field)), "missing definition " + field.name());
            }
            long first = (Long) range.attribute(AttributeId.ATTRIB_FIRST);
            reject(editRange(root, rangeList, n -> number(n, AttributeId.ATTRIB_LAST, first + 1)), "non-point definition");
            reject(editRange(root, rangeList, n -> attribute(n, new GhidraEncoderTree.Attribute("space-id",
                AttributeId.ATTRIB_SPACE, null, 0, "unresolved"))), "unresolved definition space");
        }
        else {
            var definition = new GhidraEncoderTree.Node(ElementId.ELEM_RANGE, List.of(
                new GhidraEncoderTree.Attribute("space", AttributeId.ATTRIB_SPACE,
                    program.getAddressFactory().getDefaultAddressSpace(), 0, null),
                new GhidraEncoderTree.Attribute("unsigned", AttributeId.ATTRIB_FIRST, 0x1004L, 0, null),
                new GhidraEncoderTree.Attribute("unsigned", AttributeId.ATTRIB_LAST, 0x1004L, 0, null)), List.of());
            reject(edit(root, rangeList, n -> new GhidraEncoderTree.Node(n.id(), n.attributes(), List.of(definition))),
                "stack map cannot supply a guessed definition range");
        }

        var counter = new CountingMonitor(Integer.MAX_VALUE);
        require(read(root, counter).equals(baseline), "instrumented traversal preserves mapping acceptance");
        for (int stop = 1; stop <= counter.calls; stop++) {
            var monitor = new CountingMonitor(stop);
            try {
                read(root, monitor);
                throw new AssertionError("mapping encoder ignored cancellation " + stop);
            }
            catch (IOException expected) {
                require(expected.getCause() instanceof CancelledException && monitor.calls == stop,
                    "mapping encoder retains cancellation cause and stops promptly");
            }
        }
        require(read(root, TaskMonitor.DUMMY).equals(baseline), "corruption controls leave original encoding unchanged");
        System.out.println("local-mapping-encoding=PASS stack=" + stack + " checks=" + checks);
    }

    private record Observation(boolean valid, int count, int entries) { }

    private static Observation read(GhidraEncoderTree.Node root, TaskMonitor monitor) throws Exception {
        Class<?> type = Class.forName("ghidradwarfforge.GhidraLocalMappings$MappingEncoder");
        var constructor = type.getDeclaredConstructor(TaskMonitor.class);
        constructor.setAccessible(true);
        var encoder = (Encoder) constructor.newInstance(monitor);
        root.replay(encoder, TaskMonitor.DUMMY);
        var valid = type.getDeclaredField("valid");
        var count = type.getDeclaredField("mappingCount");
        var entries = type.getDeclaredField("entries");
        valid.setAccessible(true);
        count.setAccessible(true);
        entries.setAccessible(true);
        return new Observation(valid.getBoolean(encoder), count.getInt(encoder), ((List<?>) entries.get(encoder)).size());
    }

    private static void reject(GhidraEncoderTree.Node root, String label) throws Exception {
        require(!read(root, TaskMonitor.DUMMY).valid, "malformed mapping accepted: " + label);
    }

    private static int index(GhidraEncoderTree.Node root, ElementId element) {
        for (int index = 0; index < root.children().size(); index++) {
            if (root.children().get(index).id().equals(element)) return index;
        }
        throw new AssertionError("missing saved " + element.name());
    }

    private static GhidraEncoderTree.Node edit(GhidraEncoderTree.Node root, int index,
            UnaryOperator<GhidraEncoderTree.Node> change) {
        var children = new ArrayList<>(root.children());
        children.set(index, change.apply(children.get(index)));
        return new GhidraEncoderTree.Node(root.id(), root.attributes(), children);
    }

    private static GhidraEncoderTree.Node editRange(GhidraEncoderTree.Node root, int index,
            UnaryOperator<GhidraEncoderTree.Node> change) {
        return edit(root, index, n -> edit(n, 0, change));
    }

    private static GhidraEncoderTree.Node without(GhidraEncoderTree.Node node, AttributeId field) {
        return new GhidraEncoderTree.Node(node.id(), node.attributes().stream().filter(a -> !a.id().equals(field)).toList(), node.children());
    }

    private static GhidraEncoderTree.Node number(GhidraEncoderTree.Node node, AttributeId field, long value) {
        return attribute(node, new GhidraEncoderTree.Attribute("signed", field, value, 0, null));
    }

    private static GhidraEncoderTree.Node attribute(GhidraEncoderTree.Node node, GhidraEncoderTree.Attribute value) {
        var attributes = new ArrayList<>(without(node, value.id()).attributes());
        attributes.add(value);
        return new GhidraEncoderTree.Node(node.id(), attributes, node.children());
    }

    private static final class CountingMonitor extends TaskMonitorAdapter {
        private final int stop;
        private int calls;
        CountingMonitor(int stop) { super(true); this.stop = stop; }
        @Override public void checkCancelled() throws CancelledException {
            if (++calls == stop) throw new CancelledException();
        }
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
