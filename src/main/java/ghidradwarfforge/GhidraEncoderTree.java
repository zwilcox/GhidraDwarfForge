package ghidradwarfforge;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import ghidra.pcodeCPort.opcodes.OpCode;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.AttributeId;
import ghidra.program.model.pcode.ElementId;
import ghidra.program.model.pcode.Encoder;
import ghidra.util.task.TaskMonitor;

/** Bounded typed encoding capture: attributes keep their wire types during replacement/replay. */
final class GhidraEncoderTree implements Encoder {
    record Attribute(String kind, AttributeId id, Object value, int index, String text) {
        void replay(Encoder output) throws IOException {
            switch (kind) {
                case "bool" -> output.writeBool(id, (Boolean)value);
                case "signed" -> output.writeSignedInteger(id, (Long)value);
                case "unsigned" -> output.writeUnsignedInteger(id, (Long)value);
                case "string" -> output.writeString(id, (String)value);
                case "indexed" -> output.writeStringIndexed(id, index, text);
                case "space" -> output.writeSpace(id, (AddressSpace)value);
                case "space-id" -> output.writeSpace(id, index, text);
                case "opcode" -> output.writeOpcode(id, (OpCode)value);
                default -> throw new IOException("Unknown captured encoding kind");
            }
        }
    }

    record Node(ElementId id, List<Attribute> attributes, List<Node> children) {
        Node {
            attributes = List.copyOf(attributes);
            children = List.copyOf(children);
        }

        void replay(Encoder output, TaskMonitor monitor) throws IOException {
            checkCancelled(monitor);
            output.openElement(id);
            for (var attribute : attributes) {
                checkCancelled(monitor);
                attribute.replay(output);
            }
            for (var child : children) child.replay(output, monitor);
            output.closeElement(id);
        }

        Node only(ElementId element) throws IOException {
            var matches = children.stream().filter(n -> n.id.equals(element)).toList();
            if (matches.size() != 1) throw new IOException("Unexpected allocation encoding shape at " + element.name());
            return matches.get(0);
        }

        Node replace(Node previous, Node replacement) throws IOException {
            var result = new ArrayList<>(children);
            if (!result.contains(previous)) throw new IOException("Missing encoding replacement owner");
            result.set(result.indexOf(previous), replacement);
            return new Node(id, attributes, result);
        }

        Object attribute(AttributeId attribute) {
            for (var value : attributes) if (value.id.equals(attribute)) return value.value;
            return null;
        }
    }

    private static final class OpenNode {
        final ElementId id;
        final List<Attribute> attributes = new ArrayList<>();
        final List<Node> children = new ArrayList<>();
        OpenNode(ElementId id) { this.id = id; }
    }

    private final TaskMonitor monitor;
    private final ArrayDeque<OpenNode> stack = new ArrayDeque<>();
    private final List<Node> roots = new ArrayList<>();
    private int events;
    private long textSize;

    GhidraEncoderTree(TaskMonitor monitor) { this.monitor = monitor; }

    List<Node> roots() throws IOException {
        if (!stack.isEmpty()) throw new IOException("Unclosed allocation encoding");
        return List.copyOf(roots);
    }

    private void event() throws IOException {
        checkCancelled(monitor);
        if (++events > 100_000) throw new IOException("Allocation encoding exceeds event budget");
    }

    private static void checkCancelled(TaskMonitor monitor) throws IOException {
        if (monitor.isCancelled()) throw new IOException("Allocation encoding cancelled");
    }

    private void attribute(Attribute value) throws IOException {
        event();
        if (stack.isEmpty() || !stack.peek().children.isEmpty()) throw new IOException("Misplaced encoding attribute");
        textSize += value.value instanceof String s ? s.length() : value.text == null ? 0 : value.text.length();
        if (textSize > 4_194_304) throw new IOException("Allocation encoding exceeds text budget");
        stack.peek().attributes.add(value);
    }

    @Override public void openElement(ElementId id) throws IOException {
        event();
        if (stack.size() >= 128) throw new IOException("Allocation encoding exceeds nesting budget");
        stack.push(new OpenNode(id));
    }
    @Override public void closeElement(ElementId id) throws IOException {
        event();
        if (stack.isEmpty() || !stack.peek().id.equals(id)) throw new IOException("Unbalanced allocation encoding");
        var value = stack.pop();
        var node = new Node(value.id, value.attributes, value.children);
        if (stack.isEmpty()) roots.add(node);
        else stack.peek().children.add(node);
    }
    @Override public void writeBool(AttributeId id, boolean value) throws IOException { attribute(new Attribute("bool", id, value, 0, null)); }
    @Override public void writeSignedInteger(AttributeId id, long value) throws IOException { attribute(new Attribute("signed", id, value, 0, null)); }
    @Override public void writeUnsignedInteger(AttributeId id, long value) throws IOException { attribute(new Attribute("unsigned", id, value, 0, null)); }
    @Override public void writeString(AttributeId id, String value) throws IOException { attribute(new Attribute("string", id, value, 0, null)); }
    @Override public void writeStringIndexed(AttributeId id, int index, String value) throws IOException { attribute(new Attribute("indexed", id, null, index, value)); }
    @Override public void writeSpace(AttributeId id, AddressSpace value) throws IOException { attribute(new Attribute("space", id, value, 0, null)); }
    @Override public void writeSpace(AttributeId id, int index, String value) throws IOException { attribute(new Attribute("space-id", id, null, index, value)); }
    @Override public void writeOpcode(AttributeId id, OpCode value) throws IOException { attribute(new Attribute("opcode", id, value, 0, null)); }
}
