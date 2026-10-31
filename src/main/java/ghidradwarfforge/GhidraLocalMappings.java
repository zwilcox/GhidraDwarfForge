package ghidradwarfforge;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

import ghidra.pcodeCPort.opcodes.OpCode;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.AttributeId;
import ghidra.program.model.pcode.ElementId;
import ghidra.program.model.pcode.Encoder;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeDataTypeManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Saved Ghidra merge identity, distinct from any inferred machine lifetime. */
final class GhidraLocalMappings {
    record Mapping(Variable variable, Address definition, Register register) {
    }

    record Group(Variable canonical, List<Mapping> mappings) {
        Group {
            mappings = List.copyOf(mappings);
        }
    }

    private GhidraLocalMappings() {
    }

    static List<Group> extract(Program program, Function function, TaskMonitor monitor,
            Consumer<String> diagnostic) throws CancelledException {
        monitor.checkCancelled();
        if (function.getProgram() != program || function.isExternal()) return List.of();
        Variable[] locals = function.getLocalVariables();
        if (locals.length < 2) return List.of();
        var high = new HighFunction(function, program.getLanguage(), program.getCompilerSpec(),
            new PcodeDataTypeManager(program, name -> name));
        // Let the selected Ghidra implement its saved merge contract. Do not
        // identify a variable by independently stripping "$1" from its name.
        high.getLocalSymbolMap().grabFromFunction(false);
        var groups = new ArrayList<Group>();
        Set<Variable> used = new HashSet<>();
        var symbols = high.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            monitor.checkCancelled();
            HighSymbol symbol = symbols.next();
            if (symbol.isParameter() || !symbol.isTypeLocked() || !symbol.isNameLocked()) continue;
            var collector = new MappingEncoder(monitor);
            try {
                HighSymbol.encodeMapSym(collector, symbol);
            }
            catch (IOException failure) {
                if (failure.getCause() instanceof CancelledException cancelled) throw cancelled;
                diagnostic.accept("Omitted saved local merge evidence for " + symbol.getName() + ": " + failure.getMessage());
                continue;
            }
            if (collector.mappingCount < 2) continue;
            if (!collector.valid || collector.entries.size() != collector.mappingCount) {
                diagnostic.accept("Omitted saved local merge evidence for " + symbol.getName() +
                    ": unsupported mapping form; no full register definition identity inferred");
                continue;
            }
            var mappings = new ArrayList<Mapping>();
            boolean valid = true;
            for (Encoded entry : collector.entries) {
                monitor.checkCancelled();
                Variable matched = null;
                for (Variable variable : locals) {
                    monitor.checkCancelled();
                    var storage = variable.getVariableStorage();
                    var register = variable.getRegister();
                    if (variable.getProgram() != program || variable.getFunction() != function ||
                            variable.getSource() != SourceType.USER_DEFINED || !variable.isValid() ||
                            !variable.hasAssignedStorage() || storage == null || !storage.isValid() ||
                            !storage.isRegisterStorage() || storage.getVarnodeCount() != 1 || register == null ||
                            variable.getFirstUseOffset() < 0 || variable.getLength() <= 0 ||
                            !variable.getDataType().equals(symbol.getDataType()) ||
                            storage.size() != variable.getLength() || register.getBitLength() != variable.getLength() * 8L ||
                            !storage.getFirstVarnode().getAddress().equals(register.getAddress()) ||
                            entry.bytes != storage.size() || !entry.space.equals(register.getAddress().getAddressSpace()) ||
                            entry.offset != register.getOffset()) continue;
                    Address definition;
                    try {
                        definition = function.getEntryPoint().addNoWrap(variable.getFirstUseOffset());
                    }
                    catch (ghidra.program.model.address.AddressOverflowException overflow) {
                        continue;
                    }
                    if (!entry.definitionAddress.equals(definition)) continue;
                    if (matched != null) { valid = false; break; }
                    matched = variable;
                }
                if (!valid || matched == null || used.contains(matched) ||
                        mappings.stream().anyMatch(mapping -> mapping.definition().equals(entry.definitionAddress))) {
                    valid = false;
                    break;
                }
                mappings.add(new Mapping(matched, entry.definitionAddress, matched.getRegister()));
            }
            if (valid && mappings.size() == collector.entries.size() &&
                    mappings.getFirst().variable().getSymbol().getID() == symbol.getId()) {
                groups.add(new Group(mappings.getFirst().variable(), mappings));
                for (Mapping mapping : mappings) used.add(mapping.variable());
            }
            else diagnostic.accept("Omitted saved local merge evidence for " + symbol.getName() +
                ": every mapping must match one distinct curated full-width register definition");
        }
        groups.sort(java.util.Comparator.comparing(group -> group.canonical().getName()));
        return List.copyOf(groups);
    }

    private record Encoded(AddressSpace space, long offset, int bytes, Address definitionAddress) {
    }

    /** Capture typed direct addr/rangelist pairs through the public encoder API. */
    private static final class MappingEncoder implements Encoder {
        private final TaskMonitor monitor;
        private final ArrayDeque<ElementId> path = new ArrayDeque<>();
        private final List<Encoded> entries = new ArrayList<>();
        private AddressSpace space;
        private AddressSpace pcSpace;
        private Long offset;
        private Long bytes;
        private Long first;
        private Long last;
        private int ranges;
        private int mappingCount;
        private boolean pending;
        private boolean valid = true;

        MappingEncoder(TaskMonitor monitor) {
            this.monitor = monitor;
        }

        private void check() throws IOException {
            try { monitor.checkCancelled(); }
            catch (CancelledException cancelled) { throw new IOException("cancelled", cancelled); }
        }

        private boolean at(ElementId element, int depth) {
            return path.size() == depth && path.peek().equals(element);
        }

        @Override
        public void openElement(ElementId element) throws IOException {
            check();
            path.push(element);
            if (path.size() == 1 && !element.equals(ElementId.ELEM_MAPSYM)) valid = false;
            if (path.size() == 2) {
                if (element.equals(ElementId.ELEM_ADDR)) {
                    if (pending) valid = false;
                    pending = true;
                    space = null; offset = null; bytes = null;
                }
                else if (element.equals(ElementId.ELEM_RANGELIST)) {
                    mappingCount++;
                    if (!pending) valid = false;
                    pcSpace = null; first = null; last = null; ranges = 0;
                }
                else if (!element.equals(ElementId.ELEM_SYMBOL)) valid = false;
            }
            if (path.size() == 3 && path.toArray()[1].equals(ElementId.ELEM_RANGELIST)) {
                if (!element.equals(ElementId.ELEM_RANGE)) valid = false;
                ranges++;
            }
            if (path.size() > 2 && path.toArray()[path.size() - 2].equals(ElementId.ELEM_ADDR)) valid = false;
        }

        @Override
        public void closeElement(ElementId element) throws IOException {
            check();
            if (path.isEmpty() || !path.peek().equals(element)) throw new IOException("unbalanced mapping encoder");
            if (at(ElementId.ELEM_RANGELIST, 2)) {
                if (!pending || ranges != 1 || space == null || !space.isRegisterSpace() ||
                        offset == null || bytes == null || bytes <= 0 || bytes > Integer.MAX_VALUE ||
                        pcSpace == null || first == null || !first.equals(last)) valid = false;
                else entries.add(new Encoded(space, offset, bytes.intValue(), pcSpace.getAddress(first)));
                pending = false;
            }
            if (path.size() == 1 && pending) valid = false;
            path.pop();
        }

        private void number(AttributeId attribute, long value) throws IOException {
            check();
            if (at(ElementId.ELEM_ADDR, 2)) {
                if (attribute.equals(AttributeId.ATTRIB_OFFSET)) offset = value;
                if (attribute.equals(AttributeId.ATTRIB_SIZE)) bytes = value;
            }
            if (at(ElementId.ELEM_RANGE, 3)) {
                if (attribute.equals(AttributeId.ATTRIB_FIRST)) first = value;
                if (attribute.equals(AttributeId.ATTRIB_LAST)) last = value;
            }
        }

        @Override public void writeSignedInteger(AttributeId attribute, long value) throws IOException { number(attribute, value); }
        @Override public void writeUnsignedInteger(AttributeId attribute, long value) throws IOException { number(attribute, value); }
        @Override public void writeSpace(AttributeId attribute, AddressSpace value) throws IOException {
            check();
            if (!attribute.equals(AttributeId.ATTRIB_SPACE)) return;
            if (at(ElementId.ELEM_ADDR, 2)) space = value;
            if (at(ElementId.ELEM_RANGE, 3)) pcSpace = value;
        }
        @Override public void writeSpace(AttributeId attribute, int index, String name) throws IOException {
            check();
            if (at(ElementId.ELEM_ADDR, 2) || at(ElementId.ELEM_RANGE, 3)) valid = false;
        }
        @Override public void writeBool(AttributeId attribute, boolean value) throws IOException { check(); }
        @Override public void writeString(AttributeId attribute, String value) throws IOException { check(); }
        @Override public void writeStringIndexed(AttributeId attribute, int index, String value) throws IOException { check(); }
        @Override public void writeOpcode(AttributeId attribute, OpCode value) throws IOException { check(); }
    }
}
