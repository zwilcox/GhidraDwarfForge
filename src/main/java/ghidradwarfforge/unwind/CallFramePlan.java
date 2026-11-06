package ghidradwarfforge.unwind;

import java.nio.ByteOrder;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Explicit call-frame rows for serialization, not a claim of recovered evidence.
 * The caller must prove rules and choose the complete target register universe.
 * No processor, ABI, register defaults or instruction effects are inferred here.
 */
public record CallFramePlan(int addressBytes, ByteOrder order, int returnRegister,
        Set<Integer> registers, Map<Integer, Rule> initialRules, List<Frame> frames) {
    public static final int MAX_REGISTER = 4095;
    public static final int MAX_REGISTERS = 512;
    public static final int MAX_FRAMES = 65536;
    public static final int MAX_ROWS_PER_FRAME = 65536;

    public sealed interface Rule permits Undefined, SameValue, AtCfaOffset, CfaValue, InRegister { }
    public record Undefined() implements Rule { }
    public record SameValue() implements Rule { }
    public record AtCfaOffset(long offset) implements Rule { }
    public record CfaValue(long offset) implements Rule { }
    public record InRegister(int register) implements Rule {
        public InRegister {
            checkRegister(register);
        }
    }
    public record Cfa(int register, long offset) {
        public Cfa {
            checkRegister(register);
        }
    }
    public record Row(long address, Cfa cfa, Map<Integer, Rule> rules) {
        public Row {
            Objects.requireNonNull(cfa, "CFA");
            Objects.requireNonNull(rules, "register rules");
            if (rules.isEmpty() || rules.size() > MAX_REGISTERS) {
                throw new IllegalArgumentException("frame register count exceeds bounds");
            }
            var sorted = new TreeMap<Integer, Rule>();
            for (var entry : rules.entrySet()) {
                checkRegister(Objects.requireNonNull(entry.getKey(), "register"));
                sorted.put(entry.getKey(), Objects.requireNonNull(entry.getValue(), "rule"));
            }
            rules = Collections.unmodifiableMap(sorted);
        }
    }
    public record Frame(long address, long size, List<Row> rows) {
        public Frame {
            Objects.requireNonNull(rows, "rows");
            if (size <= 0 || Long.compareUnsigned(address + size - 1, address) < 0) {
                throw new IllegalArgumentException("frame range is empty or wraps the address space");
            }
            if (rows.isEmpty() || rows.size() > MAX_ROWS_PER_FRAME) {
                throw new IllegalArgumentException("frame row count exceeds bounds");
            }
            rows = List.copyOf(rows);
            if (rows.getFirst().address() != address) {
                throw new IllegalArgumentException("frame entry has no initial rule row");
            }
            long previous = 0;
            for (int index = 0; index < rows.size(); index++) {
                long offset = rows.get(index).address() - address;
                if (Long.compareUnsigned(offset, size) >= 0 || (index != 0 && offset <= previous)) {
                    throw new IllegalArgumentException("frame rows are unordered or outside the range");
                }
                previous = offset;
            }
        }
    }

    public CallFramePlan {
        if (addressBytes != 4 && addressBytes != 8) {
            throw new IllegalArgumentException("unsupported frame address width");
        }
        Objects.requireNonNull(order, "byte order");
        checkRegister(returnRegister);
        Objects.requireNonNull(registers, "register universe");
        Objects.requireNonNull(frames, "frames");
        if (registers.isEmpty() || registers.size() > MAX_REGISTERS || !registers.contains(returnRegister)) {
            throw new IllegalArgumentException("invalid frame register universe or missing return register");
        }
        for (int register : registers) checkRegister(register);
        registers = Collections.unmodifiableSet(new TreeSet<>(registers));
        Objects.requireNonNull(initialRules, "CIE initial rules");
        if (!initialRules.keySet().equals(registers)) {
            throw new IllegalArgumentException("CIE initial rules do not match the register universe");
        }
        var initial = new TreeMap<Integer, Rule>();
        for (var entry : initialRules.entrySet()) {
            Rule rule = Objects.requireNonNull(entry.getValue(), "CIE initial rule");
            if (rule instanceof InRegister in && !registers.contains(in.register())) {
                throw new IllegalArgumentException("CIE recovery register is outside the declared universe");
            }
            initial.put(entry.getKey(), rule);
        }
        initialRules = Collections.unmodifiableMap(initial);
        if (frames.size() > MAX_FRAMES) {
            throw new IllegalArgumentException("too many frame descriptions");
        }
        frames = List.copyOf(frames);
    }

    private static void checkRegister(int register) {
        if (register < 0 || register > MAX_REGISTER) {
            throw new IllegalArgumentException("DWARF frame register exceeds bounds: " + register);
        }
    }
}
