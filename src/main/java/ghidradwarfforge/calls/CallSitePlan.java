package ghidradwarfforge.calls;

import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;

import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.ProgramTypeModel;

/** Normalized serialization plan; completeness must be established by its evidence provider. */
public record CallSitePlan(List<FunctionCalls> functions) {
    public static final CallSitePlan EMPTY = new CallSitePlan(List.of());
    public enum Completeness { PARTIAL, ALL_TAILS, ALL_CALLS }

    /** The expression describes the whole destination register, including known upper bits. */
    public record Argument(int ordinal, String name, String typeKey, int dwarfRegister, CallValue value) {
        public Argument {
            if (ordinal < 0 || dwarfRegister < 0 || name == null || typeKey == null || typeKey.isBlank() || value == null) {
                throw new IllegalArgumentException("invalid call argument identity");
            }
        }
    }
    /**
     * returnPc is the actual continuation for normal calls. For admitted tails
     * it is explicitly the GCC/GDB post-transfer lookup key, not a saved machine
     * return destination. pc always identifies the actual transfer instruction.
     */
    public record Site(long pc, long returnPc, boolean tail, Long callee, List<Argument> arguments) {
        public Site {
            if (pc < 0 || returnPc <= pc || callee != null && callee < 0 || arguments == null) {
                throw new IllegalArgumentException("invalid call-site addresses");
            }
            arguments = arguments.stream().sorted(Comparator.comparingInt(Argument::ordinal)).toList();
            var ordinals = new HashSet<Integer>();
            var registers = new HashSet<Integer>();
            for (var argument : arguments) {
                if (callee == null || !ordinals.add(argument.ordinal()) || !registers.add(argument.dwarfRegister())) {
                    throw new IllegalArgumentException("ambiguous call argument binding");
                }
            }
        }
    }
    public record FunctionCalls(long caller, Completeness completeness, List<Site> sites) {
        public FunctionCalls {
            if (caller < 0 || completeness == null || sites == null) throw new IllegalArgumentException("invalid call inventory");
            sites = sites.stream().sorted(Comparator.comparingLong(Site::pc)).toList();
        }
    }
    public CallSitePlan {
        functions = functions.stream().sorted(Comparator.comparingLong(FunctionCalls::caller)).toList();
        var callers = new HashSet<Long>();
        var pcs = new HashSet<Long>();
        var returns = new HashSet<Long>();
        for (var function : functions) {
            if (!callers.add(function.caller())) throw new IllegalArgumentException("duplicate call inventory");
            for (var site : function.sites()) {
                if (!pcs.add(site.pc()) || !returns.add(site.returnPc())) throw new IllegalArgumentException("duplicate call-site key");
                if (site.tail() && Objects.equals(site.callee(), function.caller())) {
                    throw new IllegalArgumentException("self-tail recursion is not a DWARF call-site entry");
                }
            }
        }
    }

    /** Reject stale owner/formal identities before native production. */
    public void validate(List<FunctionSymbol> exported, ProgramTypeModel types, int addressBytes) {
        var symbols = new java.util.HashMap<Long, FunctionSymbol>();
        for (var symbol : exported) symbols.put(symbol.address(), symbol);
        var signatures = new java.util.HashMap<Long, ProgramTypeModel.FunctionSignature>();
        if (types != null) for (var signature : types.functions()) signatures.put(signature.address(), signature);
        for (var function : functions) {
            var owner = symbols.get(function.caller());
            if (owner == null) throw new IllegalArgumentException("call-site owner is not exported");
            for (var site : function.sites()) {
                if (owner.ranges().stream().noneMatch(range -> range.contains(site.pc())) ||
                        (addressBytes == 4 && site.returnPc() > 0xffffffffL)) {
                    throw new IllegalArgumentException("call-site PC is outside its owner or target width");
                }
                if (site.callee() != null && !symbols.containsKey(site.callee())) {
                    throw new IllegalArgumentException("call-site origin is not exported");
                }
                var signature = signatures.get(site.callee());
                for (var argument : site.arguments()) {
                    if (signature == null || argument.ordinal() >= signature.parameters().size()) {
                        throw new IllegalArgumentException("call argument has no matching formal declaration");
                    }
                    var parameter = signature.parameters().get(argument.ordinal());
                    if (!parameter.name().equals(argument.name()) || !parameter.type().key().equals(argument.typeKey()) || parameter.returnStorage()) {
                        throw new IllegalArgumentException("call argument formal identity changed");
                    }
                    if (argument.value().bytes() > addressBytes) throw new IllegalArgumentException("call value exceeds target width");
                }
            }
        }
    }
}
