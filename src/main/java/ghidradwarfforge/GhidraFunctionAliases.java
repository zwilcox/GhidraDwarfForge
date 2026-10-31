package ghidradwarfforge;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.elf.ElfFunctionAlias;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** Read-only extraction of explicit secondary labels; never infers original linkage. */
public final class GhidraFunctionAliases {
    private static final int MAX_SYMBOLS = 262144;
    private static final int MAX_ALIASES = 65536;
    private static final long MAX_NAME_BYTES = 16L * 1024 * 1024;
    private static final long MAX_CODE_BYTES = 256L * 1024 * 1024;

    private GhidraFunctionAliases() {
    }

    public static List<ElfFunctionAlias> extract(Program program, List<FunctionSymbol> functions,
            long rebaseDelta, TaskMonitor monitor, Consumer<String> diagnostic)
            throws CancelledException {
        monitor.checkCancelled();
        List<Symbol> candidates = new ArrayList<>();
        Set<String> names = new HashSet<>();
        Set<String> collisions = new HashSet<>();
        int count = 0;
        long nameBytes = 0;
        var symbols = program.getSymbolTable().getAllSymbols(true);
        while (symbols.hasNext()) {
            monitor.checkCancelled();
            Symbol symbol = symbols.next();
            String name = symbol.getName(true);
            if (++count > MAX_SYMBOLS || name.length() > 65536 ||
                    (nameBytes += name.getBytes(StandardCharsets.UTF_8).length) > MAX_NAME_BYTES) {
                diagnostic.accept("Omitted function aliases: symbol inventory exceeds bounded name budget");
                return List.of();
            }
            if (!names.add(name)) {
                collisions.add(name);
            }
            if (symbol.getSymbolType() == SymbolType.LABEL && !symbol.isPrimary() &&
                    symbol.getSource() == SourceType.USER_DEFINED) {
                candidates.add(symbol);
                if (candidates.size() > MAX_ALIASES) {
                    diagnostic.accept("Omitted function aliases: candidate count exceeds " + MAX_ALIASES);
                    return List.of();
                }
            }
        }
        Map<Long, FunctionSymbol> owners = new HashMap<>();
        Set<Long> ambiguousEntries = new HashSet<>();
        Set<String> candidateNames = new HashSet<>();
        for (Symbol candidate : candidates) {
            candidateNames.add(candidate.getName(true));
        }
        for (FunctionSymbol function : functions) {
            monitor.checkCancelled();
            if (owners.putIfAbsent(function.address(), function) != null) {
                ambiguousEntries.add(function.address());
            }
            // Include fallback display names, which may differ from Symbol.getName(true).
            if (candidateNames.contains(function.qualifiedDisplayName())) {
                collisions.add(function.qualifiedDisplayName());
            }
        }
        candidates.sort(Comparator.comparing((Symbol s) -> s.getName(true))
            .thenComparing(Symbol::getAddress));
        List<ElfFunctionAlias> result = new ArrayList<>();
        Map<Long, List<ElfFunctionAlias.CodeRange>> bodies = new HashMap<>();
        long comparedRanges = 0;
        long codeBytes = 0;
        for (Symbol symbol : candidates) {
            monitor.checkCancelled();
            String name = symbol.getName(true);
            try {
                require(!collisions.contains(name), "ambiguous current symbol display name");
                for (Namespace scope = symbol.getParentNamespace(); !scope.isGlobal();
                        scope = scope.getParentNamespace()) {
                    require(scope.getType() == Namespace.Type.NAMESPACE || scope.getType() == Namespace.Type.CLASS,
                        "unsupported namespace ownership");
                }
                Address entry = symbol.getAddress();
                require(entry.isMemoryAddress() && entry.getAddressSpace().equals(
                    program.getAddressFactory().getDefaultAddressSpace()), "nondefault memory address");
                long address = AddressNormalizer.toElfAddress(entry.getOffset(), rebaseDelta);
                FunctionSymbol owner = owners.get(address);
                require(owner != null && !ambiguousEntries.contains(address), "not a unique exported function entry");
                var function = program.getFunctionManager().getFunctionAt(entry);
                require(function != null && !function.isExternal() && function.getName().equals(owner.name()),
                    "primary definition changed");
                var body = function.getBody();
                require(body.getNumAddressRanges() == owner.ranges().size() && owner.ranges().size() <= 65536,
                    "primary body disagrees with exported ranges");
                var actualRanges = body.getAddressRanges();
                for (var range : owner.ranges()) {
                    monitor.checkCancelled();
                    require(++comparedRanges <= MAX_NAME_BYTES, "body comparison budget exceeded");
                    var actual = actualRanges.next();
                    require(actual.getMinAddress().getAddressSpace().equals(entry.getAddressSpace()) &&
                        AddressNormalizer.toElfAddress(actual.getMinAddress().getOffset(), rebaseDelta) == range.address() &&
                        actual.getLength() == range.size(), "primary body disagrees with exported ranges");
                }
                List<ElfFunctionAlias.CodeRange> evidence = bodies.get(address);
                if (evidence == null) {
                    var collected = new ArrayList<ElfFunctionAlias.CodeRange>();
                    for (var range : owner.ranges()) {
                        monitor.checkCancelled();
                        require(range.size() <= MAX_CODE_BYTES - codeBytes, "original-code comparison budget exceeded");
                        codeBytes += range.size();
                        Address start = entry.addNoWrap(Math.subtractExact(range.address(), address));
                        collected.add(new ElfFunctionAlias.CodeRange(range.address(), range.size(),
                            hash(program, start, range.size(), monitor)));
                    }
                    evidence = List.copyOf(collected);
                    bodies.put(address, evidence);
                }
                result.add(new ElfFunctionAlias(name, owner.qualifiedDisplayName(), address, evidence));
            }
            catch (IllegalArgumentException | ArithmeticException | MemoryAccessException |
                    AddressOverflowException failure) {
                diagnostic.accept("Omitted function alias " + name + ": " + failure.getMessage());
            }
        }
        monitor.checkCancelled();
        return List.copyOf(result);
    }

    private static String hash(Program program, Address entry, long size, TaskMonitor monitor)
            throws MemoryAccessException, AddressOverflowException, CancelledException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        }
        catch (NoSuchAlgorithmException impossible) {
            throw new AssertionError(impossible);
        }
        byte[] bytes = new byte[65536];
        for (long done = 0; done < size;) {
            monitor.checkCancelled();
            Address cursor = entry.addNoWrap(done);
            var block = program.getMemory().getBlock(cursor);
            require(block != null && block.isInitialized() && block.isExecute() && !block.isOverlay(),
                "body is not initialized executable memory");
            int count = (int) Math.min(bytes.length, Math.min(size - done,
                block.getEnd().subtract(cursor) + 1));
            require(program.getMemory().getBytes(cursor, bytes, 0, count) == count,
                "incomplete program code bytes");
            digest.update(bytes, 0, count);
            done += count;
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalArgumentException(message);
        }
    }
}
