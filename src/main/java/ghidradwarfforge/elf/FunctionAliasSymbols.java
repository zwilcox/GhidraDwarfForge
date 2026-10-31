package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.StandardOpenOption;
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
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

import ghidradwarfforge.elf.ElfImage.Section;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** Bounds, collisions and original-byte binding for direct-address ELF aliases. */
public final class FunctionAliasSymbols {
    private static final long MAX_NAMES = 16L * 1024 * 1024;

    private FunctionAliasSymbols() {
    }

    /** Called only after the target description authorizes direct-address symbol semantics. */
    public static List<ElfLocalFunctionSymbol> plan(ElfImage image, List<ElfFunctionAlias> aliases,
            List<FunctionSymbol> functions, List<ElfLocalFunctionSymbol> reserved,
            BooleanSupplier cancelled, Consumer<String> diagnostic) throws IOException {
        checkCancelled(cancelled);
        if (aliases.isEmpty()) {
            return List.of();
        }
        if (image.sections().isEmpty() || (image.type() != 2 && image.type() != 3)) {
            diagnostic.accept("Omitted function aliases: requires section-backed ET_EXEC or ET_DYN");
            return List.of();
        }
        long ranges = 0;
        for (FunctionSymbol function : functions) {
            checkCancelled(cancelled);
            ranges += function.ranges().size();
        }
        if (aliases.size() > 65536 || (long) aliases.size() * (image.sections().size() + ranges) > MAX_NAMES) {
            diagnostic.accept("Omitted function aliases: allocation/ownership comparison budget exceeded");
            return List.of();
        }
        Set<ByteBuffer> originalNames;
        try {
            originalNames = originalNames(image, cancelled);
        }
        catch (IllegalArgumentException unsupported) {
            diagnostic.accept("Omitted function aliases: " + unsupported.getMessage());
            return List.of();
        }
        Set<String> occupied = new HashSet<>();
        Map<String, Integer> counts = new HashMap<>();
        Map<Long, FunctionSymbol> owners = new HashMap<>();
        Set<Long> ambiguousEntries = new HashSet<>();
        for (FunctionSymbol function : functions) {
            checkCancelled(cancelled);
            occupied.add(function.qualifiedDisplayName());
            if (owners.putIfAbsent(function.address(), function) != null) {
                ambiguousEntries.add(function.address());
            }
        }
        for (ElfLocalFunctionSymbol symbol : reserved) {
            occupied.add(symbol.name());
        }
        long namesSize = 0;
        for (ElfFunctionAlias alias : aliases) {
            checkCancelled(cancelled);
            counts.merge(alias.name(), 1, Integer::sum);
            namesSize += alias.name().getBytes(StandardCharsets.UTF_8).length + 1;
            if (namesSize > MAX_NAMES) {
                diagnostic.accept("Omitted function aliases: new name budget exceeded");
                return List.of();
            }
        }
        List<ElfFunctionAlias> ordered = new ArrayList<>(aliases);
        ordered.sort(Comparator.comparingLong(ElfFunctionAlias::address).thenComparing(ElfFunctionAlias::name));
        List<ElfLocalFunctionSymbol> result = new ArrayList<>();
        Map<Long, String> hashes = new HashMap<>();
        long codeBytes = 0;
        try (FileChannel input = FileChannel.open(image.sourcePath(), StandardOpenOption.READ)) {
            image.requireUnchanged(input);
            for (ElfFunctionAlias alias : ordered) {
                checkCancelled(cancelled);
                try {
                    require(counts.get(alias.name()) == 1 && !occupied.contains(alias.name()),
                        "name conflicts with another recovered symbol");
                    require(!originalNames.contains(ByteBuffer.wrap(alias.name().getBytes(StandardCharsets.UTF_8))),
                        "name already exists in original ELF symbol tables");
                    FunctionSymbol owner = owners.get(alias.address());
                    require(owner != null && !ambiguousEntries.contains(alias.address()) &&
                        owner.qualifiedDisplayName().equals(alias.owner()) && owner.contiguous() &&
                        owner.ranges().get(0).address() == alias.address() &&
                        owner.ranges().get(0).size() == alias.size(), "primary definition disagrees with alias evidence");
                    for (FunctionSymbol other : functions) {
                        checkCancelled(cancelled);
                        if (other == owner) {
                            continue;
                        }
                        for (var range : other.ranges()) {
                            checkCancelled(cancelled);
                            require(!intersects(alias.address(), alias.size(), range.address(), range.size()),
                                "overlapping recovered definitions");
                        }
                    }
                    Section selected = null;
                    for (Section section : image.sections()) {
                        checkCancelled(cancelled);
                        if ((section.flags & 2) != 0 && section.size > 0 &&
                                intersects(alias.address(), alias.size(), section.address, section.size)) {
                            require(selected == null, "overlapping original allocations");
                            selected = section;
                        }
                    }
                    require(selected != null && selected.type == 1 && (selected.flags & 6) == 6 &&
                        alias.address() >= selected.address && alias.address() - selected.address <= selected.size &&
                        alias.size() <= selected.size - (alias.address() - selected.address),
                        "body has no unique file-backed executable section");
                    String hash = hashes.get(alias.address());
                    if (hash == null) {
                        require(alias.size() <= 256L * 1024 * 1024 - codeBytes,
                            "original-code comparison budget exceeded");
                        codeBytes += alias.size();
                        hash = hash(input, Math.addExact(selected.offset, alias.address() - selected.address),
                            alias.size(), cancelled);
                        hashes.put(alias.address(), hash);
                    }
                    require(hash.equals(alias.codeSha256()), "program code differs from original ELF");
                    result.add(new ElfLocalFunctionSymbol(alias.name(), alias.address(), alias.size(), selected.originalIndex));
                }
                catch (IllegalArgumentException | ArithmeticException unsupported) {
                    diagnostic.accept("Omitted function alias " + alias.name() + ": " + unsupported.getMessage());
                }
            }
            checkCancelled(cancelled);
            image.requireUnchanged(input);
        }
        return List.copyOf(result);
    }

    private static boolean intersects(long a, long sizeA, long b, long sizeB) {
        return a < b ? b - a < sizeA : a - b < sizeB;
    }

    private static Set<ByteBuffer> originalNames(ElfImage image, BooleanSupplier cancelled) throws IOException {
        boolean hasStatic = image.sections().stream().anyMatch(s -> s.type == 2);
        Set<ByteBuffer> names = new HashSet<>();
        long totalNames = 0;
        long totalRows = 0;
        long stringBytes = 0;
        Map<Integer, byte[]> loadedStrings = new HashMap<>();
        int width = image.is64Bit() ? 24 : 16;
        for (Section table : image.sections()) {
            checkCancelled(cancelled);
            if (table.type != 2 && table.type != 11) {
                continue;
            }
            require(table.entrySize == width && table.size >= width && table.size % width == 0 &&
                table.link > 0 && table.link < image.sections().size(), "unsupported original symbol table framing");
            totalRows += table.size / width;
            require(totalRows <= 262144, "original symbol inventory exceeds row budget");
            Section strings = image.sections().get((int) table.link);
            require(strings.type == 3 && strings.size > 0 && strings.size <= MAX_NAMES,
                "unsupported original symbol string table");
            byte[] text = loadedStrings.get(strings.originalIndex);
            if (text == null) {
                stringBytes += strings.size;
                require(stringBytes <= MAX_NAMES, "original string tables exceed aggregate budget");
                text = image.sectionData(strings);
                loadedStrings.put(strings.originalIndex, text);
            }
            require(text[0] == 0 && text[text.length - 1] == 0, "original symbol strings lack boundary terminators");
            ByteBuffer rows = ByteBuffer.wrap(image.sectionData(table)).order(image.byteOrder());
            for (int index = 0; index < width; index++) {
                require(rows.get(index) == 0, "original symbol row zero is not null");
            }
            for (int at = 0; at < rows.limit(); at += width) {
                checkCancelled(cancelled);
                long offset = Integer.toUnsignedLong(rows.getInt(at));
                require(offset < text.length, "invalid original symbol name offset");
                int end = (int) offset;
                while (text[end] != 0) {
                    require(++end - offset <= 65536, "original symbol name exceeds budget");
                }
                totalNames += end - offset;
                require(totalNames <= MAX_NAMES, "original symbol names exceed aggregate budget");
                if (offset != 0) {
                    // No lossy decoding: arbitrary old name bytes cannot alias a new UTF-8 string.
                    names.add(ByteBuffer.wrap(text, (int) offset, end - (int) offset).slice().asReadOnlyBuffer());
                    int section = Short.toUnsignedInt(rows.getShort(at + (image.is64Bit() ? 6 : 14)));
                    require(hasStatic || table.type != 11 || section == 0,
                        "defined dynamic symbols would be hidden by a partial static table");
                }
            }
        }
        return names;
    }

    private static String hash(FileChannel input, long offset, long size, BooleanSupplier cancelled) throws IOException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        }
        catch (NoSuchAlgorithmException impossible) {
            throw new AssertionError(impossible);
        }
        ByteBuffer bytes = ByteBuffer.allocate(65536);
        for (long done = 0; done < size;) {
            checkCancelled(cancelled);
            bytes.clear().limit((int) Math.min(bytes.capacity(), size - done));
            int count = input.read(bytes, offset + done);
            if (count <= 0) {
                throw new IOException("original alias code bytes ended or stopped making progress");
            }
            digest.update(bytes.array(), 0, count);
            done += count;
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalArgumentException(message);
        }
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) {
            throw new CancellationException("function-alias planning cancelled");
        }
    }
}
