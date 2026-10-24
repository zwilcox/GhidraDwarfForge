import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;

/** Independent, source-file-launchable fixture encoder; does not use Forge's ELF reader. */
public final class ElfLayoutFixtures {
    private static final int NULL_PROGRAM_PREFIX = 0xffff;
    private static final List<String> TARGETS = List.of(
        "x86_64", "aarch64", "arm32", "mips32be", "mips32le");

    private ElfLayoutFixtures() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 3 && args[0].equals("verify-runtime")) {
            verifyRuntime(Path.of(args[1]), Path.of(args[2]));
            return;
        }
        if (args.length == 4 && args[0].equals("verify-output")) {
            verifyOutput(Path.of(args[1]), Path.of(args[2]), args[3]);
            return;
        }
        if (args.length == 0) {
            throw new IllegalArgumentException("usage: ElfLayoutFixtures <fixture-root> [target ...]");
        }
        Path root = Path.of(args[0]).toAbsolutePath().normalize();
        List<String> targets = args.length == 1 ? TARGETS :
            Arrays.asList(Arrays.copyOfRange(args, 1, args.length));
        for (String target : targets) {
            require(TARGETS.contains(target), "unknown target: " + target);
            for (String role : List.of("exec", "pie")) {
                Path input = root.resolve(target).resolve("semantic." + role + ".stripped");
                byte[] bytes = Files.readAllBytes(input);
                byte[] hash = hash(bytes);
                for (String variant : List.of("no-section-names", "extended-programs")) {
                    byte[] result = variant.equals("no-section-names")
                        ? withoutSectionNames(bytes) : extendedPrograms(bytes);
                    byte[] repeated = variant.equals("no-section-names")
                        ? withoutSectionNames(bytes) : extendedPrograms(bytes);
                    require(Arrays.equals(result, repeated), "nondeterministic fixture encoder");
                    Path output = input.resolveSibling("semantic." + role + "." + variant);
                    Files.write(output, result);
                    if (!output.toFile().setExecutable(true, false) && !Files.isExecutable(output)) {
                        throw new IOException("cannot make fixture executable: " + output);
                    }
                    require(Arrays.equals(hash, hash(Files.readAllBytes(input))),
                        "fixture generation modified original: " + input);
                    Header generated = new Header(result);
                    System.out.printf("elf-layout-fixture=%s sections=%d names=%d programs=%d%n",
                        output, generated.sectionCount, generated.nameIndex, generated.programCount);
                }
            }
        }
    }

    private static byte[] withoutSectionNames(byte[] original) {
        Header before = new Header(original);
        require(before.sectionCount > 0 && before.nameIndex > 0,
            "fixture needs an ordinary named section table");
        byte[] result = original.clone();
        Header after = new Header(result);
        after.data.putShort(after.elf64 ? 62 : 50, (short) 0);
        for (int index = 0; index < before.sectionCount; index++) {
            after.data.putInt(before.sectionOffset + index * before.sectionSize, 0);
        }
        return result;
    }

    private static byte[] extendedPrograms(byte[] original) {
        Header before = new Header(original);
        require(before.programCount > 0 && before.programCount < NULL_PROGRAM_PREFIX &&
            before.sectionCount > 0, "fixture requires ordinary program and section tables");
        int count = Math.addExact(NULL_PROGRAM_PREFIX, before.programCount + 1);
        int tableOffset = align(original.length, 4096);
        int tableSize = Math.multiplyExact(count, before.programSize);
        byte[] result = Arrays.copyOf(original, Math.addExact(tableOffset, tableSize));
        int originalPrograms = tableOffset + NULL_PROGRAM_PREFIX * before.programSize;
        System.arraycopy(original, before.programOffset, result, originalPrograms,
            Math.multiplyExact(before.programCount, before.programSize));
        ByteBuffer output = ByteBuffer.wrap(result).order(before.data.order());
        long end = 0;
        for (int index = 0; index < before.programCount; index++) {
            int offset = before.programOffset + index * before.programSize;
            if (before.data.getInt(offset) == 1) {
                end = Math.max(end, Math.addExact(before.word(offset + (before.elf64 ? 16 : 8)),
                    before.word(offset + (before.elf64 ? 40 : 20))));
            }
        }
        long tableAddress = Math.addExact(end, 4095L) & ~4095L;
        // Map the relocated table into the image and update PT_PHDR. Merely
        // appending headers would leave the interpreter's AT_PHDR unmapped.
        for (int index = 0; index < before.programCount; index++) {
            int offset = originalPrograms + index * before.programSize;
            if (output.getInt(offset) == 6) {
                writeProgram(output, offset, before.elf64, 6, 4, tableOffset,
                    tableAddress, tableSize, before.elf64 ? 8 : 4);
            }
        }
        writeProgram(output, originalPrograms + before.programCount * before.programSize,
            before.elf64, 1, 4, tableOffset, tableAddress, tableSize, 4096);
        if (before.elf64) {
            output.putLong(32, tableOffset);
        }
        else {
            output.putInt(28, tableOffset);
        }
        output.putShort(before.elf64 ? 56 : 44, (short) 0xffff);
        output.putInt(before.sectionOffset + (before.elf64 ? 44 : 28), count);
        Header after = new Header(result);
        require(after.programCount == count,
            "fixture did not encode the true PN_XNUM program count");
        return result;
    }

    private static void writeProgram(ByteBuffer output, int offset, boolean elf64,
            int type, int flags, long fileOffset, long address, long size, long alignment) {
        output.putInt(offset, type);
        if (elf64) {
            output.putInt(offset + 4, flags);
            output.putLong(offset + 8, fileOffset);
            output.putLong(offset + 16, address);
            output.putLong(offset + 24, address);
            output.putLong(offset + 32, size);
            output.putLong(offset + 40, size);
            output.putLong(offset + 48, alignment);
        }
        else {
            output.putInt(offset + 4, Math.toIntExact(fileOffset));
            output.putInt(offset + 8, Math.toIntExact(address));
            output.putInt(offset + 12, Math.toIntExact(address));
            output.putInt(offset + 16, Math.toIntExact(size));
            output.putInt(offset + 20, Math.toIntExact(size));
            output.putInt(offset + 24, flags);
            output.putInt(offset + 28, Math.toIntExact(alignment));
        }
    }

    private static void verifyOutput(Path input, Path output, String variant) throws Exception {
        Header before = new Header(Files.readAllBytes(input));
        Header after = new Header(Files.readAllBytes(output));
        require(Arrays.equals(Arrays.copyOf(before.bytes, 24), Arrays.copyOf(after.bytes, 24)),
            "ELF identification/type/machine/version changed");
        require(before.word(24) == after.word(24) &&
            before.data.getInt(before.elf64 ? 48 : 36) == after.data.getInt(after.elf64 ? 48 : 36),
            "ELF entry/ABI flags changed");
        require(after.programCount == 0 && after.programOffset == 0,
            "sidecar retained program headers");
        require(after.sectionCount > before.sectionCount && after.nameIndex > 0,
            "sidecar did not add named DWARF/section table");
        require(after.data.getInt(after.sectionOffset + (after.elf64 ? 44 : 28)) == 0,
            "sidecar retained stale extended program count");
        if (variant.equals("no-section-names")) {
            require(before.nameIndex == 0, "input has a section-name table");
            for (int index = 1; index < before.sectionCount; index++) {
                int oldOffset = before.sectionOffset + index * before.sectionSize;
                int newOffset = after.sectionOffset + index * after.sectionSize;
                require(after.data.getInt(newOffset) == 0,
                    "invented original section name at index " + index);
                int type = before.data.getInt(oldOffset + 4);
                if (type == 4 || type == 9) {
                    byte[] neutral = new byte[after.sectionSize];
                    ByteBuffer header = ByteBuffer.wrap(neutral).order(after.data.order());
                    header.putInt(4, 8);
                    if (after.elf64) {
                        header.putLong(48, 1);
                    }
                    else {
                        header.putInt(32, 1);
                    }
                    require(Arrays.equals(neutral, Arrays.copyOfRange(after.bytes,
                        newOffset, newOffset + after.sectionSize)),
                        "inherited relocation section was not canonically neutralized");
                    continue;
                }
                require(Arrays.equals(Arrays.copyOfRange(before.bytes, oldOffset + 4,
                    oldOffset + before.sectionSize), Arrays.copyOfRange(after.bytes,
                    newOffset + 4, newOffset + after.sectionSize)),
                    "unnamed section metadata/index changed at " + index);
                if (type != 0 && type != 8) {
                    int payload = Math.toIntExact(before.word(oldOffset + (before.elf64 ? 24 : 16)));
                    int length = Math.toIntExact(before.word(oldOffset + (before.elf64 ? 32 : 20)));
                    require(Arrays.equals(Arrays.copyOfRange(before.bytes, payload,
                        Math.addExact(payload, length)), Arrays.copyOfRange(after.bytes,
                        payload, Math.addExact(payload, length))),
                        "unnamed section payload changed at " + index);
                }
            }
        }
        else {
            require(variant.equals("extended-programs") &&
                before.programCount > NULL_PROGRAM_PREFIX, "incorrect PN_XNUM fixture");
        }
        System.out.println("elf-layout-output-metadata=PASS " + variant);
    }

    private static void verifyRuntime(Path extended, Path ordinary) throws Exception {
        Header before = new Header(Files.readAllBytes(ordinary));
        Header after = new Header(Files.readAllBytes(extended));
        require(after.programCount == NULL_PROGRAM_PREFIX + before.programCount + 1,
            "runtime comparison needs the complete PN_XNUM table");
        for (int index = 0; index < NULL_PROGRAM_PREFIX; index++) {
            require(after.data.getInt(after.programOffset + index * after.programSize) == 0,
                "fixture has meaningful program metadata before the escape threshold");
        }
        boolean lateLoad = false;
        for (int index = NULL_PROGRAM_PREFIX; index < after.programCount - 1; index++) {
            lateLoad |= after.data.getInt(after.programOffset + index * after.programSize) == 1;
        }
        require(lateLoad, "fixture has no original PT_LOAD beyond the escape threshold");
        byte[] prefix = Arrays.copyOf(after.bytes, before.bytes.length);
        // The original image prefix differs only in these count/table fields.
        // No original segment address, instruction or data byte may change.
        for (int[] field : new int[][] {
                { before.elf64 ? 32 : 28, before.elf64 ? 8 : 4 },
                { before.elf64 ? 56 : 44, 2 },
                { before.sectionOffset + (before.elf64 ? 44 : 28), 4 } }) {
            System.arraycopy(before.bytes, field[0], prefix, field[0], field[1]);
        }
        require(Arrays.equals(before.bytes, prefix), "PN_XNUM altered the original load image");
        System.out.println("elf-layout-runtime-equivalence=PASS original_loads_unchanged=true");
    }

    private static final class Header {
        private final byte[] bytes;
        private final ByteBuffer data;
        private final boolean elf64;
        private final int sectionOffset;
        private final int sectionSize;
        private final int sectionCount;
        private final int nameIndex;
        private final int programOffset;
        private final int programSize;
        private final int programCount;

        private Header(byte[] bytes) {
            this.bytes = bytes;
            require(bytes.length >= 64 && bytes[0] == 0x7f && bytes[1] == 'E' &&
                bytes[2] == 'L' && bytes[3] == 'F', "not an ELF fixture");
            elf64 = bytes[4] == 2;
            data = ByteBuffer.wrap(bytes).order(bytes[5] == 1
                ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
            sectionOffset = Math.toIntExact(word(elf64 ? 40 : 32));
            sectionSize = Short.toUnsignedInt(data.getShort(elf64 ? 58 : 46));
            int count = Short.toUnsignedInt(data.getShort(elf64 ? 60 : 48));
            sectionCount = count == 0 && sectionOffset != 0
                ? Math.toIntExact(word(sectionOffset + (elf64 ? 32 : 20))) : count;
            int names = Short.toUnsignedInt(data.getShort(elf64 ? 62 : 50));
            nameIndex = names == 0xffff
                ? data.getInt(sectionOffset + (elf64 ? 40 : 24)) : names;
            programOffset = Math.toIntExact(word(elf64 ? 32 : 28));
            programSize = Short.toUnsignedInt(data.getShort(elf64 ? 54 : 42));
            int programs = Short.toUnsignedInt(data.getShort(elf64 ? 56 : 44));
            programCount = programs == 0xffff
                ? data.getInt(sectionOffset + (elf64 ? 44 : 28)) : programs;
        }

        private long word(int offset) {
            return elf64 ? data.getLong(offset) : Integer.toUnsignedLong(data.getInt(offset));
        }
    }

    private static int align(int value, int alignment) {
        return Math.addExact(value, alignment - 1) & -alignment;
    }

    private static byte[] hash(byte[] bytes) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(bytes);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalArgumentException(message);
        }
    }
}
