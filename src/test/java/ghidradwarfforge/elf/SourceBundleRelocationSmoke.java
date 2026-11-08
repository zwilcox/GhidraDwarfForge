package ghidradwarfforge.elf;

import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;
import ghidradwarfforge.dwarf.SyntheticSourceRelocation;
import ghidradwarfforge.output.SourceBundleFiles;

/** Real headless-produced sections; the integration driver independently validates and runs GDB. */
public final class SourceBundleRelocationSmoke {
    public static void main(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException("sidecar index destination-directory");
        Path sidecar = Path.of(args[0]);
        Path index = Path.of(args[1]);
        Path destination = Path.of(args[2]).toAbsolutePath();
        Files.createDirectory(destination);
        var bundle = SourceBundleFiles.open(index, () -> false).orElseThrow();
        String directory = destination.toString().replace(java.io.File.separatorChar, '/');
        var plan = SyntheticSourceSidecar.prepare(sidecar, directory, () -> false);
        bundle.requireSourceNames(plan.sourceFiles());
        if (plan.sourceFiles().size() < 3) throw new AssertionError("fixture needs multiple source files");
        for (Path source : bundle.files()) Files.copy(source, destination.resolve(source.getFileName()));
        Path relocated = destination.resolve(sidecar.getFileName());
        try (var stage = FileChannel.open(relocated, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            plan.writeStage(stage, () -> false);
        }
        plan.requireMatches(relocated, () -> false);
        var retained = SourceBundleFiles.open(destination.resolve(index.getFileName()), () -> false).orElseThrow();
        retained.requireSourceNames(plan.sourceFiles());
        if (!bundle.manifest().equals(retained.manifest())) throw new AssertionError("transport altered source inventory");
        var again = SyntheticSourceSidecar.prepare(relocated, directory, () -> false);
        again.requireMatches(relocated, () -> false);
        if (!again.sourceFiles().equals(plan.sourceFiles())) throw new AssertionError("relocation changed source indices");

        var image = ElfImage.read(sidecar);
        var moved = ElfImage.read(relocated);
        byte[] info = section(image, ".debug_info");
        byte[] abbrev = section(image, ".debug_abbrev");
        byte[] strings = section(image, ".debug_str");
        byte[] line = section(image, ".debug_line");
        byte[] afterLine = section(moved, ".debug_line");
        int beforeProgram = 12 + ByteBuffer.wrap(line).order(image.byteOrder()).getInt(8);
        int afterProgram = 12 + ByteBuffer.wrap(afterLine).order(image.byteOrder()).getInt(8);
        if (!Arrays.equals(Arrays.copyOfRange(line, beforeProgram, line.length),
                Arrays.copyOfRange(afterLine, afterProgram, afterLine.length))) throw new AssertionError("line program changed");
        for (String name : List.of(".debug_abbrev", ".debug_rnglists", ".debug_loclists", ".debug_aranges")) {
            if (!Arrays.equals(section(image, name), section(moved, name))) throw new AssertionError(name + " changed");
        }
        var wrongOrder = new ArrayList<>(plan.sourceFiles());
        java.util.Collections.swap(wrongOrder, 1, 2);
        try { bundle.requireSourceNames(wrongOrder); throw new AssertionError("wrong source index order accepted"); }
        catch (java.io.IOException expected) { }
        // Preserve byte lengths while introducing forbidden paths/duplicate names in the real file table.
        byte[] firstName = plan.sourceFiles().get(1).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] secondName = plan.sourceFiles().get(2).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        int firstOffset = locate(line, firstName);
        int secondOffset = locate(line, secondName);
        byte[] path = line.clone(); path[firstOffset] = '/';
        byte[] duplicate = line.clone();
        if (firstName.length != secondName.length) throw new AssertionError("expected equal generated filename widths");
        System.arraycopy(firstName, 0, duplicate, secondOffset, firstName.length);
        for (byte[] malformed : List.of(path, duplicate)) {
            try {
                SyntheticSourceRelocation.relocate(info, abbrev, strings, malformed, image.byteOrder(), directory, () -> false);
                throw new AssertionError("invalid multi-file table accepted");
            }
            catch (IllegalArgumentException expected) { }
        }
        AtomicInteger visits = new AtomicInteger();
        SyntheticSourceRelocation.relocate(info, abbrev, strings, line, image.byteOrder(), directory,
            () -> { visits.incrementAndGet(); return false; });
        for (int stop = 1; stop <= visits.get(); stop++) {
            AtomicInteger reached = new AtomicInteger();
            int selected = stop;
            try {
                SyntheticSourceRelocation.relocate(info, abbrev, strings, line, image.byteOrder(), directory,
                    () -> reached.incrementAndGet() == selected);
                throw new AssertionError("missed relocation cancellation at " + stop);
            }
            catch (CancellationException expected) { }
        }
        bundle.verify(() -> false);
        System.out.println("source-bundle-relocation-smoke=PASS files=" + plan.sourceFiles().size() +
            " cancellation=" + visits.get());
    }

    private static byte[] section(ElfImage image, String name) throws Exception {
        var section = image.sections().stream().filter(s -> s.name.equals(name)).findFirst().orElseThrow();
        if ((section.flags & 0x800) != 0) throw new AssertionError("this raw-byte fixture requires uncompressed sections");
        return image.sectionData(section);
    }

    private static int locate(byte[] bytes, byte[] name) {
        for (int start = 0; start <= bytes.length - name.length; start++) {
            if (Arrays.equals(bytes, start, start + name.length, name, 0, name.length)) return start;
        }
        throw new AssertionError("expected file table string");
    }
}
