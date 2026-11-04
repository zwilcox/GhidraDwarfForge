package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CancellationException;

/** Standalone mount binding checks; no target modification or elevated calls. */
public final class LinuxAttachmentMountSmoke {
    private static final String RECORD = "33 2 259:2 / / rw,relatime shared:1 - ext4 /dev/example rw";
    private static final String IDENTITY = "259:2:123@33";
    private static int checks;
    @FunctionalInterface interface Action { void run() throws Exception; }

    public static void main(String[] args) throws Exception {
        require(args.length == 1, "expected a new owned directory");
        require(select(RECORD + "\n").equals(RECORD), "ordinary mount record");
        String escaped = RECORD.replace("/ /", "/a\\040b /c\\134d");
        require(select(escaped + "\n").equals(escaped), "escaped paths must remain opaque");
        String highByte = RECORD.replace("/dev/example", "/dev/\u00ff");
        require(select(highByte + "\n").equals(highByte), "non-UTF8 source bytes must remain lossless");
        require(select("9 1 0:2 / /proc rw - proc proc rw\n" + RECORD + "\n").equals(RECORD),
            "select by ID rather than table position");
        for (String bad : new String[] {
                "", RECORD, RECORD + "\n" + RECORD + "\n",
                RECORD.replace("ext4", "ext3") + "\n",
                RECORD.replace("ext4", "ext2") + "\n",
                RECORD.replace("259:2", "259:3") + "\n",
                RECORD.replace("33 2", "34 2") + "\n",
                RECORD.replace("rw,relatime", "ro,relatime") + "\n",
                RECORD.replace("example rw", "example ro") + "\n",
                RECORD.replace("shared:1", "idmapped") + "\n",
                RECORD.replace("shared:1", "shared:bad") + "\n",
                RECORD.replace("shared:1", "shared:1 -") + "\n",
                RECORD.replace("shared:1", "shared:1\0") + "\n",
                RECORD.replace("/ /", "/  /") + "\n"}) {
            refused(() -> select(bad), IOException.class);
        }
        refused(() -> LinuxAttachmentMount.select(new byte[LinuxAttachmentMount.LIMIT + 1], IDENTITY), IOException.class);
        refused(() -> LinuxAttachmentMount.select((RECORD + "\n").getBytes(StandardCharsets.US_ASCII),
            "259:2:123"), IOException.class);
        Path directory = Files.createDirectory(Path.of(args[0]));
        var mount = new LinuxAttachmentMount(new LinuxDirectorySync());
        var observed = mount.inspect(directory, () -> false);
        require(observed.mountRecord().contains(" - ext4 "), "actual ext4 record");
        refused(() -> mount.inspect(Path.of("/proc"), () -> false), IOException.class);
        refused(() -> mount.inspect(directory, () -> true), CancellationException.class);
        Path link = directory.resolve("leaf-link");
        Files.createSymbolicLink(link, directory);
        refused(() -> mount.inspect(link, () -> false), IOException.class);
        Files.delete(link);
        long descriptors = descriptors();
        for (int i = 0; i < 128; i++) require(mount.inspect(directory, () -> false).equals(observed), "mount changed");
        require(descriptors() == descriptors, "mount descriptor growth");
        System.out.println("identity=" + observed.directory().identity());
        System.out.println("mountRecord=" + observed.mountRecord());
        System.out.println("mount-binding=PASS checks=" + checks);
    }

    private static long descriptors() throws IOException {
        try (var entries = Files.list(Path.of("/proc/self/fd"))) { return entries.count(); }
    }
    private static String select(String records) throws IOException {
        return LinuxAttachmentMount.select(records.getBytes(StandardCharsets.ISO_8859_1), IDENTITY);
    }
    private static void refused(Action action, Class<? extends Exception> expected) throws Exception {
        try { action.run(); }
        catch (Exception failure) { require(expected.isInstance(failure), "wrong refusal: " + failure); return; }
        throw new AssertionError("unexpected success");
    }
    private static void require(boolean value, String message) {
        if (!value) throw new AssertionError(message);
        checks++;
    }
}
