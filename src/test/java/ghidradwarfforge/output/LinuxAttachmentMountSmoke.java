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
        parserBoundaries();
        if (args.length == 1 && args[0].equals("--parser-only")) {
            System.out.println("mount-parser=PASS checks=" + checks);
            return;
        }
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
        var virtualFailure = new java.util.concurrent.atomic.AtomicReference<Throwable>();
        Thread virtual = Thread.ofVirtual().unstarted(() -> {
            try { mount.inspect(directory, () -> false); }
            catch (Throwable failure) { virtualFailure.set(failure); }
        });
        virtual.start();
        virtual.join();
        require(virtualFailure.get() instanceof IOException &&
            virtualFailure.get().getMessage().contains("requires a platform thread"),
            "virtual thread mount inspection was not rejected before native observation");
        int[] polls = {0};
        require(mount.inspect(directory, () -> { polls[0]++; return false; }).equals(observed),
            "counted mount observation changed snapshot");
        long beforeCancellation = descriptors();
        for (int stop = 1; stop <= polls[0]; stop++) {
            int selected = stop;
            int[] current = {0};
            refused(() -> mount.inspect(directory, () -> ++current[0] == selected), CancellationException.class);
            require(mount.inspect(directory, () -> false).equals(observed), "cancelled observation poisoned retry");
            require(descriptors() == beforeCancellation, "cancelled mount observation leaked descriptors");
        }
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

    /** Kernel proc(5) mountinfo fields, plus Forge's deliberately stricter admission policy.
     * https://www.kernel.org/doc/html/latest/filesystems/proc.html#proc-pid-mountinfo-information-about-mounts
     * Synthetic parser cases do not establish real host attachment eligibility. */
    private static void parserBoundaries() throws Exception {
        for (String optional : new String[] {"", "unbindable", "master:1", "shared:1 master:2",
                "master:2 propagate_from:3", "shared:18446744073709551615"}) {
            String record = RECORD.replace("shared:1 ", optional.isEmpty() ? "" : optional + " ");
            require(select(record + "\n").equals(record), "recognized mount field rejected: " + optional);
        }
        for (String id : new String[] {"0", "1", "9223372036854775808", "18446744073709551615"}) {
            String record = RECORD.replace("33 2 ", id + " " + id + " ");
            require(LinuxAttachmentMount.select((record + "\n").getBytes(StandardCharsets.US_ASCII),
                "259:2:123@" + id).equals(record), "unsigned mount ID changed");
        }
        for (String bad : new String[] {"", "+1", "-1", "01", "1x", "x1", "18446744073709551616"}) {
            for (String prefix : new String[] {"shared:", "master:", "propagate_from:"}) {
                rejectRecord(RECORD.replace("shared:1", prefix + bad) + "\n", IDENTITY,
                    "unreviewed attachment mount field");
            }
            rejectRecord(RECORD + "\n", "259:2:123@" + bad, "missing native mount ID");
            rejectRecord(RECORD.replace("33 2 ", bad + " 2 ") + "\n", IDENTITY, "malformed mount entry");
            rejectRecord(RECORD.replace("33 2 ", "33 " + bad + " ") + "\n", IDENTITY, "malformed mount entry");
        }
        for (String identity : new String[] {"", "259:2", "259:2:123@33:extra"}) {
            rejectRecord(RECORD + "\n", identity, "invalid native directory identity");
        }
        rejectRecord(RECORD + "\n", "259:2:123@33@34", "missing native mount ID");
        for (String control : new String[] {"\0", "\r", "\t"}) {
            rejectRecord(RECORD.replace("example", "exam" + control + "ple") + "\n", IDENTITY,
                "malformed mount information");
        }
        rejectRecord("33 2 259:2\n", IDENTITY, "malformed mount entry");
        rejectRecord(RECORD.replace(" - ", " missing ") + "\n", IDENTITY, "malformed selected mount entry");
        rejectRecord(RECORD + " extra\n", IDENTITY, "malformed selected mount entry");
        for (boolean superblock : new boolean[] {false, true}) {
            for (String options : new String[] {"rw", "relatime,rw", "rw,relatime"}) {
                String record = superblock ? RECORD.substring(0, RECORD.length() - 2) + options :
                    RECORD.replace("rw,relatime", options);
                require(select(record + "\n").equals(record), "valid writable options rejected");
            }
            for (String options : new String[] {"ro", "ro,rw", "rw,ro", "rw,", ",rw", "rw,,relatime", "rwx"}) {
                String record = superblock ? RECORD.substring(0, RECORD.length() - 2) + options :
                    RECORD.replace("rw,relatime", options);
                rejectRecord(record + "\n", IDENTITY, "attachment mount is not writable");
            }
        }
        String limit = RECORD.replace("/dev/example", "x".repeat(
            LinuxAttachmentMount.LIMIT - RECORD.length() - 1 + "/dev/example".length()));
        require((limit + "\n").length() == LinuxAttachmentMount.LIMIT, "mount limit fixture length");
        require(select(limit + "\n").equals(limit), "exact mount information bound rejected");
        rejectRecord(limit + "x\n", IDENTITY, "incomplete or oversized mount information");
    }

    private static void rejectRecord(String record, String identity, String diagnostic) throws Exception {
        byte[] bytes = record.getBytes(StandardCharsets.ISO_8859_1);
        byte[] before = bytes.clone();
        try {
            LinuxAttachmentMount.select(bytes, identity);
            throw new AssertionError("accepted invalid mount record: " + diagnostic);
        }
        catch (IOException expected) {
            require(expected.getMessage().contains(diagnostic), "wrong mount rejection: " + expected);
        }
        require(java.util.Arrays.equals(bytes, before), "mount rejection modified input");
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
