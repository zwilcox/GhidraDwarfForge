package ghidradwarfforge.output;

import com.sun.jna.Library;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.Pointer;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Linux Intel LP64 opened-file metadata primitive, not an attachment Host or admission
 * policy. listxattr can hide inaccessible namespaces: these observations MUST
 * NOT be interpreted as complete metadata or proof that hidden attributes do
 * not exist. Host admission/privileged verification remains a separate gate.
 *
 * Applies only ordinary mode/owner/group/mtime, user attributes and access ACLs
 * to an already owned private stage. Never creates, replaces or deletes a file.
 * Access/change/birth times, inode flags and hidden metadata are not preservation
 * claims. Cancellation is checked around native calls; it cannot interrupt a
 * blocked filesystem operation. No adversarial filesystem-race claim is made.
 */
public final class LinuxFileMetadata {
    private interface LibC extends Library {
        int open(byte[] path, int flags);
        int close(int fd);
        int statx(int fd, byte[] path, int flags, int mask, Pointer result);
        long flistxattr(int fd, Pointer names, long bytes);
        long fgetxattr(int fd, byte[] name, Pointer value, long bytes);
        int fsetxattr(int fd, byte[] name, Pointer value, long bytes, int flags);
        int fremovexattr(int fd, byte[] name);
        int fchown(int fd, int uid, int gid);
        int fchmod(int fd, int mode);
        int futimens(int fd, Pointer times);
    }

    private static final int REQUIRED_FIELDS = 0x3df;
    private static final int XATTR_LIMIT = 65536;
    private static final int TOTAL_LIMIT = 8 * 1024 * 1024;
    private static final HexFormat HEX = HexFormat.of();
    private final LibC libc;

    public record Facts(String identity, long links, int mode, long uid, long gid, long bytes,
            long modifiedSeconds, int modifiedNanos, long changedSeconds, int changedNanos,
            long attributes, long attributesMask) { }

    /** Names and values are lossless hexadecimal bytes; no UTF-8 assumption for xattrs. */
    public record Snapshot(Facts facts, Map<String, String> visibleAttributes) {
        public Snapshot { visibleAttributes = Map.copyOf(visibleAttributes); }

        /** Digest of this primitive's supported preservation fields, not full host metadata. */
        public String preservationSha256() {
            try {
                var bytes = new ByteArrayOutputStream();
                try (var out = new DataOutputStream(bytes)) {
                    out.writeInt(1);
                    out.writeInt(facts.mode());
                    out.writeLong(facts.uid());
                    out.writeLong(facts.gid());
                    out.writeLong(facts.modifiedSeconds());
                    out.writeInt(facts.modifiedNanos());
                    out.writeInt(visibleAttributes.size());
                    for (var entry : new TreeMap<>(visibleAttributes).entrySet()) {
                        for (String hex : new String[] {entry.getKey(), entry.getValue()}) {
                            byte[] value = HEX.parseHex(hex);
                            out.writeInt(value.length);
                            out.write(value);
                        }
                    }
                }
                return HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray()));
            }
            catch (IOException | NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
        }
    }

    public LinuxFileMetadata() throws IOException {
        if (!System.getProperty("os.name").equals("Linux") || !Platform.isIntel() ||
                Native.LONG_SIZE != 8 || Native.POINTER_SIZE != 8 ||
                !Charset.forName(System.getProperty("sun.jnu.encoding")).equals(StandardCharsets.UTF_8)) {
            throw new IOException("Linux metadata requires audited LP64 libc and UTF-8 native paths");
        }
        try { libc = Native.load("c", LibC.class); }
        catch (RuntimeException | LinkageError unavailable) {
            throw new IOException("Linux libc metadata calls are unavailable", unavailable);
        }
    }

    public Snapshot inspect(Path path, BooleanSupplier cancelled) throws IOException {
        try (var file = open(path, cancelled)) {
            var result = observe(file.fd, cancelled);
            require(result.facts().equals(stat(-100, pathBytes(path), 0x100)), "metadata path changed during inspection");
            return result;
        }
    }

    /** Caller must own the stage and establish complete host admission separately. */
    public Snapshot applyToOwnedStage(Path source, Snapshot expected, Path stage, BooleanSupplier cancelled)
            throws IOException {
        check(cancelled);
        supported(expected);
        try (var input = open(source, cancelled); var output = open(stage, cancelled)) {
            Snapshot before = observe(input.fd, cancelled);
            require(before.equals(expected), "metadata source changed");
            Snapshot prior = observe(output.fd, cancelled);
            supported(prior);
            require(!before.facts().identity().equals(prior.facts().identity()), "metadata stage aliases source");
            require(before.facts().links() == 1 && prior.facts().links() == 1, "metadata application rejects hardlinks");
            var wanted = before.facts();
            if (wanted.uid() != prior.facts().uid() || wanted.gid() != prior.facts().gid()) {
                check(cancelled);
                checked(libc.fchown(output.fd, (int) wanted.uid(), (int) wanted.gid()), "fchown");
            }
            check(cancelled);
            checked(libc.fchmod(output.fd, wanted.mode() & 0777), "fchmod");
            for (String name : prior.visibleAttributes().keySet()) {
                if (!before.visibleAttributes().containsKey(name)) {
                    check(cancelled);
                    checked(libc.fremovexattr(output.fd, nameBytes(name)), "fremovexattr");
                }
            }
            for (var attribute : new TreeMap<>(before.visibleAttributes()).entrySet()) {
                check(cancelled);
                byte[] value = HEX.parseHex(attribute.getValue());
                try (var memory = new Memory(Math.max(1, value.length))) {
                    memory.write(0, value, 0, value.length);
                    checked(libc.fsetxattr(output.fd, nameBytes(attribute.getKey()), memory, value.length, 0), "fsetxattr");
                }
            }
            try (var times = new Memory(32)) {
                times.clear();
                times.setLong(8, 0x3ffffffeL); // UTIME_OMIT: do not rewind ordinary read access times.
                times.setLong(16, wanted.modifiedSeconds());
                times.setLong(24, wanted.modifiedNanos());
                check(cancelled);
                checked(libc.futimens(output.fd, times), "futimens");
            }
            Snapshot after = observe(output.fd, cancelled);
            supported(after);
            require(after.facts().identity().equals(prior.facts().identity()) &&
                after.facts().bytes() == prior.facts().bytes() && after.facts().links() == 1,
                "metadata stage identity or size changed");
            require(after.preservationSha256().equals(before.preservationSha256()), "metadata application readback differs");
            require(observe(input.fd, cancelled).equals(before) &&
                stat(-100, pathBytes(source), 0x100).equals(before.facts()), "metadata source changed during application");
            require(stat(-100, pathBytes(stage), 0x100).equals(after.facts()), "metadata stage path changed");
            return after;
        }
    }

    private static void supported(Snapshot snapshot) throws IOException {
        require((snapshot.facts().mode() & 07000) == 0, "privileged file mode is unsupported");
        require(snapshot.facts().attributes() == 0, "special inode attributes require separate preservation policy");
        for (String name : snapshot.visibleAttributes().keySet()) {
            require(name.startsWith("757365722e") || name.equals(HEX.formatHex(
                "system.posix_acl_access".getBytes(StandardCharsets.US_ASCII))), "unsupported visible metadata namespace");
        }
    }

    private Snapshot observe(int fd, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        Facts before = stat(fd, new byte[] {0}, 0x1000);
        var attributes = new TreeMap<String, String>();
        int total = 0;
        try (var names = new Memory(XATTR_LIMIT); var value = new Memory(XATTR_LIMIT)) {
            long count = libc.flistxattr(fd, names, XATTR_LIMIT);
            checked(count, "flistxattr");
            require(count <= XATTR_LIMIT, "attribute list exceeds bound");
            byte[] bytes = names.getByteArray(0, (int) count);
            for (int begin = 0; begin < bytes.length;) {
                check(cancelled);
                int end = begin;
                while (end < bytes.length && bytes[end] != 0) end++;
                require(end < bytes.length && end > begin && end - begin <= 255, "malformed attribute name list");
                byte[] name = Arrays.copyOfRange(bytes, begin, end + 1);
                long size = libc.fgetxattr(fd, name, value, XATTR_LIMIT);
                checked(size, "fgetxattr");
                require(size <= XATTR_LIMIT, "attribute value exceeds bound");
                total += (int) size + name.length;
                require(total <= TOTAL_LIMIT && attributes.size() < 1024, "visible metadata exceeds bound");
                String key = HEX.formatHex(bytes, begin, end);
                require(attributes.put(key, HEX.formatHex(value.getByteArray(0, (int) size))) == null,
                    "duplicate attribute name");
                begin = end + 1;
            }
        }
        check(cancelled);
        require(before.equals(stat(fd, new byte[] {0}, 0x1000)), "opened metadata changed while reading attributes");
        return new Snapshot(before, attributes);
    }

    private Facts stat(int fd, byte[] path, int flags) throws IOException {
        try (var data = new Memory(256)) {
            data.clear();
            checked(libc.statx(fd, path, flags, 0x7ff, data), "statx");
            require((data.getInt(0) & REQUIRED_FIELDS) == REQUIRED_FIELDS, "statx omitted required metadata");
            int mode = Short.toUnsignedInt(data.getShort(28));
            require((mode & 0170000) == 0100000, "metadata requires a regular non-link file");
            require(data.getLong(40) >= 0 && data.getInt(120) >= 0 && data.getInt(120) < 1000000000 &&
                data.getInt(104) >= 0 && data.getInt(104) < 1000000000, "invalid statx size/time");
            return new Facts(Integer.toUnsignedString(data.getInt(136)) + ":" +
                Integer.toUnsignedString(data.getInt(140)) + ":" + Long.toUnsignedString(data.getLong(32)),
                Integer.toUnsignedLong(data.getInt(16)), mode, Integer.toUnsignedLong(data.getInt(20)),
                Integer.toUnsignedLong(data.getInt(24)), data.getLong(40), data.getLong(112), data.getInt(120),
                data.getLong(96), data.getInt(104), data.getLong(8), data.getLong(56));
        }
    }

    private Opened open(Path path, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        byte[] bytes = pathBytes(path);
        Facts before = stat(-100, bytes, 0x100);
        int fd = libc.open(bytes, 0x800 | 0x80000 | 0x20000); // RDONLY, NONBLOCK, CLOEXEC, NOFOLLOW
        checked(fd, "open");
        var opened = new Opened(fd);
        try {
            require(before.equals(stat(fd, new byte[] {0}, 0x1000)), "opened file differs from path observation");
            check(cancelled);
            return opened;
        }
        catch (IOException | RuntimeException failure) {
            try { opened.close(); } catch (IOException closeFailure) { failure.addSuppressed(closeFailure); }
            throw failure;
        }
    }

    private final class Opened implements AutoCloseable {
        private final int fd;
        private Opened(int fd) { this.fd = fd; }
        public void close() throws IOException { checked(libc.close(fd), "close"); }
    }

    private static byte[] nameBytes(String hex) {
        byte[] bytes = HEX.parseHex(hex);
        return Arrays.copyOf(bytes, bytes.length + 1);
    }

    private static byte[] pathBytes(Path path) throws IOException {
        Path absolute = path.toAbsolutePath();
        require(Path.of(absolute.toString()).equals(absolute), "native path is not losslessly representable");
        byte[] bytes = absolute.toString().getBytes(StandardCharsets.UTF_8);
        return Arrays.copyOf(bytes, bytes.length + 1);
    }

    private static void checked(long result, String operation) throws IOException {
        if (result < 0) throw new IOException("Linux metadata " + operation + " failed (errno=" + Native.getLastError() + ")");
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("Linux metadata operation cancelled");
    }

    private static void require(boolean value, String message) throws IOException {
        if (!value) throw new IOException(message);
    }
}
