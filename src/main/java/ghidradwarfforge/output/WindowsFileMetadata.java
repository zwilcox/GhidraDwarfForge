package ghidradwarfforge.output;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.HexFormat;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Opened-handle Windows metadata primitive, NOT an attachment Host/admission
 * decision. Reads owner/group/DACL, ordinary attributes/times and data streams.
 * It neither queries SACLs/extended attributes nor proves their absence. Full
 * protected-metadata admission and host durability remain separate requirements.
 * Never enables privileges, creates a file or replaces a target. Application is
 * restricted to a caller-owned private stage; failures may leave that stage
 * partly adjusted. Blocking kernel calls cannot be interrupted by cancellation.
 */
public final class WindowsFileMetadata {
    private interface Kernel extends StdCallLibrary {
        Pointer CreateFileW(WString path, int access, int sharing, Pointer security, int disposition, int flags, Pointer template);
        int CloseHandle(Pointer handle);
        int GetFileType(Pointer handle);
        int GetFileInformationByHandleEx(Pointer handle, int kind, Pointer info, int size);
        int SetFileInformationByHandle(Pointer handle, int kind, Pointer info, int size);
        Pointer LocalFree(Pointer memory);
        Pointer GetCurrentProcess();
        int GetProcessHandleCount(Pointer process, Pointer count);
    }

    private interface SecurityApi extends StdCallLibrary {
        int GetSecurityInfo(Pointer handle, int type, int fields, PointerByReference owner, PointerByReference group,
            PointerByReference dacl, Pointer sacl, PointerByReference descriptor);
        int SetFileSecurityW(WString path, int fields, Pointer descriptor);
        int SetSecurityInfo(Pointer handle, int type, int fields, Pointer owner, Pointer group, Pointer dacl, Pointer sacl);
        int IsValidSecurityDescriptor(Pointer descriptor);
        int GetSecurityDescriptorLength(Pointer descriptor);
        int GetSecurityDescriptorControl(Pointer descriptor, Pointer control, Pointer revision);
        int IsValidSid(Pointer sid);
        int GetLengthSid(Pointer sid);
    }

    private static final HexFormat HEX = HexFormat.of();
    private static final int LIMIT = 1024 * 1024;
    private final Kernel kernel;
    private final SecurityApi security;

    public record Facts(String identity, long links, long bytes, int attributes,
            long created, long modified, long changed) { }
    public record Security(int control, String owner, String group, String dacl, String rawDescriptor) { }
    public record Preservation(int attributes, long created, long modified,
            int control, String owner, String group, String dacl) { }
    public record Snapshot(Facts facts, Security security, Map<String, Long> dataStreams) {
        public Snapshot { dataStreams = Map.copyOf(dataStreams); }
        public Preservation preservation() {
            return new Preservation(facts.attributes(), facts.created(), facts.modified(),
                security.control(), security.owner(), security.group(), security.dacl());
        }
    }

    public WindowsFileMetadata() throws IOException {
        require(Platform.isWindows() && Platform.isIntel() && Native.POINTER_SIZE == 8,
            "Windows metadata requires the audited 64-bit Intel host ABI");
        try {
            kernel = Native.load("kernel32", Kernel.class);
            security = Native.load("advapi32", SecurityApi.class);
        }
        catch (LinkageError | RuntimeException unavailable) {
            throw new IOException("Windows metadata APIs are unavailable", unavailable);
        }
    }

    public Snapshot inspect(Path path, BooleanSupplier cancelled) throws IOException {
        try (var file = open(path, false, cancelled)) {
            var result = observe(file.handle, cancelled);
            checkPath(path, result.facts(), cancelled);
            return result;
        }
    }

    public Snapshot applyToOwnedStage(Path source, Snapshot expected, Path stage, BooleanSupplier cancelled)
            throws IOException {
        check(cancelled);
        supported(expected);
        try (var input = open(source, false, cancelled); var output = open(stage, true, cancelled)) {
            var before = observe(input.handle, cancelled);
            require(before.equals(expected), "Windows metadata source changed");
            var prior = observe(output.handle, cancelled);
            supported(prior);
            require(!before.facts().identity().equals(prior.facts().identity()), "Windows metadata stage aliases source");
            require(before.facts().links() == 1 && prior.facts().links() == 1, "Windows metadata rejects hardlinks");
            var wanted = before.security();
            // Match the source's inheritance model. SetSecurityInfo upgrades
            // legacy controls; SetFileSecurityW clears the modern inherited bit.
            // Neither conversion is acceptable. Select before writing, require
            // exact readback, and never retry a failed API through the other one.
            int fields = 7 | ((wanted.control() & 0x1000) != 0 ? 0x80000000 : 0x20000000);
            if ((wanted.control() & 0x400) == 0) {
                try (var descriptor = bytes(wanted.rawDescriptor())) {
                    checkPath(stage, prior.facts(), cancelled);
                    check(cancelled);
                    success(security.SetFileSecurityW(new WString("\\\\?\\" + stage.toAbsolutePath()), fields, descriptor),
                        "SetFileSecurityW");
                }
            }
            else {
                try (var owner = bytes(wanted.owner()); var group = bytes(wanted.group()); var dacl = bytes(wanted.dacl())) {
                    check(cancelled);
                    error(security.SetSecurityInfo(output.handle, 1, fields, owner, group,
                        wanted.dacl() == null ? null : dacl, null), "SetSecurityInfo");
                }
            }
            try (var basic = new Memory(40)) {
                basic.clear(); // zero access/change time means leave those fields unchanged.
                basic.setLong(0, before.facts().created());
                basic.setLong(16, before.facts().modified());
                basic.setInt(32, before.facts().attributes());
                check(cancelled);
                success(kernel.SetFileInformationByHandle(output.handle, 0, basic, 40), "SetFileInformationByHandle");
            }
            var after = observe(output.handle, cancelled);
            supported(after);
            require(after.facts().identity().equals(prior.facts().identity()) && after.facts().links() == 1 &&
                after.facts().bytes() == prior.facts().bytes(), "Windows stage identity/size changed");
            require(after.preservation().equals(before.preservation()), "Windows metadata application readback differs");
            require(observe(input.handle, cancelled).equals(before), "Windows source metadata changed during application");
            checkPath(source, before.facts(), cancelled);
            checkPath(stage, after.facts(), cancelled);
            return after;
        }
    }

    /** Isolated lifetime oracle; not a metadata property or admission check. */
    long processHandleCount() throws IOException {
        try (var count = new Memory(4)) {
            success(kernel.GetProcessHandleCount(kernel.GetCurrentProcess(), count), "GetProcessHandleCount");
            return Integer.toUnsignedLong(count.getInt(0));
        }
    }

    private Snapshot observe(Pointer handle, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        Facts before = facts(handle);
        Security descriptor = security(handle);
        check(cancelled);
        Map<String, Long> streams = streams(handle);
        check(cancelled);
        require(before.equals(facts(handle)), "Windows opened metadata changed during inspection");
        return new Snapshot(before, descriptor, streams);
    }

    // Shared by the opened-stage rename primitive; caller retains handle ownership.
    Facts facts(Pointer handle) throws IOException {
        require(kernel.GetFileType(handle) == 1, "Windows metadata requires a disk file");
        try (var basic = info(handle, 0, 40); var standard = info(handle, 1, 24);
                var identity = info(handle, 18, 24); var tag = info(handle, 9, 8)) {
            require(standard.getByte(20) == 0 && standard.getByte(21) == 0 &&
                (tag.getInt(0) & 0x410) == 0 && tag.getInt(4) == 0,
                "Windows metadata rejects deleted, directory or reparse files");
            require(tag.getInt(0) == basic.getInt(32), "Windows file attributes changed");
            require(standard.getLong(8) >= 0, "Windows file size exceeds bound");
            return new Facts(Long.toUnsignedString(identity.getLong(0), 16) + ":" +
                HEX.formatHex(identity.getByteArray(8, 16)), Integer.toUnsignedLong(standard.getInt(16)),
                standard.getLong(8), basic.getInt(32), basic.getLong(0), basic.getLong(16), basic.getLong(24));
        }
    }

    private Security security(Pointer handle) throws IOException {
        var owner = new PointerByReference();
        var group = new PointerByReference();
        var dacl = new PointerByReference();
        var descriptor = new PointerByReference();
        error(security.GetSecurityInfo(handle, 1, 7, owner, group, dacl, null, descriptor), "GetSecurityInfo");
        Pointer base = descriptor.getValue();
        require(base != null, "Windows security descriptor is missing");
        try (var allocation = new LocalAllocation(base); var control = new Memory(2); var revision = new Memory(4)) {
            success(security.IsValidSecurityDescriptor(base), "IsValidSecurityDescriptor");
            long size = Integer.toUnsignedLong(security.GetSecurityDescriptorLength(base));
            require(size >= 20 && size <= LIMIT, "Windows security descriptor exceeds bound");
            success(security.GetSecurityDescriptorControl(base, control, revision), "GetSecurityDescriptorControl");
            int flags = Short.toUnsignedInt(control.getShort(0));
            require(revision.getInt(0) == 1 && (flags & 0x8000) != 0, "unsupported Windows descriptor format");
            String ownerBytes = sid(base, size, owner.getValue());
            String groupBytes = sid(base, size, group.getValue());
            String acl = null;
            if (dacl.getValue() != null) {
                bounds(base, size, dacl.getValue(), 8);
                int aclSize = Short.toUnsignedInt(dacl.getValue().getShort(2));
                require(aclSize >= 8, "invalid Windows ACL length");
                bounds(base, size, dacl.getValue(), aclSize);
                acl = HEX.formatHex(dacl.getValue().getByteArray(0, aclSize));
            }
            return new Security(flags, ownerBytes, groupBytes, acl, HEX.formatHex(base.getByteArray(0, (int) size)));
        }
    }

    private String sid(Pointer base, long size, Pointer value) throws IOException {
        bounds(base, size, value, 8);
        success(security.IsValidSid(value), "IsValidSid");
        long length = Integer.toUnsignedLong(security.GetLengthSid(value));
        require(length >= 8 && length <= 68, "Windows SID exceeds bound");
        bounds(base, size, value, length);
        return HEX.formatHex(value.getByteArray(0, (int) length));
    }

    private static void bounds(Pointer base, long size, Pointer value, long length) throws IOException {
        require(value != null, "missing Windows descriptor field");
        long offset = Pointer.nativeValue(value) - Pointer.nativeValue(base);
        require(offset >= 0 && length >= 0 && offset <= size - length, "Windows descriptor field exceeds allocation");
    }

    private Map<String, Long> streams(Pointer handle) throws IOException {
        var result = new TreeMap<String, Long>();
        try (var data = info(handle, 7, LIMIT)) {
            int offset = 0;
            while (true) {
                require(offset <= LIMIT - 24 && result.size() < 1024, "Windows stream list exceeds bound");
                long next = Integer.toUnsignedLong(data.getInt(offset));
                long length = Integer.toUnsignedLong(data.getInt(offset + 4));
                require(length > 0 && length % 2 == 0 && length <= LIMIT - offset - 24, "invalid Windows stream name");
                String name = StandardCharsets.UTF_16LE.newDecoder().decode(ByteBuffer.wrap(
                    data.getByteArray(offset + 24, (int) length))).toString();
                long bytes = data.getLong(offset + 8);
                require(bytes >= 0 && result.put(name, bytes) == null, "invalid or duplicate Windows stream");
                if (next == 0) break;
                require(next % 8 == 0 && next >= 24 + length && next <= LIMIT - offset - 24,
                    "invalid Windows stream chain");
                offset += (int) next;
            }
        }
        return result;
    }

    private static void supported(Snapshot snapshot) throws IOException {
        require((snapshot.facts().attributes() & ~0x20a7) == 0, "special Windows attributes require separate policy");
        require(snapshot.dataStreams().equals(Map.of("::$DATA", snapshot.facts().bytes())),
            "Windows metadata application rejects named or missing data streams");
    }

    private Memory info(Pointer handle, int kind, int bytes) throws IOException {
        var data = new Memory(bytes);
        try {
            data.clear();
            success(kernel.GetFileInformationByHandleEx(handle, kind, data, bytes), "GetFileInformationByHandleEx(" + kind + ")");
            return data;
        }
        catch (IOException | RuntimeException | LinkageError failure) { data.close(); throw failure; }
    }

    private Opened open(Path path, boolean write, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        Path absolute = path.toAbsolutePath();
        String value = absolute.toString();
        require(value.matches("[A-Za-z]:\\\\.*") && value.indexOf(':', 2) < 0,
            "Windows metadata primitive requires a local drive path without alternate streams");
        for (Path component : absolute) {
            String name = component.toString();
            require(!name.endsWith(".") && !name.endsWith(" ") && !name.equals(".."),
                "Windows metadata path requires resolved traversal without ambiguous suffixes");
        }
        require(Files.readAttributes(absolute, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS).isRegularFile(),
            "Windows metadata requires a regular non-link file");
        int access = 0x80020000 | (write ? 0xc0100 : 0); // GENERIC_READ/READ_CONTROL and stage metadata writes.
        Pointer handle = kernel.CreateFileW(new WString("\\\\?\\" + value), access, 7, null, 3, 0x02200000, null);
        if (handle == null || Pointer.nativeValue(handle) == -1L) {
            throw new IOException("Windows metadata CreateFileW failed (error=" + Native.getLastError() + ")");
        }
        var opened = new Opened(handle);
        try {
            facts(handle);
            check(cancelled);
            return opened;
        }
        catch (IOException | RuntimeException | LinkageError failure) {
            try { opened.close(); } catch (IOException closeFailure) { failure.addSuppressed(closeFailure); }
            throw failure;
        }
    }

    private void checkPath(Path path, Facts expected, BooleanSupplier cancelled) throws IOException {
        try (var selected = open(path, false, cancelled)) {
            require(facts(selected.handle).equals(expected), "Windows selected metadata path changed");
        }
    }

    private final class Opened implements AutoCloseable {
        private final Pointer handle;
        private Opened(Pointer handle) { this.handle = handle; }
        public void close() throws IOException { success(kernel.CloseHandle(handle), "CloseHandle"); }
    }

    private final class LocalAllocation implements AutoCloseable {
        private final Pointer memory;
        private LocalAllocation(Pointer memory) { this.memory = memory; }
        public void close() throws IOException { require(kernel.LocalFree(memory) == null, "Windows LocalFree failed"); }
    }

    private static Memory bytes(String hex) {
        byte[] value = hex == null ? new byte[0] : HEX.parseHex(hex);
        var result = new Memory(Math.max(1, value.length));
        result.write(0, value, 0, value.length);
        return result;
    }

    private static void success(int value, String operation) throws IOException {
        if (value == 0) throw new IOException("Windows metadata " + operation + " failed (error=" + Native.getLastError() + ")");
    }

    private static void error(int value, String operation) throws IOException {
        if (value != 0) throw new IOException("Windows metadata " + operation + " failed (error=" + Integer.toUnsignedString(value) + ")");
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("Windows metadata operation cancelled");
    }

    private static void require(boolean value, String message) throws IOException {
        if (!value) throw new IOException(message);
    }
}
