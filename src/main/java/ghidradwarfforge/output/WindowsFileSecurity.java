package ghidradwarfforge.output;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Read-only complete Windows security descriptor observation. Requires an
 * already authorized token; never enables privileges or falls back to partial
 * metadata. Not a preservation policy, attachment Host or elevation helper.
 * Native declarations are audited in windows-security-visibility-api.json.
 */
public final class WindowsFileSecurity {
    private interface SecurityApi extends StdCallLibrary {
        int GetKernelObjectSecurity(Pointer handle, int fields, Pointer descriptor, int bytes, Pointer needed);
        int IsValidSecurityDescriptor(Pointer descriptor);
        int GetSecurityDescriptorLength(Pointer descriptor);
        int GetSecurityDescriptorControl(Pointer descriptor, Pointer control, Pointer revision);
        int GetSecurityDescriptorSacl(Pointer descriptor, Pointer present, PointerByReference acl, Pointer defaulted);
        int IsValidAcl(Pointer acl);
    }

    // Native kernel/path observations agree for both absent SACLs and actual
    // audit/label data. GetSecurityInfo adds a protection flag for absent SACLs.
    private static final int FIELDS = 0x10000; // BACKUP_SECURITY_INFORMATION
    private static final int LIMIT = 1024 * 1024;
    private final WindowsFileMetadata metadata;
    private final SecurityApi security;

    public record Descriptor(int control, boolean saclPresent, boolean saclDefaulted,
            String saclHex, String rawDescriptor) { }
    public record Snapshot(WindowsFileMetadata.Facts facts, Descriptor descriptor) { }
    @FunctionalInterface interface Hook { void opened() throws IOException; }

    public WindowsFileSecurity() throws IOException {
        metadata = new WindowsFileMetadata(); // Enforces the audited host ABI before native loading.
        try {
            security = Native.load("advapi32", SecurityApi.class);
        }
        catch (LinkageError | RuntimeException unavailable) {
            throw new IOException("Windows full-security APIs are unavailable", unavailable);
        }
    }

    public Snapshot inspect(Path path, BooleanSupplier cancelled) throws IOException {
        return inspect(path, cancelled, () -> { });
    }

    Snapshot inspect(Path path, BooleanSupplier cancelled, Hook hook) throws IOException {
        check(cancelled);
        try (var file = metadata.openForSecurity(path, cancelled)) {
            var before = metadata.facts(file.handle);
            hook.opened();
            check(cancelled);
            var descriptor = read(file.handle);
            check(cancelled);
            require(before.equals(metadata.facts(file.handle)), "Windows full-security file changed");
            metadata.checkPath(path, before, cancelled);
            require(descriptor.equals(read(file.handle)), "Windows security descriptor changed during inspection");
            require(before.equals(metadata.facts(file.handle)), "Windows full-security file changed after readback");
            metadata.checkPath(path, before, cancelled);
            check(cancelled);
            return new Snapshot(before, descriptor);
        }
    }

    private Descriptor read(Pointer handle) throws IOException {
        try (var needed = new Memory(4)) {
            needed.clear();
            int sized = security.GetKernelObjectSecurity(handle, FIELDS, null, 0, needed);
            int error = Native.getLastError();
            require(sized == 0 && error == 122,
                "Windows complete security sizing failed (error=" + Integer.toUnsignedString(error) + ")");
            long capacity = Integer.toUnsignedLong(needed.getInt(0));
            require(capacity >= 20 && capacity <= LIMIT, "Windows complete descriptor capacity exceeds bound");
            try (var allocation = new Memory(capacity)) {
                allocation.clear();
                success(security.GetKernelObjectSecurity(handle, FIELDS, allocation, (int) capacity, needed),
                    "GetKernelObjectSecurity");
                long returned = Integer.toUnsignedLong(needed.getInt(0));
                require(returned >= 20 && returned <= capacity, "Windows complete descriptor changed size");
                return decode(allocation, returned);
            }
        }
    }

    private Descriptor decode(Pointer allocation, long available) throws IOException {
        success(security.IsValidSecurityDescriptor(allocation), "IsValidSecurityDescriptor");
        long length = Integer.toUnsignedLong(security.GetSecurityDescriptorLength(allocation));
        require(length >= 20 && length <= available, "Windows complete descriptor exceeds bound");
        try (var control = new Memory(2); var revision = new Memory(4);
                var present = new Memory(4); var defaulted = new Memory(4)) {
            control.clear(); revision.clear(); present.clear(); defaulted.clear();
            success(security.GetSecurityDescriptorControl(allocation, control, revision), "GetSecurityDescriptorControl");
            int flags = Short.toUnsignedInt(control.getShort(0));
            require(revision.getInt(0) == 1 && (flags & 0x8000) != 0, "Unsupported complete descriptor format");
            var acl = new PointerByReference();
            success(security.GetSecurityDescriptorSacl(allocation, present, acl, defaulted), "GetSecurityDescriptorSacl");
            boolean exists = present.getInt(0) != 0;
            require(exists == ((flags & 0x10) != 0), "Inconsistent complete SACL presence");
            String bytes = null;
            if (acl.getValue() != null) {
                require(exists, "Absent complete SACL has a pointer");
                bounds(allocation, length, acl.getValue(), 8);
                int aclSize = Short.toUnsignedInt(acl.getValue().getShort(2));
                require(aclSize >= 8, "Invalid complete SACL size");
                bounds(allocation, length, acl.getValue(), aclSize);
                success(security.IsValidAcl(acl.getValue()), "IsValidAcl");
                bytes = HexFormat.of().formatHex(acl.getValue().getByteArray(0, aclSize));
            }
            return new Descriptor(flags, exists, exists && defaulted.getInt(0) != 0, bytes,
                HexFormat.of().formatHex(allocation.getByteArray(0, (int) length)));
        }
    }

    private static void bounds(Pointer base, long size, Pointer field, long length) throws IOException {
        long offset = Pointer.nativeValue(field) - Pointer.nativeValue(base);
        require(offset >= 0 && length >= 0 && offset <= size - length, "Complete descriptor field exceeds allocation");
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("Windows full-security inspection cancelled");
    }
    private static void success(int value, String operation) throws IOException {
        require(value != 0, operation + " failed (error=" + Native.getLastError() + ")");
    }
    private static void require(boolean value, String message) throws IOException {
        if (!value) throw new IOException(message);
    }
}
