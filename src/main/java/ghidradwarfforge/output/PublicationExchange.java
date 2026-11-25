package ghidradwarfforge.output;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.win32.StdCallLibrary;
import java.io.IOException;
import java.nio.file.Path;

/** Swap two existing leaf names without exposing an empty public name or discarding its occupant. */
interface PublicationExchange {
    void exchange(Path privateName, Path publicName) throws IOException;

    static PublicationExchange open() throws IOException {
        String host = System.getProperty("os.name");
        if (host.equals("Linux")) return new LinuxAtomicRename()::exchange;
        if (host.startsWith("Windows")) {
            try { return new WindowsExchange(); }
            catch (RuntimeException | LinkageError unavailable) {
                throw new IOException("Windows transactional rename is unavailable", unavailable);
            }
        }
        throw new IOException("No atomic file exchange is available on " + host);
    }

    final class WindowsExchange implements PublicationExchange {
        private interface Transactions extends StdCallLibrary {
            Pointer CreateTransaction(Pointer security, Pointer id, int options, int isolation,
                int isolationFlags, int timeout, WString description);
            int CommitTransaction(Pointer transaction);
        }

        private interface Kernel extends StdCallLibrary {
            int MoveFileTransactedW(WString source, WString target, Pointer callback, Pointer data,
                int flags, Pointer transaction);
            int CloseHandle(Pointer handle);
        }

        private final Transactions transactions = Native.load("KtmW32", Transactions.class);
        private final Kernel kernel = Native.load("kernel32", Kernel.class);

        @Override
        public void exchange(Path privateName, Path publicName) throws IOException {
            // A single namespace transaction also exchanges a symlink itself without opening
            // its referent. The third name lives in the writer's private directory.
            WString owned = wide(privateName);
            WString target = wide(publicName);
            WString holding = wide(privateName.resolveSibling(privateName.getFileName() + ".exchange"));
            Pointer transaction = transactions.CreateTransaction(null, null, 0, 0, 0, 0, null);
            if (transaction == null || Pointer.nativeValue(transaction) == -1) throw failure("CreateTransaction");
            try {
                move(target, holding, transaction);
                move(owned, target, transaction);
                move(holding, owned, transaction);
                if (transactions.CommitTransaction(transaction) == 0) throw failure("CommitTransaction");
            }
            finally {
                // Closing the last handle rolls back an uncommitted transaction, including on process exit.
                kernel.CloseHandle(transaction);
            }
        }

        private static WString wide(Path file) {
            String path = file.toAbsolutePath().toString();
            if (path.startsWith("\\\\?\\")) return new WString(path);
            return new WString(path.startsWith("\\\\") ? "\\\\?\\UNC\\" + path.substring(2) : "\\\\?\\" + path);
        }

        private void move(WString source, WString target, Pointer transaction) throws IOException {
            if (kernel.MoveFileTransactedW(source, target, null, null, 0, transaction) == 0) {
                throw failure("MoveFileTransactedW");
            }
        }

        private static IOException failure(String operation) {
            return new IOException(operation + " failed during atomic output exchange (Win32 error " +
                Native.getLastError() + ")");
        }
    }
}
