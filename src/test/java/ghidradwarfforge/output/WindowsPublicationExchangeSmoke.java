package ghidradwarfforge.output;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.WString;
import java.nio.file.FileSystemException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Check native call order and rollback-by-close when a Windows namespace transaction fails. */
final class WindowsPublicationExchangeSmoke {
    private static final Pointer HANDLE = Pointer.createConstant(41);
    private record Move(String source, String target) { }

    static void exercise(Path root) throws Exception {
        // Only path conversion is real here. Use a drive path even when the Windows test temp is a UNC share.
        if (java.io.File.separatorChar == '\\') root = Path.of("C:\\Forge test");
        verify(root, null, 0, false);
        verify(root, Pointer.createConstant(-1L), 0, false);
        for (int failedMove = 1; failedMove <= 3; failedMove++) verify(root, HANDLE, failedMove, false);
        verify(root, HANDLE, 0, true);
        verify(root, HANDLE, 0, false);
    }

    private static void verify(Path root, Pointer opened, int failedMove, boolean failCommit) throws Exception {
        Path stage = root.resolve("symbols.stage").toAbsolutePath();
        Path target = root.resolve("image.dbg").toAbsolutePath();
        Path holding = stage.resolveSibling("symbols.stage.exchange");
        var nativeCalls = new Calls(opened, failedMove, failCommit);
        var exchange = new PublicationExchange.WindowsExchange(nativeCalls, nativeCalls);
        boolean created = HANDLE.equals(opened);
        boolean shouldCommit = created && failedMove == 0;
        try {
            exchange.exchange(stage, target);
            require(shouldCommit && !failCommit, "native failure reported as a successful exchange");
        }
        catch (FileSystemException failure) {
            String operation = !created ? "CreateTransaction" : failedMove != 0 ? "MoveFileTransactedW" : "CommitTransaction";
            Path source = switch (failedMove) { case 2 -> stage; case 3 -> holding; default -> target; };
            Path destination = switch (failedMove) { case 1 -> holding; case 2 -> target; default -> stage; };
            require(!shouldCommit || failCommit, "unexpected failure on successful transaction");
            require(failure.getFile().equals(source.toString()) && failure.getOtherFile().equals(destination.toString()) &&
                failure.getReason().contains(operation) && failure.getReason().contains("Win32 error 32"),
                "wrong failed operation or pathname: " + failure);
        }
        String prefix = "\\\\?\\";
        var expected = List.of(new Move(prefix + target, prefix + holding), new Move(prefix + stage, prefix + target),
            new Move(prefix + holding, prefix + stage));
        int moveCount = !created ? 0 : failedMove == 0 ? 3 : failedMove;
        require(nativeCalls.moves.equals(expected.subList(0, moveCount)), "incorrect native move sequence");
        require(nativeCalls.opens == 1 && nativeCalls.commits == (shouldCommit ? 1 : 0) &&
            nativeCalls.closes == (created ? 1 : 0), "invalid transaction lifetime");
    }

    private static final class Calls implements PublicationExchange.WindowsExchange.Transactions,
            PublicationExchange.WindowsExchange.Kernel {
        final List<Move> moves = new ArrayList<>();
        final Pointer opened;
        final int failedMove;
        final boolean failCommit;
        int opens, commits, closes;

        Calls(Pointer opened, int failedMove, boolean failCommit) {
            this.opened = opened;
            this.failedMove = failedMove;
            this.failCommit = failCommit;
        }

        @Override
        public Pointer CreateTransaction(Pointer security, Pointer id, int options, int isolation,
                int flags, int timeout, WString description) {
            require(security == null && id == null && options == 0 && isolation == 0 && flags == 0 &&
                timeout == 0 && description == null, "unexpected CreateTransaction arguments");
            opens++;
            Native.setLastError(32);
            return opened;
        }

        @Override
        public int MoveFileTransactedW(WString from, WString to, Pointer callback, Pointer data,
                int flags, Pointer transaction) {
            require(HANDLE.equals(transaction) && closes == 0 && commits == 0 && callback == null &&
                data == null && flags == 0, "move escaped the open transaction");
            moves.add(new Move(from.toString(), to.toString()));
            Native.setLastError(32);
            return moves.size() == failedMove ? 0 : 1;
        }

        @Override
        public int CommitTransaction(Pointer transaction) {
            require(HANDLE.equals(transaction) && closes == 0 && moves.size() == 3, "premature commit");
            commits++;
            Native.setLastError(32);
            return failCommit ? 0 : 1;
        }

        @Override
        public int CloseHandle(Pointer transaction) {
            require(HANDLE.equals(transaction), "closed an invalid transaction handle");
            closes++;
            return 1;
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
