// Read a saved annotation fixture through the packaged production extractor.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.GhidraAnnotationInventory;
import ghidradwarfforge.GhidraAnnotationInventory.Limits;
import com.google.gson.GsonBuilder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;

public class VerifyAnnotationInventory extends GhidraScript {
    private static final class ProbeMonitor extends TaskMonitorAdapter {
        private final int cancelAt;
        private int checks;

        private ProbeMonitor(int cancelAt) {
            super(true);
            this.cancelAt = cancelAt;
        }

        @Override
        public boolean isCancelled() {
            return ++checks == cancelAt || super.isCancelled();
        }

        @Override
        public void checkCancelled() throws CancelledException {
            if (++checks == cancelAt) throw new CancelledException();
            super.checkCancelled();
        }
    }

    @Override
    public void run() throws Exception {
        var counting = new ProbeMonitor(-1);
        var snapshot = GhidraAnnotationInventory.read(currentProgram, new Limits(10000, 1000000), counting);
        int cancellationPoints = counting.checks;
        var exact = new Limits(snapshot.records(), snapshot.textUnits());
        if (!snapshot.equals(GhidraAnnotationInventory.read(currentProgram, exact, monitor))) {
            throw new AssertionError("exact-limit read differs");
        }
        for (var limit : List.of(new Limits(snapshot.records() - 1, snapshot.textUnits()),
                new Limits(snapshot.records(), snapshot.textUnits() - 1))) {
            try {
                GhidraAnnotationInventory.read(currentProgram, limit, monitor);
                throw new AssertionError("annotation inventory silently exceeded budget");
            }
            catch (IllegalArgumentException expected) {
                if (!expected.getMessage().contains("nothing was truncated")) throw expected;
            }
        }
        var listing = currentProgram.getListing();
        var wrongCount = (ghidra.program.model.listing.Listing) java.lang.reflect.Proxy.newProxyInstance(
            listing.getClass().getClassLoader(), new Class<?>[] { ghidra.program.model.listing.Listing.class },
            (proxy, method, arguments) -> method.getName().equals("getCommentAddressCount")
                ? listing.getCommentAddressCount() + 1 : method.invoke(listing, arguments));
        var changingProgram = (ghidra.program.model.listing.Program) java.lang.reflect.Proxy.newProxyInstance(
            currentProgram.getClass().getClassLoader(), new Class<?>[] { ghidra.program.model.listing.Program.class },
            (proxy, method, arguments) -> method.getName().equals("getListing")
                ? wrongCount : method.invoke(currentProgram, arguments));
        try {
            GhidraAnnotationInventory.read(changingProgram, new Limits(10000, 1000000), monitor);
            throw new AssertionError("incomplete comment inventory was accepted");
        }
        catch (IllegalStateException expected) {
            if (!expected.getMessage().startsWith("Incomplete or changing")) throw expected;
        }
        for (int point = 1; point <= cancellationPoints; point++) {
            monitor.checkCancelled();
            try {
                GhidraAnnotationInventory.read(currentProgram, exact, new ProbeMonitor(point));
                throw new AssertionError("ignored annotation cancellation checkpoint " + point);
            }
            catch (CancelledException expected) { }
        }
        if (!snapshot.equals(GhidraAnnotationInventory.read(currentProgram, exact, monitor))) {
            throw new AssertionError("failed reads changed annotation inventory");
        }
        var comments = new ArrayList<TreeMap<String, Object>>();
        for (var comment : snapshot.comments()) {
            if (!comment.text().equals(currentProgram.getListing().getComment(comment.category(), comment.address()))) {
                throw new AssertionError("comment differs from direct listing getter");
            }
            var row = new TreeMap<String, Object>();
            row.put("space", comment.address().getAddressSpace().getName());
            row.put("offset", Long.toUnsignedString(comment.address().getOffset(), 16));
            row.put("category", comment.category().name());
            row.put("text", comment.text());
            comments.add(row);
        }
        var equates = new ArrayList<TreeMap<String, Object>>();
        for (var equate : snapshot.equates()) {
            var row = new TreeMap<String, Object>();
            row.put("storedName", equate.storedName());
            row.put("storedValue", Long.toString(equate.storedValue()));
            row.put("storedBits", Long.toUnsignedString(equate.storedValue()));
            var references = new ArrayList<TreeMap<String, Object>>();
            for (var reference : equate.references()) {
                var ref = new TreeMap<String, Object>();
                ref.put("space", reference.address().getAddressSpace().getName());
                ref.put("offset", Long.toUnsignedString(reference.address().getOffset(), 16));
                ref.put("operand", reference.operand());
                ref.put("dynamicHash", Long.toUnsignedString(reference.dynamicHash()));
                references.add(ref);
            }
            row.put("references", references);
            equates.add(row);
        }
        var result = new TreeMap<String, Object>();
        result.put("comments", comments);
        result.put("equates", equates);
        result.put("commentAddresses", snapshot.commentAddresses());
        result.put("records", snapshot.records());
        result.put("textUnits", snapshot.textUnits());
        result.put("cancellationPoints", cancellationPoints);
        result.put("origin", GhidraAnnotationInventory.class.getProtectionDomain().getCodeSource().getLocation().toString());
        Files.writeString(Path.of(getScriptArgs()[0]), new GsonBuilder().setPrettyPrinting().create().toJson(result) + "\n");
        println("annotation-inventory=PASS comments=" + comments.size() + " equates=" + equates.size());
    }
}
