package ghidradwarfforge.output;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicBoolean;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

/** Parent/child decoding must share budgets and cancellation without owning separate streams. */
public final class ReportValueReaderSmoke {
    private static final String DOCUMENT = "[0,[1,2],3]";

    public static void main(String[] args) throws Exception {
        require(parse(6, 3, false) == 6, "exact document-wide value limit");
        reject(() -> parse(5, 3, false), "child cannot reset the shared value count");
        reject(() -> parse(6, 2, false), "parent array limit still applies after child completes");
        try {
            parse(6, 3, true);
            throw new AssertionError("child ignored cancellation");
        }
        catch (CancellationException expected) { }
        require(parse(6, 3, false) == 6, "new document has its own budget after failures");
        System.out.println("report-value-reader=PASS shared-budget/array/cancellation/owned-close");
    }

    private static int parse(int values, int arrayItems, boolean cancelChild) throws IOException {
        var closed = new AtomicBoolean();
        var cancelled = new AtomicBoolean();
        var input = new ByteArrayInputStream(DOCUMENT.getBytes(StandardCharsets.UTF_8)) {
            @Override public void close() throws IOException { closed.set(true); super.close(); }
        };
        var limits = new ReportJsonReader.Limits(1024, 32, 3, values, arrayItems);
        try (var json = new JsonReader(new ReportJsonReader(input, cancelled::get, limits))) {
            json.setLenient(false);
            int result = new Parent(json, cancelled, limits, cancelChild).read();
            require(json.peek() == JsonToken.END_DOCUMENT, "complete document consumed");
            return result;
        }
        finally {
            require(closed.get(), "owned input closes on success/failure/cancellation");
        }
    }

    private static final class Parent extends ReportValueReader {
        private final AtomicBoolean stop;
        private final boolean cancelChild;

        Parent(JsonReader json, AtomicBoolean stop, ReportJsonReader.Limits limits, boolean cancelChild) {
            super(json, stop::get, limits);
            this.stop = stop;
            this.cancelChild = cancelChild;
        }

        int read() throws IOException {
            int[] total = {0};
            array(() -> {
                if (json.peek() == JsonToken.BEGIN_ARRAY) {
                    if (cancelChild) stop.set(true);
                    total[0] += new Child(this).read();
                }
                else total[0] += integer();
            });
            return total[0];
        }
    }

    private static final class Child extends ReportValueReader {
        Child(ReportValueReader parent) { super(parent); }
        int read() throws IOException {
            int[] total = {0};
            array(() -> total[0] += integer());
            return total[0];
        }
    }

    private interface Attempt { void run() throws IOException; }
    private static void reject(Attempt attempt, String message) {
        try { attempt.run(); }
        catch (IOException expected) { return; }
        throw new AssertionError(message);
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
