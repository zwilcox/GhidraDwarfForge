package ghidradwarfforge.performance;

import java.io.IOException;
import java.nio.file.Files;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CancellationException;

import jdk.jfr.Recording;
import jdk.jfr.consumer.RecordingFile;

/** Exercise real JFR recording and propagation, including unsuccessful phases. */
public final class ExportPhaseSmoke {
    public static void main(String[] args) throws Exception {
        var destination = Files.createTempFile("forge-phase-smoke-", ".jfr");
        try (var recording = new Recording()) {
            recording.enable("ghidradwarfforge.ExportPhase").withThreshold(Duration.ZERO);
            recording.start();
            Object expected = new Object();
            Object actual = ExportPhase.measure("outer", () ->
                ExportPhase.measure("inner", () -> expected));
            require(actual == expected, "result identity changed");
            var failure = new IOException("expected checked failure");
            try {
                ExportPhase.measure("failure", () -> { throw failure; });
                throw new AssertionError("exception swallowed");
            }
            catch (IOException observed) {
                require(observed == failure, "exception identity changed");
            }
            var cancelled = new CancellationException("expected cancellation");
            try {
                ExportPhase.measure("cancelled", () -> { throw cancelled; });
                throw new AssertionError("cancellation swallowed");
            }
            catch (CancellationException observed) {
                require(observed == cancelled, "cancellation identity changed");
            }
            var manual = ExportPhase.start("manual");
            manual.completed = true;
            manual.close();
            manual.close();
            recording.stop();
            recording.dump(destination);
            var events = RecordingFile.readAllEvents(destination).stream()
                .filter(event -> event.getEventType().getName().equals("ghidradwarfforge.ExportPhase"))
                .toList();
            require(events.size() == 5, "missing or duplicate phase events");
            require(events.stream().map(event -> event.getString("phase")).sorted().toList()
                .equals(List.of("cancelled", "failure", "inner", "manual", "outer")), "phase names");
            for (var event : events) {
                String phase = event.getString("phase");
                require(event.getBoolean("completed") ==
                    !(phase.equals("failure") || phase.equals("cancelled")), "completion: " + phase);
                require(!event.getDuration().isNegative(), "negative duration");
                require(event.getStackTrace() == null, "unexpected stack collection");
            }
            var outer = events.stream().filter(event -> event.getString("phase").equals("outer")).findFirst().orElseThrow();
            var inner = events.stream().filter(event -> event.getString("phase").equals("inner")).findFirst().orElseThrow();
            require(!inner.getStartTime().isBefore(outer.getStartTime()) &&
                !inner.getEndTime().isAfter(outer.getEndTime()), "nested timing boundaries");
        }
        finally {
            Files.deleteIfExists(destination);
        }
        System.out.println("export-phase-smoke=PASS");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
