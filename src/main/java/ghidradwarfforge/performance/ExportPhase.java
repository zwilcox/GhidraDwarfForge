package ghidradwarfforge.performance;

import jdk.jfr.Category;
import jdk.jfr.Description;
import jdk.jfr.Event;
import jdk.jfr.Label;
import jdk.jfr.Name;
import jdk.jfr.StackTrace;

/** Optional JFR observations; never part of a deterministic export artifact. */
@Name("ghidradwarfforge.ExportPhase")
@Label("Forge export phase")
@Category("GhidraDwarfForge")
@Description("Elapsed phase time, including waits; not CPU time. Nested phases overlap.")
@StackTrace(false)
public final class ExportPhase extends Event implements AutoCloseable {
    @Label("Phase")
    public String phase;

    @Label("Completed normally")
    public boolean completed;

    private boolean closed;

    private ExportPhase(String phase) {
        this.phase = phase;
        begin();
    }

    public static ExportPhase start(String phase) {
        return new ExportPhase(phase);
    }

    @FunctionalInterface
    public interface Operation<T, E extends Exception> {
        T run() throws E;
    }

    public static <T, E extends Exception> T measure(String phase, Operation<T, E> operation)
            throws E {
        try (var observation = start(phase)) {
            T result = operation.run();
            observation.completed = true;
            return result;
        }
    }

    @Override
    public void close() {
        if (!closed) {
            closed = true;
            end();
            commit();
        }
    }
}
