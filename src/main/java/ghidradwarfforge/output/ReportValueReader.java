package ghidradwarfforge.output;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

import java.io.IOException;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.function.BooleanSupplier;

/** Shared strict streaming primitives; nested schema decoders consume one document budget. */
abstract class ReportValueReader {
    protected final JsonReader json;
    protected final BooleanSupplier cancelled;
    protected final ReportJsonReader.Limits limits;
    private final Budget budget;
    protected enum ValuePopulation { LEGACY, COVERAGE }
    private final ValuePopulation population;

    private static final class Budget {
        private int values;
        private int legacy;
        private int coverage;
    }

    ReportValueReader(JsonReader json, BooleanSupplier cancelled, ReportJsonReader.Limits limits) {
        this(json, cancelled, limits, ValuePopulation.LEGACY);
    }

    ReportValueReader(JsonReader json, BooleanSupplier cancelled, ReportJsonReader.Limits limits, ValuePopulation population) {
        this.json = Objects.requireNonNull(json);
        this.cancelled = Objects.requireNonNull(cancelled);
        this.limits = Objects.requireNonNull(limits);
        budget = new Budget();
        this.population = Objects.requireNonNull(population);
    }

    /** Child decoders never reset input-wide value, byte, string or depth limits. */
    ReportValueReader(ReportValueReader parent) {
        this(parent, parent.population);
    }

    /** Scoped populations share the original counters; entering a child never replenishes any budget. */
    ReportValueReader(ReportValueReader parent, ValuePopulation population) {
        json = parent.json;
        cancelled = parent.cancelled;
        limits = parent.limits;
        budget = parent.budget;
        this.population = Objects.requireNonNull(population);
    }

    protected IOException missingFields(String description, Set<String> missing) {
        return invalid("missing field in " + description);
    }

    protected long address() throws IOException {
        String value = text(true);
        if (!value.matches("0x(?:0|[1-9a-f][0-9a-f]{0,15})")) {
            throw invalid("invalid report address spelling");
        }
        return Long.parseUnsignedLong(value.substring(2), 16);
    }

    protected void textObject(String description, Set<String> fields) throws IOException {
        object(description, fields, ignored -> text(true));
    }

    protected void object(String description, Set<String> fields, FieldReader reader) throws IOException {
        object(description, fields, Set.of(), reader);
    }

    /** Optional fields still participate in unknown/decoded-duplicate checks. */
    protected Set<String> object(String description, Set<String> fields, Set<String> optional,
            FieldReader reader) throws IOException {
        value(JsonToken.BEGIN_OBJECT);
        json.beginObject();
        Set<String> seen = new HashSet<>();
        while (json.hasNext()) {
            ReportJsonReader.checkCancelled(cancelled);
            String name = json.nextName();
            if (!fields.contains(name) && !optional.contains(name)) {
                throw invalid("unknown field in " + description);
            }
            if (!seen.add(name)) {
                throw invalid("duplicate decoded field in " + description);
            }
            reader.read(name);
        }
        json.endObject();
        if (!seen.containsAll(fields)) {
            Set<String> missing = new HashSet<>(fields);
            missing.removeAll(seen);
            throw missingFields(description, missing);
        }
        return Set.copyOf(seen);
    }

    protected int array(ValueReader reader) throws IOException {
        value(JsonToken.BEGIN_ARRAY);
        json.beginArray();
        int count = 0;
        while (json.hasNext()) {
            if (count == limits.arrayItems()) {
                throw invalid("array exceeds safety limit " + limits.arrayItems());
            }
            count++;
            reader.read();
        }
        json.endArray();
        return count;
    }

    protected <T> T nullable(NullableReader<T> reader) throws IOException {
        if (json.peek() == JsonToken.NULL) {
            value(JsonToken.NULL);
            json.nextNull();
            return null;
        }
        return reader.read();
    }

    protected String text(boolean nonblank) throws IOException {
        value(JsonToken.STRING);
        String text = json.nextString();
        if (nonblank && text.isBlank()) {
            throw invalid("required report text is blank");
        }
        return text;
    }

    protected int integer() throws IOException {
        value(JsonToken.NUMBER);
        String spelling = json.nextString();
        if (!spelling.matches("0|[1-9][0-9]{0,9}")) {
            throw invalid("expected canonical nonnegative report integer");
        }
        try {
            return Integer.parseInt(spelling);
        }
        catch (NumberFormatException overflow) {
            throw new IOException("report integer exceeds signed 32-bit range", overflow);
        }
    }

    protected void value(JsonToken expected) throws IOException {
        ReportJsonReader.checkCancelled(cancelled);
        if (budget.values == limits.totalValues()) {
            throw invalid("value count exceeds safety limit " + limits.totalValues());
        }
        budget.values++;
        if (population == ValuePopulation.COVERAGE) {
            if (budget.coverage == limits.coverageValues()) {
                throw invalid("coverage value count exceeds safety limit " + limits.coverageValues());
            }
            budget.coverage++;
        }
        else {
            if (budget.legacy == limits.values()) {
                throw invalid("legacy value count exceeds safety limit " + limits.values());
            }
            budget.legacy++;
        }
        if (json.peek() != expected) {
            throw invalid("expected " + expected + " report value");
        }
    }

    protected static IOException invalid(String detail) {
        return new IOException("invalid export report: " + detail);
    }

    @FunctionalInterface
    protected interface FieldReader {
        void read(String name) throws IOException;
    }

    @FunctionalInterface
    protected interface ValueReader {
        void read() throws IOException;
    }

    @FunctionalInterface
    protected interface NullableReader<T> {
        T read() throws IOException;
    }
}
