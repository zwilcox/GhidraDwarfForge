package ghidradwarfforge.nativeapi;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import com.google.gson.JsonParser;
import ghidradwarfforge.annotations.SyntheticConstant;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** Isolated producer process: no Ghidra API or native decompiler on its classpath. */
public final class EquateConstantsSmoke {
    public static void main(String[] args) throws Exception {
        var observations = JsonParser.parseString(Files.readString(Path.of(args[4]))).getAsJsonObject();
        var constants = new ArrayList<SyntheticConstant>();
        for (var entry : observations.getAsJsonArray("constants")) {
            for (var row : entry.getAsJsonObject().getAsJsonArray("constants")) {
                var item = row.getAsJsonObject();
                var value = item.getAsJsonObject("value");
                constants.add(new SyntheticConstant(item.get("name").getAsString(), value.get("bits").getAsInt(),
                    value.get("signed").getAsBoolean(), value.get("value").getAsLong()));
            }
        }
        // Independently test widths absent from the current saved-program fixture.
        for (int bits : List.of(1, 3, 7, 9, 24, 31, 63, 64)) {
            constants.add(new SyntheticConstant("width_signed_" + bits, bits, true,
                bits == 64 ? Long.MIN_VALUE : -(1L << (bits - 1))));
            constants.add(new SyntheticConstant("width_unsigned_" + bits, bits, false, -1L >>> (64 - bits)));
        }
        constants.add(new SyntheticConstant("forge_equate_type_u64", 64, false, 99));
        var functions = List.of(new FunctionSymbol("annotation_probe", Long.parseLong(args[5]), Long.parseLong(args[6])));
        var result = new MinimalDwarfSidecarExporter().export(Path.of(args[0]), Path.of(args[1]),
            Path.of(args[2]), Path.of(args[3]), functions, null, null, "equates.c", () -> false,
            List.of(), List.of(), List.of(), List.of(), constants, System.err::println);
        if (result.functionCount() != 1) throw new AssertionError("constant changed function count");
        if (!result.emission().types().nodes().isEmpty() ||
                result.emission().functions().stream().anyMatch(function -> !function.variables().isEmpty())) {
            throw new AssertionError("synthetic constants counted as recovered types/variables");
        }
        byte[] published = Files.readAllBytes(Path.of(args[1]));
        for (var bad : List.of(List.of(constants.getFirst(), constants.getFirst()),
                List.of(new SyntheticConstant("annotation_probe", 8, false, 1)))) {
            try {
                new MinimalDwarfSidecarExporter().export(Path.of(args[0]), Path.of(args[1]),
                    Path.of(args[2]), Path.of(args[3]), functions, null, null, "equates.c", () -> false,
                    List.of(), List.of(), List.of(), List.of(), bad, ignored -> { });
                throw new AssertionError("conflicting constant accepted");
            }
            catch (IllegalArgumentException expected) { }
        }
        try {
            new MinimalDwarfSidecarExporter().export(Path.of(args[0]), Path.of(args[1]),
                Path.of(args[2]), Path.of(args[3]), functions, null, null, "equates.c", () -> true,
                List.of(), List.of(), List.of(), List.of(), constants, ignored -> { });
            throw new AssertionError("cancelled export accepted");
        }
        catch (java.util.concurrent.CancellationException expected) { }
        if (!java.util.Arrays.equals(published, Files.readAllBytes(Path.of(args[1])))) {
            throw new AssertionError("failed export changed published sidecar");
        }
        for (long value : List.of(-129L, 128L, Long.MIN_VALUE, Long.MAX_VALUE)) {
            try {
                new SyntheticConstant("invalid", 8, true, value);
                throw new AssertionError("out-of-range signed value accepted");
            }
            catch (IllegalArgumentException expected) { }
        }
        for (long value : List.of(-1L, 256L, Long.MAX_VALUE)) {
            try {
                new SyntheticConstant("invalid", 8, false, value);
                throw new AssertionError("out-of-range unsigned value accepted");
            }
            catch (IllegalArgumentException expected) { }
        }
        System.out.println("equate-constants=" + constants.size());
    }
}
