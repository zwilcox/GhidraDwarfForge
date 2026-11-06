// Verify enum, operand and high-pcode evidence without changing the saved program.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.util.exception.CancelledException;
import ghidradwarfforge.GhidraAnnotationInventory;
import ghidradwarfforge.GhidraAnnotationInventory.EquateValue;
import ghidradwarfforge.GhidraAnnotationInventory.EquateReference;
import ghidradwarfforge.GhidraEquateEvidence;
import ghidradwarfforge.GhidraEquateEvidence.Status;
import ghidradwarfforge.GhidraFunctionSymbols;
import ghidradwarfforge.GhidraSyntheticSource;
import com.google.gson.GsonBuilder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class VerifyEquateEvidence extends GhidraScript {
    private static final class Probe extends TaskMonitorAdapter {
        private final int stop;
        private int checks;
        Probe(int stop) { this.stop = stop; }
        @Override public void checkCancelled() throws CancelledException {
            if (++checks == stop) throw new CancelledException();
        }
    }

    private GhidraAnnotationInventory.Snapshot only(EquateValue value) {
        return new GhidraAnnotationInventory.Snapshot(List.of(), List.of(value), 0, 1, value.storedName().length());
    }

    private void enumStatus(EquateValue value, Status expected) throws Exception {
        var found = GhidraEquateEvidence.interpret(currentProgram, only(value), Map.of(), monitor).getFirst();
        if (found.enumeration().status() != expected) throw new AssertionError(value.storedName() + ": " + found.enumeration());
    }

    @Override
    public void run() throws Exception {
        var inventory = GhidraAnnotationInventory.read(currentProgram,
            new GhidraAnnotationInventory.Limits(10000, 1000000), monitor);
        var collector = new GhidraEquateEvidence.DynamicCollector(currentProgram, inventory, monitor);
        var functions = GhidraFunctionSymbols.extract(currentProgram, monitor, ignored -> { }, 0)
            .stream().filter(function -> function.name().equals("annotation_probe")).toList();
        GhidraSyntheticSource.decompile(currentProgram, functions, 0, monitor,
            (decompiler, function, timeout, taskMonitor) -> {
                var result = decompiler.decompileFunction(function, timeout, taskMonitor);
                if (!result.decompileCompleted()) throw new AssertionError(result.getErrorMessage());
                collector.accept(result.getHighFunction(), taskMonitor);
                return result;
            });
        var dynamic = collector.snapshot(monitor);
        try {
            GhidraSyntheticSource.decompile(currentProgram, functions, 0, monitor,
                (decompiler, function, timeout, taskMonitor) -> { throw new CancelledException(); });
            throw new AssertionError("collector cancellation became an ordinary failed function");
        }
        catch (CancelledException expected) { }
        var counting = new Probe(-1);
        var evidence = GhidraEquateEvidence.interpret(currentProgram, inventory, dynamic, counting);
        if (evidence.size() != 14) throw new AssertionError("fixture equates missing");
        var rows = new ArrayList<TreeMap<String, Object>>();
        int enumCount = 0;
        int scalarCount = 0;
        int dynamicCount = 0;
        for (var item : evidence) {
            var row = new TreeMap<String, Object>();
            row.put("storedName", item.stored().storedName());
            row.put("storedValue", Long.toString(item.stored().storedValue()));
            row.put("enumeration", item.enumeration());
            if (item.enumeration().status() == Status.RESOLVED) {
                enumCount++;
                if (item.enumeration().value().bits() != 8 ||
                        item.enumeration().value().signed() != (item.stored().storedValue() < 0)) {
                    throw new AssertionError("enum storage semantics lost");
                }
            }
            var references = new ArrayList<TreeMap<String, Object>>();
            for (var ref : item.references()) {
                var entry = new TreeMap<String, Object>();
                entry.put("space", ref.reference().address().getAddressSpace().getName());
                entry.put("offset", Long.toUnsignedString(ref.reference().address().getOffset(), 16));
                entry.put("operand", ref.reference().operand());
                entry.put("dynamicHash", Long.toUnsignedString(ref.reference().dynamicHash()));
                entry.put("scalar", ref.scalar());
                entry.put("dynamic", ref.dynamic());
                references.add(entry);
                if (ref.scalar().status() == Status.RESOLVED) {
                    scalarCount++;
                    if (ref.scalar().value().value() != item.stored().storedValue()) throw new AssertionError("scalar value changed");
                }
                if (ref.dynamic().status() == Status.RESOLVED) {
                    dynamicCount++;
                    var value = ref.dynamic().value();
                    if (value.bits() != 32 || value.signed() || value.value() != 53 || ref.reference().operand() != -1) {
                        throw new AssertionError("dynamic-only constant width/bits ownership changed");
                    }
                }
            }
            row.put("references", references);
            rows.add(row);
        }
        if (enumCount != 3 || scalarCount != 2 || dynamicCount != 1) {
            throw new AssertionError("evidence counts " + enumCount + "/" + scalarCount + "/" + dynamicCount);
        }
        var enumeration = evidence.stream().filter(e -> e.enumeration().status() == Status.RESOLVED &&
            e.stored().storedValue() == 19).findFirst().orElseThrow().stored();
        String prefix = enumeration.storedName().substring(0, enumeration.storedName().lastIndexOf(':') + 1);
        enumStatus(new EquateValue("dtID", 16, List.of()), Status.MALFORMED_ENUM_NAME);
        enumStatus(new EquateValue("dtID:999999999999999999999999:16", 16, List.of()), Status.MALFORMED_ENUM_NAME);
        enumStatus(new EquateValue(enumeration.storedName(), 20, List.of()), Status.ENUM_VALUE_MISMATCH);
        enumStatus(new EquateValue(prefix + "20", 20, List.of()), Status.MISSING_ENUM_MEMBER);
        enumStatus(new EquateValue(prefix + "256", 256, List.of()), Status.VALUE_OUT_OF_RANGE);
        if (currentProgram.getDataTypeManager().findDataTypeForID(new ghidra.util.UniversalID(1)) != null) {
            throw new AssertionError("missing-type fixture ID occupied");
        }
        enumStatus(new EquateValue("dtID:1:16", 16, List.of()), Status.MISSING_ENUM);
        var structure = currentProgram.getDataTypeManager().getDataType("/ANNOTATION_TYPE");
        if (!(structure instanceof ghidra.program.model.data.Structure)) throw new AssertionError("saved structure missing");
        enumStatus(new EquateValue("dtID:" + structure.getUniversalID().getValue() + ":16", 16, List.of()), Status.WRONG_ENUM_TYPE);
        var dynamicEquate = inventory.equates().stream().filter(e -> e.storedName().equals("ANNOTATION_DYNAMIC_ONLY")).findFirst().orElseThrow();
        var mismatch = new EquateValue(dynamicEquate.storedName(), 54, dynamicEquate.references());
        if (GhidraEquateEvidence.interpret(currentProgram, only(mismatch), dynamic, monitor).getFirst()
                .references().getFirst().dynamic().status() != Status.DYNAMIC_VALUE_MISMATCH) {
            throw new AssertionError("mismatched dynamic value accepted");
        }
        var truncated = new EquateValue(dynamicEquate.storedName(), 53 + (1L << 32), dynamicEquate.references());
        if (GhidraEquateEvidence.interpret(currentProgram, only(truncated), dynamic, monitor).getFirst()
                .references().getFirst().dynamic().status() != Status.DYNAMIC_VALUE_MISMATCH) {
            throw new AssertionError("stored value truncated to match dynamic bits");
        }
        if (GhidraEquateEvidence.interpret(currentProgram, only(dynamicEquate), Map.of(), monitor).getFirst()
                .references().getFirst().dynamic().status() != Status.NO_DECOMPILER_EVIDENCE) {
            throw new AssertionError("unresolved dynamic value fabricated");
        }
        var originalReference = enumeration.references().getFirst();
        var badReference = new EquateReference(originalReference.address(), 999, 0);
        if (GhidraEquateEvidence.interpret(currentProgram,
                only(new EquateValue("bad-operand", 19, List.of(badReference))), Map.of(), monitor).getFirst()
                .references().getFirst().scalar().status() != Status.INVALID_OPERAND) {
            throw new AssertionError("invalid operand accepted");
        }
        for (int point = 1; point <= counting.checks; point++) {
            try {
                GhidraEquateEvidence.interpret(currentProgram, inventory, dynamic, new Probe(point));
                throw new AssertionError("ignored cancellation " + point);
            }
            catch (CancelledException expected) { }
        }
        var result = new TreeMap<String, Object>();
        result.put("origin", GhidraEquateEvidence.class.getProtectionDomain().getCodeSource().getLocation().toString());
        result.put("equates", rows);
        result.put("enumCount", enumCount);
        result.put("scalarCount", scalarCount);
        result.put("dynamicCount", dynamicCount);
        result.put("negativeControls", 11);
        result.put("cancellationPoints", counting.checks);
        Files.writeString(Path.of(getScriptArgs()[0]), new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(result) + "\n");
        println("equate-evidence=PASS");
    }
}
