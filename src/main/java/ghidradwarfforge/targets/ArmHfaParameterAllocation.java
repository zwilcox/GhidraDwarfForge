package ghidradwarfforge.targets;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.GhidraParameterAllocation;
import ghidradwarfforge.elf.Arm32CallAbi;
import ghidradwarfforge.elf.ElfImage;

/** Expand computed VFP HFA joins into their logical floating members without changing allocation. */
public final class ArmHfaParameterAllocation {
    private ArmHfaParameterAllocation() { }

    public static GhidraParameterAllocation forProgram(Program program, ElfImage image,
            TaskMonitor monitor, Consumer<String> diagnostic) throws CancelledException, IOException {
        monitor.checkCancelled();
        String language = program.getLanguageID().toString();
        boolean big = image.byteOrder() == java.nio.ByteOrder.BIG_ENDIAN;
        if (image.machine() != 40 || image.is64Bit() ||
                !language.equals(big ? "ARM:LEBE:32:v8LEInstruction" : "ARM:LE:32:v8") ||
                !program.getCompilerSpec().getCompilerSpecID().toString().equals("default") ||
                !Arm32CallAbi.observe(image, monitor::isCancelled).valid()) {
            return GhidraParameterAllocation.UNCHANGED;
        }
        var prototype = program.getCompilerSpec().getCallingConvention("__stdcall");
        if (prototype == null) return GhidraParameterAllocation.UNCHANGED;
        return (function, task, report) -> {
            task.checkCancelled();
            if (function.getProgram() != program || function.hasCustomVariableStorage() ||
                    function.hasVarArgs() || function.getCallingConvention() != prototype) return Map.of();
            var parameters = function.getParameters();
            if (parameters.length > 4096) return Map.of();
            var signature = new ArrayList<DataType>();
            signature.add(function.getReturn().getFormalDataType());
            for (var parameter : parameters) {
                task.checkCancelled();
                if (!parameter.isAutoParameter()) signature.add(parameter.getFormalDataType());
            }
            var expected = prototype.getStorageLocations(program, signature.toArray(DataType[]::new), true);
            if (expected.length != parameters.length + 1) return Map.of();
            var changes = new LinkedHashMap<Integer, VariableStorage>();
            for (int index = 0; index < parameters.length; index++) {
                task.checkCancelled();
                var parameter = parameters[index];
                var actual = parameter.getVariableStorage();
                if (!actual.equals(expected[index + 1]) ||
                        actual.isForcedIndirect() != expected[index + 1].isForcedIndirect() ||
                        actual.isAutoStorage() != expected[index + 1].isAutoStorage()) return Map.of();
                if (parameter.isAutoParameter()) continue;
                var widths = new ArrayList<Integer>();
                if (!members(parameter.getFormalDataType(), widths, new int[] {64}, task) ||
                        widths.size() < 2 || widths.size() > 4 ||
                        widths.stream().anyMatch(width -> !width.equals(widths.getFirst()))) continue;
                int width = widths.getFirst(), count = widths.size();
                if (!actual.isValid() || actual.isForcedIndirect() || actual.size() != width * count) continue;
                var nodes = actual.getVarnodes().clone();
                if (Arrays.stream(nodes).anyMatch(node -> !node.isRegister())) continue;
                Arrays.sort(nodes, Comparator.comparing(node -> node.getAddress()));
                var start = nodes[0].getAddress();
                int consumed = 0;
                boolean contiguous = true;
                for (var node : nodes) {
                    if (node.getAddress().subtract(start) != consumed) contiguous = false;
                    consumed += node.getSize();
                }
                if (!contiguous || consumed != width * count) continue;
                // Only the actual argument-bank S/D members may describe this HFA.
                // Integer/vector Q storage and explicit analyst joins are not reinterpreted.
                String prefix = width == 4 ? "s" : "d";
                int limit = width == 4 ? 16 : 8;
                var pieces = new ArrayList<Register>();
                for (int first = 0; first + count <= limit; first++) {
                    task.checkCancelled();
                    Register register = program.getRegister(prefix + first);
                    if (register == null || !register.getAddress().equals(start)) continue;
                    for (int member = 0; member < count; member++) {
                        Register piece = program.getRegister(prefix + (first + member));
                        if (piece == null || piece.getMinimumByteSize() != width ||
                                piece.getAddress().subtract(start) != (long) member * width) break;
                        pieces.add(piece);
                    }
                    break;
                }
                if (pieces.size() != count) continue;
                List<Register> ordered = big ? pieces : pieces.reversed();
                try {
                    var replacement = new VariableStorage(program, ordered.toArray(Register[]::new));
                    if (replacement.equals(actual)) continue;
                    changes.put(parameter.getOrdinal(), replacement);
                    report.accept("Expanded computed HFA register storage for " + function.getName() + "::" +
                        parameter.getName() + " from " + actual + " to " + replacement +
                        "; saved program and formal type remain unchanged");
                }
                catch (InvalidInputException invalid) {
                    throw new IllegalStateException("Validated HFA members cannot form a register join", invalid);
                }
            }
            return Map.copyOf(changes);
        };
    }

    /** Bounded flattening; reject padding, overlaps, unions and non-floating members. */
    private static boolean members(DataType type, List<Integer> widths, int[] budget, TaskMonitor monitor)
            throws CancelledException {
        monitor.checkCancelled();
        if (--budget[0] < 0 || type == null || widths.size() > 4) return false;
        if (type instanceof TypeDef alias) return members(alias.getBaseDataType(), widths, budget, monitor);
        if (type instanceof AbstractFloatDataType && (type.getLength() == 4 || type.getLength() == 8)) {
            widths.add(type.getLength());
            return widths.size() <= 4;
        }
        if (type instanceof Array array) {
            if (array.getNumElements() < 1 || array.getNumElements() > 4 ||
                    array.getElementLength() != array.getDataType().getLength()) return false;
            for (int index = 0; index < array.getNumElements(); index++) {
                if (!members(array.getDataType(), widths, budget, monitor)) return false;
            }
            return true;
        }
        if (!(type instanceof Structure structure) || structure.getNumDefinedComponents() < 1 ||
                structure.getNumDefinedComponents() > 4) return false;
        int offset = 0;
        for (var component : structure.getDefinedComponents()) {
            if (component.isBitFieldComponent() || component.getOffset() != offset ||
                    component.getLength() != component.getDataType().getLength() ||
                    !members(component.getDataType(), widths, budget, monitor)) return false;
            offset += component.getLength();
        }
        return offset == structure.getLength();
    }
}
