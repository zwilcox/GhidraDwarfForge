package ghidradwarfforge.targets;

import java.io.IOException;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.XmlEncode;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.GhidraParameterAllocation;
import ghidradwarfforge.elf.Arm32CallAbi;
import ghidradwarfforge.elf.ElfImage;

/** AAPCS32 B.4/C.4/C.5: aggregate bytes precede padding in allocated core/stack words. */
public final class ArmCompositeParameterAllocation {
    private static final Map<String, String> BASELINES = Map.of(
        "__stdcall", "ba8574da1c90f0de5f2c200657abf9ee36ba32836797c3f4e26b979bb001210b",
        "__stdcall_softfp", "3aff662ed70b8bd451ae1d1ce9eae845d041f4cda1f94b03e7e8b43b32bf4e7d");

    private ArmCompositeParameterAllocation() { }

    public static GhidraParameterAllocation forProgram(Program program, ElfImage image,
            TaskMonitor monitor, Consumer<String> diagnostic) throws CancelledException, IOException {
        monitor.checkCancelled();
        if (image.machine() != 40 || image.is64Bit() || image.byteOrder() != ByteOrder.BIG_ENDIAN ||
                !program.getLanguageID().toString().equals("ARM:LEBE:32:v8LEInstruction") ||
                !program.getCompilerSpec().getCompilerSpecID().toString().equals("default") ||
                !Arm32CallAbi.observe(image, monitor::isCancelled).valid()) return GhidraParameterAllocation.UNCHANGED;
        var prototypes = new ArrayList<PrototypeModel>();
        for (var baseline : BASELINES.entrySet()) {
            monitor.checkCancelled();
            var prototype = program.getCompilerSpec().getCallingConvention(baseline.getKey());
            if (prototype == null) continue;
            var encoder = new XmlEncode(false);
            prototype.encode(encoder, program.getCompilerSpec().getPcodeInjectLibrary());
            try {
                String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(encoder.toString().getBytes(StandardCharsets.UTF_8)));
                if (hash.equals(baseline.getValue())) prototypes.add(prototype);
                else diagnostic.accept("Computed composite allocation correction unavailable: " +
                    baseline.getKey() + " differs from the audited prototype");
            }
            catch (java.security.NoSuchAlgorithmException impossible) { throw new IOException(impossible); }
        }
        return (function, task, report) -> {
            task.checkCancelled();
            if (function.getProgram() != program || function.hasCustomVariableStorage() || function.hasVarArgs() ||
                    !prototypes.contains(function.getCallingConvention())) return Map.of();
            var parameters = function.getParameters();
            if (parameters.length > 4096) return Map.of();
            var signature = new ArrayList<DataType>();
            signature.add(function.getReturn().getFormalDataType());
            for (var parameter : parameters) {
                task.checkCancelled();
                if (!parameter.isAutoParameter()) signature.add(parameter.getFormalDataType());
            }
            var expected = function.getCallingConvention().getStorageLocations(program, signature.toArray(DataType[]::new), true);
            if (expected.length != parameters.length + 1) return Map.of();
            var changes = new LinkedHashMap<Integer, VariableStorage>();
            for (int index = 0; index < parameters.length; index++) {
                task.checkCancelled();
                var parameter = parameters[index];
                var actual = parameter.getVariableStorage();
                if (!actual.equals(expected[index + 1]) || actual.isForcedIndirect() != expected[index + 1].isForcedIndirect() ||
                        actual.isAutoStorage() != expected[index + 1].isAutoStorage()) return Map.of();
                if (parameter.isAutoParameter()) continue;
                DataType type = parameter.getFormalDataType();
                int aliases = 0;
                while (type instanceof TypeDef alias && aliases++ < 64) type = alias.getBaseDataType();
                if (!(type instanceof Composite || type instanceof Array) || type.getLength() <= 0 ||
                        type.getLength() % 4 == 0 || !actual.isValid() || actual.isForcedIndirect() ||
                        actual.size() != type.getLength()) continue;
                var replacement = memoryOrdered(program, actual, task);
                if (replacement == null || replacement.equals(actual)) continue;
                changes.put(parameter.getOrdinal(), replacement);
                report.accept("Normalized computed aggregate padding for " + function.getName() + "::" + parameter.getName() +
                    " from " + actual + " to " + replacement + "; saved program and formal type remain unchanged");
            }
            return Map.copyOf(changes);
        };
    }

    private static VariableStorage memoryOrdered(Program program, VariableStorage actual, TaskMonitor monitor)
            throws CancelledException {
        var core = new ArrayList<Register>();
        Varnode stack = null;
        for (Varnode node : actual.getVarnodes()) {
            monitor.checkCancelled();
            if (node.getAddress().isStackAddress()) {
                if (stack != null || node.getOffset() < 0) return null;
                stack = node;
                continue;
            }
            Register found = null;
            for (int index = 0; index < 4; index++) {
                Register candidate = program.getRegister("r" + index);
                if (candidate != null && candidate.getMinimumByteSize() == 4 &&
                        candidate.getAddress().getAddressSpace().equals(node.getAddress().getAddressSpace())) {
                    long offset = node.getAddress().subtract(candidate.getAddress());
                    if (offset >= 0 && offset + node.getSize() <= 4) found = candidate;
                }
            }
            if (found == null || core.contains(found)) return null;
            core.add(found);
        }
        core.sort(java.util.Comparator.comparing(Register::getAddress));
        for (int index = 1; index < core.size(); index++) {
            if (core.get(index).getAddress().subtract(core.get(index - 1).getAddress()) != 4) return null;
        }
        var nodes = new ArrayList<Varnode>();
        int remaining = actual.size();
        for (Register register : core) {
            int width = Math.min(remaining, 4);
            if (width <= 0) return null;
            // BE8 register storage bytes are little endian. The first bytes
            // of a big-endian memory word occupy its high register bits.
            nodes.add(new Varnode(register.getAddress().add(4 - width), width));
            remaining -= width;
        }
        if (stack != null) {
            int padding = (4 - stack.getSize() % 4) % 4;
            if (remaining != stack.getSize() || stack.getOffset() % 4 != padding) return null;
            nodes.add(new Varnode(stack.getAddress().subtract(padding), remaining));
            remaining = 0;
        }
        if (remaining != 0) return null;
        try { return new VariableStorage(program, nodes.toArray(Varnode[]::new)); }
        catch (InvalidInputException invalid) { throw new IllegalStateException("Audited aggregate allocation is not representable", invalid); }
    }
}
