package ghidradwarfforge.targets;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.AutoParameterType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.XmlEncode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.GhidraParameterAllocation;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.nativeapi.DwarfTarget;

/** SysV i386 extended floating returns use ST0, not a hidden result pointer. */
public final class I386ParameterAllocation {
    private static final String BASELINE =
        "7ba01164ccf6a676ad8af4061342e76c9e2722e9e9460d400c50f8bdd2d68df7";

    private I386ParameterAllocation() {
    }

    public static GhidraParameterAllocation forProgram(Program program, ElfImage image,
            TaskMonitor monitor, Consumer<String> diagnostic) throws CancelledException, IOException {
        monitor.checkCancelled();
        var spec = program.getCompilerSpec();
        byte[] header = image.headerBytes();
        int osAbi = Byte.toUnsignedInt(header[7]);
        if (!DwarfTarget.fromElf(image).name().equals("x86") ||
                !program.getLanguageID().toString().equals("x86:LE:32:default") ||
                !spec.getCompilerSpecID().toString().equals("gcc") ||
                (image.type() != 2 && image.type() != 3) || image.flags() != 0 ||
                (osAbi != 0 && osAbi != 3) || header[8] != 0) {
            return GhidraParameterAllocation.UNCHANGED;
        }
        var original = spec.getDefaultCallingConvention();
        var encoder = new XmlEncode(false);
        original.encode(encoder, spec.getPcodeInjectLibrary());
        try {
            String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(encoder.toString().getBytes(StandardCharsets.UTF_8)));
            if (!hash.equals(BASELINE)) {
                diagnostic.accept("Computed floating-return allocation correction unavailable: selected prototype differs from the audited baseline");
                return GhidraParameterAllocation.UNCHANGED;
            }
        }
        catch (java.security.NoSuchAlgorithmException error) {
            throw new IOException("Cannot identify audited parameter allocation", error);
        }
        return new GhidraParameterAllocation() {
            @Override
            public boolean hasReturnCorrections() { return true; }

            @Override
            public SignatureResolution resolveSignature(FunctionSignature signature, TaskMonitor task)
                    throws CancelledException {
                task.checkCancelled();
                if (spec.getCallingConvention(signature.getCallingConventionName()) != original ||
                        !extended(signature.getReturnType()) || signature.getArguments().length > 4095) return null;
                var types = new ArrayList<DataType>();
                types.add(signature.getReturnType());
                for (var argument : signature.getArguments()) {
                    task.checkCancelled();
                    types.add(argument.getDataType());
                }
                var expected = original.getStorageLocations(program, types.toArray(DataType[]::new), true);
                types.set(0, new DoubleDataType(program.getDataTypeManager()));
                var adjusted = original.getStorageLocations(program, types.toArray(DataType[]::new), true);
                if (expected.length != types.size() + 1 || adjusted.length != types.size() ||
                        expected[1].getAutoParameterType() != AutoParameterType.RETURN_STORAGE_PTR ||
                        !adjusted[0].isRegisterStorage() || adjusted[0].size() != 10 ||
                        !adjusted[0].getRegister().getName().equals("ST0")) {
                    throw new IllegalStateException("Call override escaped audited floating-return allocation");
                }
                var inputs = new ArrayList<VariableStorage>();
                for (int index = 1; index < adjusted.length; index++) {
                    task.checkCancelled();
                    var storage = adjusted[index];
                    var prior = expected[index + 1];
                    if (!storage.isStackStorage() || storage.size() != prior.size() ||
                            storage.isForcedIndirect() || storage.isAutoStorage() ||
                            storage.getStackOffset() < 4 || storage.getStackOffset() > prior.getStackOffset()) {
                        throw new IllegalStateException("Call override escaped audited stack boundary");
                    }
                    inputs.add(storage);
                }
                return new SignatureResolution(adjusted[0], inputs);
            }

            @Override
            public Map<Integer, VariableStorage> corrections(Function function, TaskMonitor task,
                    Consumer<String> report) throws CancelledException {
                return resolve(function, task, report).storage();
            }

            @Override
            public Resolution resolveDeclaration(Function function, TaskMonitor task,
                    Consumer<String> report) throws CancelledException {
                return resolve(function, task, report);
            }

            @Override
            public Resolution resolve(Function function, TaskMonitor task,
                    Consumer<String> report) throws CancelledException {
                task.checkCancelled();
                var unchanged = new Resolution(Map.of(), Set.of());
                if (function.getProgram() != program || function.hasCustomVariableStorage() ||
                        function.getCallingConvention() != original) return unchanged;
                DataType type = function.getReturn().getFormalDataType();
                var seen = java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<DataType, Boolean>());
                while (type instanceof TypeDef alias && seen.add(type) && seen.size() <= 64) {
                    type = alias.getBaseDataType();
                }
                if (!(type instanceof AbstractFloatDataType) || type.getLength() != 10 ||
                        type.getAlignedLength() != 12) return unchanged;
                var parameters = function.getParameters();
                if (parameters.length == 0 || parameters.length > 4096 ||
                        parameters[0].getAutoParameterType() != AutoParameterType.RETURN_STORAGE_PTR) return unchanged;
                var types = new ArrayList<DataType>();
                types.add(function.getReturn().getFormalDataType());
                for (int index = 1; index < parameters.length; index++) {
                    task.checkCancelled();
                    if (parameters[index].isAutoParameter()) return unchanged;
                    types.add(parameters[index].getFormalDataType());
                }
                var expected = original.getStorageLocations(program, types.toArray(DataType[]::new), true);
                // Ghidra 12.0.3 compares aligned length 12 with ST0's size 10 and
                // falls back to indirect return. Use the same scalar x87 return
                // class solely to allocate inputs; never replace the formal type.
                types.set(0, new DoubleDataType(program.getDataTypeManager()));
                var adjusted = original.getStorageLocations(program, types.toArray(DataType[]::new), true);
                if (expected.length != parameters.length + 1 || adjusted.length != parameters.length ||
                        !same(expected[0], function.getReturn().getVariableStorage()) ||
                        !adjusted[0].isRegisterStorage() || adjusted[0].size() != 10 ||
                        !adjusted[0].getRegister().getName().equals("ST0")) {
                    throw new IllegalStateException("Floating-return correction escaped audited allocation");
                }
                var changes = new LinkedHashMap<Integer, VariableStorage>();
                for (int index = 0; index < parameters.length; index++) {
                    task.checkCancelled();
                    if (!same(expected[index + 1], parameters[index].getVariableStorage())) {
                        throw new IllegalStateException("Saved dynamic storage disagrees with its selected prototype");
                    }
                    if (index == 0) continue;
                    var replacement = adjusted[index];
                    var prior = expected[index + 1];
                    // Preserve genuinely unassigned storage instead of inventing a carrier.
                    if (prior.isUnassignedStorage() && replacement.isUnassignedStorage()) continue;
                    if (!replacement.isStackStorage() || replacement.size() != prior.size() ||
                            replacement.isForcedIndirect() != prior.isForcedIndirect() || replacement.isAutoStorage() ||
                            replacement.getStackOffset() < 4 || replacement.getStackOffset() > prior.getStackOffset()) {
                        throw new IllegalStateException("Floating-return correction escaped audited stack boundary");
                    }
                    changes.put(parameters[index].getOrdinal(), replacement);
                }
                report.accept("Corrected computed extended floating-return parameter allocation for " +
                    function.getName() + "; omitted the spurious automatic return pointer and restored stack arguments; " +
                    "saved program and formal types remain unchanged");
                return new Resolution(changes, Set.of(parameters[0].getOrdinal()), adjusted[0]);
            }
        };
    }

    private static boolean extended(DataType type) {
        var seen = java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<DataType, Boolean>());
        while (type instanceof TypeDef alias && seen.add(type) && seen.size() <= 64) {
            type = alias.getBaseDataType();
        }
        return type instanceof AbstractFloatDataType && type.getLength() == 10 && type.getAlignedLength() == 12;
    }

    private static boolean same(VariableStorage left, VariableStorage right) {
        return left.equals(right) && left.isAutoStorage() == right.isAutoStorage() &&
            left.isForcedIndirect() == right.isForcedIndirect();
    }
}
