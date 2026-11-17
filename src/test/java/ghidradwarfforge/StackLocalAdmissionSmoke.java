package ghidradwarfforge;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.lang.DynamicVariableStorage;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.Storage;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;

/** Admission and competing saved owners over the real stack STORE/LOAD fixture. */
final class StackLocalAdmissionSmoke {
    private static int checks;

    private StackLocalAdmissionSmoke() { }

    static void check(ProgramDB program, Function original, LocalVariable saved,
            TargetRegisterMap registers, Storage rejected,
            List<GhidraVariableStorage.StorageInterval> expected) throws Exception {
        require(!expected.isEmpty() && expected.stream().anyMatch(row -> row.storage().available()), "missing positive fixture");
        long modification = program.getModificationNumber();
        var storage = saved.getVariableStorage();
        var type = saved.getDataType();
        int firstUse = saved.getFirstUseOffset();
        long symbol = saved.getSymbol().getID();
        for (OmissionReason reason : OmissionReason.values()) {
            if (reason != OmissionReason.UNKNOWN_LIFETIME) {
                require(StackLocalLifetime.prove(program, original, saved, registers,
                    new UnavailableStorage(reason, "unrelated omission"), TaskMonitor.DUMMY).isEmpty(),
                    "stack proof replaced another omission: " + reason);
            }
        }
        var proven = expected.stream().filter(row -> row.storage().available()).findFirst().orElseThrow().storage();
        require(StackLocalLifetime.prove(program, original, saved, registers, proven, TaskMonitor.DUMMY).isEmpty(),
            "stack refinement replaced a proven location");
        var parameter = new ParameterImpl("not_a_local", type, storage, program, SourceType.USER_DEFINED);
        require(StackLocalLifetime.prove(program, original, parameter, registers, rejected, TaskMonitor.DUMMY).isEmpty(),
            "incoming parameter acquired a curated local lifetime");
        Object owner = new Object();
        var foreign = new ProgramDB("foreign-stack-owner", program.getLanguage(),
            program.getLanguage().getCompilerSpecByID(program.getCompilerSpec().getCompilerSpecID()), owner);
        try {
            var cases = new ArrayList<>(List.of("transparent", "wrong-function", "foreign-program", "foreign-function",
                "detached", "analysis", "zero-first-use", "negative-first-use", "invalid", "unassigned",
                "zero-width", "negative-width", "short-type", "missing-storage", "bad-storage", "unknown-storage",
                "void-storage", "foreign-storage", "indirect-storage", "register-storage", "short-storage"));
            for (String defect : cases) {
                Function[] function = new Function[1];
                LocalVariable[] local = new LocalVariable[1];
                function[0] = (Function) Proxy.newProxyInstance(Function.class.getClassLoader(),
                    new Class<?>[] { Function.class }, (proxy, method, args) -> {
                        if (method.getName().equals("getProgram") && defect.equals("foreign-function")) return foreign;
                        if (method.getName().equals("getAllVariables")) {
                            return Arrays.stream(original.getAllVariables())
                                .filter(value -> !defect.equals("detached") || value != saved)
                                .map(value -> value == saved ? local[0] : value).toArray(Variable[]::new);
                        }
                        try { return method.invoke(original, args); }
                        catch (InvocationTargetException failure) { throw failure.getCause(); }
                    });
                local[0] = (LocalVariable) Proxy.newProxyInstance(LocalVariable.class.getClassLoader(),
                    new Class<?>[] { LocalVariable.class }, (proxy, method, args) -> {
                        String name = method.getName();
                        if (name.equals("getFunction")) return defect.equals("wrong-function") ? original : function[0];
                        if (name.equals("getProgram") && defect.equals("foreign-program")) return foreign;
                        if (name.equals("getSource") && defect.equals("analysis")) return SourceType.ANALYSIS;
                        if (name.equals("getFirstUseOffset")) {
                            if (defect.equals("zero-first-use")) return 0;
                            if (defect.equals("negative-first-use")) return -1;
                        }
                        if (name.equals("isValid") && defect.equals("invalid")) return false;
                        if (name.equals("hasAssignedStorage") && defect.equals("unassigned")) return false;
                        if (name.equals("getLength")) {
                            if (defect.equals("zero-width")) return 0;
                            if (defect.equals("negative-width")) return -1;
                        }
                        if (name.equals("getDataType") && defect.equals("short-type")) return ByteDataType.dataType;
                        if (name.equals("getVariableStorage")) {
                            if (defect.equals("missing-storage")) return null;
                            if (defect.equals("bad-storage")) return VariableStorage.BAD_STORAGE;
                            if (defect.equals("unknown-storage")) return VariableStorage.UNASSIGNED_STORAGE;
                            if (defect.equals("void-storage")) return VariableStorage.VOID_STORAGE;
                            if (defect.equals("foreign-storage")) return new VariableStorage(foreign, saved.getStackOffset(), saved.getLength());
                            if (defect.equals("indirect-storage")) return new DynamicVariableStorage(program, true, storage.getVarnodes());
                            if (defect.equals("register-storage")) return new VariableStorage(program, program.getCompilerSpec().getStackPointer());
                            if (defect.equals("short-storage")) return new VariableStorage(program, saved.getStackOffset(), saved.getLength() - 1);
                        }
                        try { return method.invoke(saved, args); }
                        catch (InvocationTargetException failure) { throw failure.getCause(); }
                    });
                var actual = StackLocalLifetime.prove(program, function[0], local[0], registers, rejected, TaskMonitor.DUMMY);
                require(defect.equals("transparent") ? actual.equals(expected) : actual.isEmpty(),
                    "unproven stack metadata acquired a lifetime: " + defect + " " + actual);
                require(StackLocalLifetime.prove(program, original, saved, registers, rejected, TaskMonitor.DUMMY).equals(expected),
                    "metadata refusal poisoned stack proof: " + defect);
                require(program.getModificationNumber() == modification && saved.getSymbol().getID() == symbol &&
                    saved.getVariableStorage().equals(storage) && saved.getDataType().equals(type) && saved.getFirstUseOffset() == firstUse,
                    "stack proof changed saved identity: " + defect);
            }
        }
        finally { foreign.flushEvents(); foreign.release(owner); }

        var unassigned = original.addLocalVariable(new LocalVariableImpl("unknown_owner", firstUse,
            type, VariableStorage.UNASSIGNED_STORAGE, true, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
        try {
            require(!unassigned.hasAssignedStorage(), "unknown owner unexpectedly has storage");
            require(StackLocalLifetime.prove(program, original, saved, registers, rejected, TaskMonitor.DUMMY).equals(expected),
                "unassigned owner claimed the saved stack bytes");
        }
        finally { original.removeVariable(unassigned); }
        var disjoint = original.addLocalVariable(new LocalVariableImpl("disjoint_owner", type,
            saved.getStackOffset() - 32, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
        try {
            require(!storage.intersects(disjoint.getVariableStorage()), "disjoint owner overlaps");
            require(StackLocalLifetime.prove(program, original, saved, registers, rejected, TaskMonitor.DUMMY).equals(expected),
                "disjoint saved owner invalidated the stack proof");
        }
        finally { original.removeVariable(disjoint); }
        var invalid = original.addLocalVariable(new LocalVariableImpl("invalid_owner", firstUse,
            type, VariableStorage.BAD_STORAGE, true, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
        require(invalid.hasAssignedStorage() && !invalid.getVariableStorage().isValid(), "bad owner was normalized");
        require(StackLocalLifetime.prove(program, original, saved, registers, rejected, TaskMonitor.DUMMY).isEmpty(),
            "invalid saved ownership allowed a stack lifetime");
        // Leave this final malformed row for fixture disposal; this Ghidra version
        // can retain a stale variable-cache entry after deleting BAD_STORAGE rows.
        System.out.println("stack-local-admission=PASS checks=" + checks + " language=" + program.getLanguageID());
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
