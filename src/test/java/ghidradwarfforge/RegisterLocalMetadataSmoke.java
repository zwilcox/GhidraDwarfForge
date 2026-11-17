package ghidradwarfforge;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.List;

import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.lang.DynamicVariableStorage;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;

/** Saved register identity must agree before either local lifetime refinement. */
final class RegisterLocalMetadataSmoke {
    private static int checks;

    private RegisterLocalMetadataSmoke() { }

    @FunctionalInterface
    interface Proof {
        List<GhidraVariableStorage.StorageInterval> prove(Function function, LocalVariable local) throws Exception;
    }

    static void check(ProgramDB program, Function original, LocalVariable saved,
            List<GhidraVariableStorage.StorageInterval> expected, Proof proof)
            throws Exception {
        long modification = program.getModificationNumber();
        var storage = saved.getVariableStorage();
        var type = saved.getDataType();
        var register = saved.getRegister();
        int firstUse = saved.getFirstUseOffset();
        Object owner = new Object();
        var foreign = new ProgramDB("foreign-register-owner", program.getLanguage(),
            program.getLanguage().getCompilerSpecByID(program.getCompilerSpec().getCompilerSpecID()), owner);
        try {
            for (String defect : List.of("transparent", "wrong-function", "foreign-program", "foreign-function",
                    "invalid", "unassigned", "missing-storage", "bad-storage", "unknown-storage", "void-storage",
                    "foreign-storage", "indirect-storage", "stack-storage", "short-storage", "missing-register",
                    "wrong-register", "short-register", "zero-width", "negative-width", "short-type")) {
                Function[] function = new Function[1];
                LocalVariable[] local = new LocalVariable[1];
                function[0] = (Function) Proxy.newProxyInstance(Function.class.getClassLoader(),
                    new Class<?>[] { Function.class }, (proxy, method, args) -> {
                        if (method.getName().equals("getProgram") && defect.equals("foreign-function")) return foreign;
                        if (method.getName().equals("getAllVariables")) {
                            return Arrays.stream(original.getAllVariables())
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
                        if (name.equals("isValid") && defect.equals("invalid")) return false;
                        if (name.equals("hasAssignedStorage") && defect.equals("unassigned")) return false;
                        if (name.equals("getLength")) {
                            if (defect.equals("zero-width")) return 0;
                            if (defect.equals("negative-width")) return -1;
                        }
                        if (name.equals("getDataType") && defect.equals("short-type")) return ByteDataType.dataType;
                        if (name.equals("getRegister")) {
                            if (defect.equals("missing-register")) return null;
                            if (defect.equals("wrong-register")) return program.getRegister(
                                register.getName().startsWith("R") ? (saved.getLength() == 4 ? "R11D" : "R11") :
                                    (saved.getLength() == 4 ? "w10" : "x10"));
                            if (defect.equals("short-register")) return program.getRegister(
                                register.getName().startsWith("R") ? "R10W" : "w9");
                        }
                        if (name.equals("getVariableStorage")) {
                            if (defect.equals("missing-storage")) return null;
                            if (defect.equals("bad-storage")) return VariableStorage.BAD_STORAGE;
                            if (defect.equals("unknown-storage")) return VariableStorage.UNASSIGNED_STORAGE;
                            if (defect.equals("void-storage")) return VariableStorage.VOID_STORAGE;
                            if (defect.equals("foreign-storage")) return new VariableStorage(foreign, register);
                            if (defect.equals("indirect-storage")) return new DynamicVariableStorage(program, true, storage.getVarnodes());
                            if (defect.equals("stack-storage")) return new VariableStorage(program, -16, saved.getLength());
                            if (defect.equals("short-storage")) return new VariableStorage(program,
                                new Varnode(register.getAddress(), saved.getLength() - 1));
                        }
                        try { return method.invoke(saved, args); }
                        catch (InvocationTargetException failure) { throw failure.getCause(); }
                    });
                // AArch64 w9 already is the narrowest ordinary integer register;
                // that control deliberately remains valid for the four-byte local.
                boolean unchanged = defect.equals("transparent") ||
                    (defect.equals("short-register") && register.getName().equals("w9"));
                var actual = proof.prove(function[0], local[0]);
                require(unchanged ? actual.equals(expected) : actual.isEmpty(),
                    "inconsistent saved register metadata acquired a lifetime: " + defect + " " + actual);
                require(proof.prove(original, saved).equals(expected),
                    "metadata refusal changed subsequent local proof: " + defect);
                require(program.getModificationNumber() == modification && saved.getVariableStorage().equals(storage) &&
                    saved.getDataType().equals(type) && saved.getRegister().equals(register) && saved.getFirstUseOffset() == firstUse,
                    "register proof changed saved identity: " + defect);
            }
        }
        finally { foreign.flushEvents(); foreign.release(owner); }
        System.out.println("register-local-metadata=PASS checks=" + checks);
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
