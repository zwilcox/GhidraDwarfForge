package ghidradwarfforge;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;

import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.DynamicVariableStorage;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.Varnode;

/** Contradictory saved API claims over real decoded scalar, mixed and indirect fixtures. */
final class ParameterProofMetadataSmoke {
    @FunctionalInterface
    interface Proof {
        List<GhidraVariableStorage.StorageInterval> read(Function function, Parameter parameter) throws Exception;
    }

    private ParameterProofMetadataSmoke() { }

    static void run(String mode, ProgramDB program, Function original, Parameter saved, Proof proof) throws Exception {
        var expected = proof.read(original, saved);
        require(!expected.isEmpty() && expected.stream().anyMatch(row -> row.storage().available()),
            "metadata control needs a proven value: " + mode);
        long modification = program.getModificationNumber();
        var storage = saved.getVariableStorage();
        var formal = saved.getFormalDataType();
        var effective = saved.getDataType();
        var body = original.getBody();
        var cases = new ArrayList<>(List.of("transparent", "foreign-owner", "negative-ordinal", "detached",
            "late-first-use", "zero-width", "negative-width", "short-width", "missing-type", "short-type"));
        if (mode.equals("indirect")) cases.addAll(List.of("non-pointer", "unknown-pointee", "wrong-pointee",
            "short-pointer", "empty-object", "narrow-abi-pointer"));
        for (String defect : cases) {
            Function[] function = new Function[1];
            Parameter[] parameter = new Parameter[1];
            function[0] = (Function) Proxy.newProxyInstance(Function.class.getClassLoader(),
                new Class<?>[] { Function.class }, (proxy, method, args) -> {
                    if (method.getName().equals("getParameter") &&
                            ((int) args[0] == saved.getOrdinal() || (int) args[0] < 0)) {
                        return defect.equals("detached") ? saved : parameter[0];
                    }
                    if (method.getName().equals("getParameters")) {
                        var parameters = original.getParameters().clone();
                        parameters[saved.getOrdinal()] = parameter[0];
                        return parameters;
                    }
                    try { return method.invoke(original, args); }
                    catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
            parameter[0] = (Parameter) Proxy.newProxyInstance(Parameter.class.getClassLoader(),
                new Class<?>[] { Parameter.class }, (proxy, method, args) -> {
                    String name = method.getName();
                    if (name.equals("getFunction")) return defect.equals("foreign-owner") ? original : function[0];
                    if (name.equals("getOrdinal") && defect.equals("negative-ordinal")) return -1;
                    if (name.equals("getFirstUseOffset") && defect.equals("late-first-use")) return 1;
                    if (name.equals("getLength")) {
                        if (defect.equals("zero-width")) return 0;
                        if (defect.equals("negative-width")) return -1;
                        if (defect.equals("short-width")) return saved.getLength() - 1;
                        if (defect.equals("narrow-abi-pointer")) return 4;
                    }
                    if (name.equals("getFormalDataType")) {
                        if (defect.equals("missing-type")) return null;
                        if (defect.equals("short-type")) return ByteDataType.dataType;
                        if (defect.equals("empty-object")) return VoidDataType.dataType;
                    }
                    if (name.equals("getDataType")) {
                        if (defect.equals("non-pointer")) return IntegerDataType.dataType;
                        if (defect.equals("unknown-pointee")) return new PointerDataType(null, saved.getLength());
                        if (defect.equals("wrong-pointee")) return new PointerDataType(ByteDataType.dataType, saved.getLength());
                        if (defect.equals("short-pointer") || defect.equals("narrow-abi-pointer")) return new PointerDataType(formal, 4);
                        if (defect.equals("empty-object")) return new PointerDataType(VoidDataType.dataType, saved.getLength());
                    }
                    if (name.equals("getVariableStorage") && defect.equals("narrow-abi-pointer")) {
                        return new DynamicVariableStorage(program, true,
                            new Varnode(storage.getFirstVarnode().getAddress(), 4));
                    }
                    try { return method.invoke(saved, args); }
                    catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
            var actual = proof.read(function[0], parameter[0]);
            require(defect.equals("transparent") ? actual.equals(expected) : actual.isEmpty(),
                "unproven parameter metadata acquired a location: " + mode + "/" + defect + " " + actual);
            require(proof.read(original, saved).equals(expected), "metadata refusal poisoned retry: " + mode + "/" + defect);
            require(program.getModificationNumber() == modification && original.getParameter(saved.getOrdinal()) == saved &&
                original.getBody().equals(body) && saved.getVariableStorage().equals(storage) &&
                saved.getFormalDataType().equals(formal) && saved.getDataType().equals(effective),
                "metadata proof changed saved state: " + mode + "/" + defect);
        }
        System.out.println("parameter-proof-metadata=PASS mode=" + mode + " cases=" + cases.size() +
            " language=" + program.getLanguageID());
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
