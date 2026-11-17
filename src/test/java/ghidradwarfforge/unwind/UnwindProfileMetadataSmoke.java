package ghidradwarfforge.unwind;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.List;

import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.targets.UnwindAbiProfile;

/** Inconsistent metadata views over a real decoded program must not establish an ABI. */
final class UnwindProfileMetadataSmoke {
    private UnwindProfileMetadataSmoke() { }

    static void check(Program program, Function function, ElfImage image,
            UnwindAbiProfile.Bound baseline, boolean arm) throws Exception {
        long modification = program.getModificationNumber();
        String first = baseline.description().registers().get(0);
        String second = baseline.description().registers().get(1);
        for (String defect : List.of("transparent", "pointer-width", "byte-order", "missing-register",
                "narrow-register", "aliased-register", "missing-stack", "wrong-stack", "missing-flags")) {
            var compiler = (CompilerSpec) Proxy.newProxyInstance(CompilerSpec.class.getClassLoader(),
                new Class<?>[] {CompilerSpec.class}, (proxy, method, args) -> {
                    if (method.getName().equals("getStackPointer")) {
                        if (defect.equals("missing-stack")) return null;
                        if (defect.equals("wrong-stack")) return program.getRegister(first);
                    }
                    return invoke(program.getCompilerSpec(), method, args);
                });
            var language = (Language) Proxy.newProxyInstance(Language.class.getClassLoader(),
                new Class<?>[] {Language.class}, (proxy, method, args) -> {
                    if (method.getName().equals("isBigEndian") && defect.equals("byte-order")) return true;
                    return invoke(program.getLanguage(), method, args);
                });
            var view = (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
                new Class<?>[] {Program.class}, (proxy, method, args) -> {
                    if (method.getName().equals("getCompilerSpec")) return compiler;
                    if (method.getName().equals("getLanguage")) return language;
                    if (method.getName().equals("getDefaultPointerSize") && defect.equals("pointer-width")) return 4;
                    if (method.getName().equals("getRegister") && args.length == 1 && args[0] instanceof String name) {
                        if (name.equals(first)) {
                            if (defect.equals("missing-register")) return null;
                            if (defect.equals("narrow-register")) return program.getRegister(arm ? "w0" : "EAX");
                        }
                        if (name.equals(second) && defect.equals("aliased-register")) return program.getRegister(first);
                        if (baseline.description().flags().contains(name) && defect.equals("missing-flags")) return null;
                    }
                    return invoke(program, method, args);
                });
            if (defect.equals("transparent") || defect.equals("missing-flags")) {
                var selected = UnwindAbiProfile.select(view, function, image, 0, TaskMonitor.DUMMY);
                require(selected.entry().equals(baseline.entry()) && selected.registers().equals(baseline.registers()),
                    "valid metadata view changed incoming frame identities");
                require(defect.equals("transparent") ? selected.equals(baseline) :
                    selected.permittedCells().equals(List.copyOf(baseline.registers().values())),
                    "missing optional flags granted unknown register effects");
            }
            else {
                String diagnostic = switch (defect) {
                    case "pointer-width", "byte-order" -> "outside the selected ordinary unwind ABIs";
                    case "missing-register", "narrow-register" -> "profile register width/name is unavailable";
                    case "aliased-register" -> "profile registers alias unexpectedly";
                    default -> "compiler stack register differs from the audited ABI";
                };
                try {
                    UnwindAbiProfile.select(view, function, image, 0, TaskMonitor.DUMMY);
                    throw new AssertionError("accepted inconsistent unwind metadata: " + defect);
                }
                catch (IllegalArgumentException expected) {
                    require(expected.getMessage().contains(diagnostic), "wrong metadata rejection: " + expected);
                }
            }
            require(program.getModificationNumber() == modification &&
                UnwindAbiProfile.select(program, function, image, 0, TaskMonitor.DUMMY).equals(baseline),
                "metadata rejection changed the program or valid retry");
        }
        for (String defect : List.of("external", "thunk", "missing-convention", "unknown-convention")) {
            var view = (Function) Proxy.newProxyInstance(Function.class.getClassLoader(),
                new Class<?>[] {Function.class}, (proxy, method, args) -> {
                    if (method.getName().equals("isExternal") && defect.equals("external")) return true;
                    if (method.getName().equals("isThunk") && defect.equals("thunk")) return true;
                    if (defect.endsWith("convention")) {
                        if (method.getName().equals("getCallingConvention")) return null;
                        if (method.getName().equals("hasUnknownCallingConventionName")) return defect.equals("unknown-convention");
                    }
                    return invoke(function, method, args);
                });
            if (defect.equals("unknown-convention")) {
                require(UnwindAbiProfile.select(program, view, image, 0, TaskMonitor.DUMMY).equals(baseline),
                    "ordinary unknown convention lost audited compiler fallback");
            }
            else {
                try {
                    UnwindAbiProfile.select(program, view, image, 0, TaskMonitor.DUMMY);
                    throw new AssertionError("accepted incompatible function metadata: " + defect);
                }
                catch (IllegalArgumentException expected) {
                    require(expected.getMessage().contains("function convention is not the audited ordinary ABI"),
                        "wrong function metadata rejection");
                }
                if (defect.equals("thunk")) {
                    require(UnwindAbiProfile.selectForCallSites(program, view, image, 0, TaskMonitor.DUMMY)
                        .entry().equals(baseline.entry()), "call-site thunk selection lost its separate contract");
                }
            }
            require(program.getModificationNumber() == modification &&
                UnwindAbiProfile.select(program, function, image, 0, TaskMonitor.DUMMY).equals(baseline),
                "function metadata view changed the program or retry");
        }
        System.out.println("unwind-profile-metadata=PASS target=" + baseline.description().id() + " cases=13");
    }

    private static Object invoke(Object target, Method method, Object[] args) throws Throwable {
        try { return method.invoke(target, args); }
        catch (InvocationTargetException failure) { throw failure.getCause(); }
    }

    private static void require(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }
}
