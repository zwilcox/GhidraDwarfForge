package ghidradwarfforge;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.function.BiConsumer;

import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;

/** Transparent target API view plus one inconsistent profile field at a time. */
final class TargetProfileViews {
    private TargetProfileViews() { }

    static Program create(Program program, int width, String defect, boolean growsNegative,
            BiConsumer<Boolean, String> check) {
        var originalSpace = program.getLanguage().getDefaultDataSpace();
        var selectedSpace = (AddressSpace) Proxy.newProxyInstance(AddressSpace.class.getClassLoader(),
            new Class<?>[] { AddressSpace.class }, (proxy, method, args) -> {
                String name = method.getName();
                if (name.equals("isOverlaySpace") && defect.equals("overlay")) return true;
                if (name.equals("getType") && defect.equals("register-space")) return AddressSpace.TYPE_REGISTER;
                if (name.equals("getAddressableUnitSize") && defect.equals("word-addressed")) return 2;
                if (name.equals("getPointerSize")) {
                    if (defect.equals("zero-pointer")) return 0;
                    if (defect.equals("wide-pointer")) return 9;
                    if (defect.equals("pointer-mismatch")) return width - 1;
                }
                try { return method.invoke(originalSpace, args); }
                catch (InvocationTargetException failure) { throw failure.getCause(); }
            });
        var language = (Language) Proxy.newProxyInstance(Language.class.getClassLoader(), new Class<?>[] { Language.class },
            (proxy, method, args) -> {
                if (method.getName().equals("getDefaultDataSpace")) return defect.equals("missing-memory") ? null : selectedSpace;
                try { return method.invoke(program.getLanguage(), args); }
                catch (InvocationTargetException failure) { throw failure.getCause(); }
            });
        var factory = (AddressFactory) Proxy.newProxyInstance(AddressFactory.class.getClassLoader(),
            new Class<?>[] { AddressFactory.class }, (proxy, method, args) -> {
                if (!defect.equals("unregistered-memory") && method.getName().equals("getAddressSpace") &&
                        args[0] instanceof Integer id && id == originalSpace.getSpaceID()) return selectedSpace;
                try { return method.invoke(program.getAddressFactory(), args); }
                catch (InvocationTargetException failure) { throw failure.getCause(); }
            });
        var compiler = (CompilerSpec) Proxy.newProxyInstance(CompilerSpec.class.getClassLoader(),
            new Class<?>[] { CompilerSpec.class }, (proxy, method, args) -> {
                if (method.getName().equals("getStackPointer")) {
                    if (defect.equals("missing-stack-pointer")) return null;
                    if (defect.equals("partial-stack-pointer")) {
                        var alias = program.getRegister(program.getLanguageID().toString().startsWith("x86") ?
                            (width == 8 ? "ESP" : "SP") : "wsp");
                        check.accept(alias != null && alias != alias.getBaseRegister(), "partial pointer fixture lacks an alias");
                        return alias;
                    }
                }
                if (method.getName().equals("stackGrowsNegative")) return growsNegative;
                try { return method.invoke(program.getCompilerSpec(), args); }
                catch (InvocationTargetException failure) { throw failure.getCause(); }
            });
        return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(), new Class<?>[] { Program.class },
            (proxy, method, args) -> {
                if (method.getName().equals("getLanguage")) return language;
                if (method.getName().equals("getCompilerSpec")) return compiler;
                if (method.getName().equals("getAddressFactory")) return factory;
                try { return method.invoke(program, args); }
                catch (InvocationTargetException failure) { throw failure.getCause(); }
            });
    }
}
