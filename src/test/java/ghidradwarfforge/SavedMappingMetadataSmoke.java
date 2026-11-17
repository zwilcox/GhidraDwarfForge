package ghidradwarfforge;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.IdentityHashMap;
import java.util.List;

import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.Variable;
import ghidra.util.task.TaskMonitor;

/** Match Ghidra's saved merge map only to consistent curated listing identities. */
final class SavedMappingMetadataSmoke {
    private static int checks;

    private SavedMappingMetadataSmoke() { }

    static void check(ProgramDB program, Function original, List<GhidraLocalMappings.Group> expected) throws Exception {
        long modification = program.getModificationNumber();
        Variable[] saved = original.getLocalVariables();
        var snapshot = Arrays.stream(saved).map(SavedMappingMetadataSmoke::identity).toList();
        Object owner = new Object();
        var foreign = new ProgramDB("foreign-mapping-owner", program.getLanguage(),
            program.getLanguage().getCompilerSpecByID(program.getCompilerSpec().getCompilerSpecID()), owner);
        try {
            for (int selected = 0; selected < saved.length; selected++) {
                final int member = selected;
                for (String defect : List.of("transparent", "wrong-function", "foreign-program", "invalid", "unassigned",
                        "missing-register", "wrong-register", "zero-width", "negative-first-use")) {
                    Function[] function = new Function[1];
                    var views = new IdentityHashMap<Variable, Variable>();
                    function[0] = (Function) Proxy.newProxyInstance(Function.class.getClassLoader(),
                        new Class<?>[] { Function.class }, (proxy, method, args) -> {
                            if (method.getName().equals("getLocalVariables") || method.getName().equals("getAllVariables")) {
                                var values = (Variable[]) method.invoke(original, args);
                                return Arrays.stream(values).map(value -> views.getOrDefault(value, value)).toArray(Variable[]::new);
                            }
                            try { return method.invoke(original, args); }
                            catch (InvocationTargetException failure) { throw failure.getCause(); }
                        });
                    for (int index = 0; index < saved.length; index++) {
                        Variable value = saved[index];
                        boolean changed = index == member;
                        var view = (Variable) Proxy.newProxyInstance(LocalVariable.class.getClassLoader(),
                            new Class<?>[] { LocalVariable.class }, (proxy, method, args) -> {
                                String name = method.getName();
                                if (name.equals("equals")) return proxy == args[0];
                                if (name.equals("hashCode")) return System.identityHashCode(proxy);
                                if (name.equals("getFunction")) return changed && defect.equals("wrong-function") ? original : function[0];
                                if (changed) {
                                    if (name.equals("getProgram") && defect.equals("foreign-program")) return foreign;
                                    if (name.equals("isValid") && defect.equals("invalid")) return false;
                                    if (name.equals("hasAssignedStorage") && defect.equals("unassigned")) return false;
                                    if (name.equals("getRegister")) {
                                        if (defect.equals("missing-register")) return null;
                                        if (defect.equals("wrong-register")) return value.getRegister().equals(saved[0].getRegister())
                                            ? saved[1].getRegister() : saved[0].getRegister();
                                    }
                                    if (name.equals("getLength") && defect.equals("zero-width")) return 0;
                                    if (name.equals("getFirstUseOffset") && defect.equals("negative-first-use")) return -1;
                                }
                                try { return method.invoke(value, args); }
                                catch (InvocationTargetException failure) { throw failure.getCause(); }
                            });
                        views.put(value, view);
                    }
                    var messages = new ArrayList<String>();
                    var actual = GhidraLocalMappings.extract(program, function[0], TaskMonitor.DUMMY, messages::add);
                    // Ghidra can omit an invalid trailing member before encoding
                    // the saved map. Its preceding complete identity remains valid;
                    // no result may include the inconsistent member or jump its gap.
                    var prefix = member < 2 ? List.<GhidraLocalMappings.Group>of() :
                        List.of(new GhidraLocalMappings.Group(expected.getFirst().canonical(),
                            expected.getFirst().mappings().subList(0, member)));
                    boolean accepted = defect.equals("transparent") ? describe(actual).equals(describe(expected)) :
                        actual.isEmpty() || describe(actual).equals(describe(prefix));
                    require(accepted,
                        "inconsistent listing metadata acquired a saved merge: " + member + "/" + defect + " " + actual);
                    require(program.getModificationNumber() == modification &&
                        Arrays.stream(original.getLocalVariables()).map(SavedMappingMetadataSmoke::identity).toList().equals(snapshot),
                        "merge extraction rewrote saved identities");
                    require(GhidraLocalMappings.extract(program, original, TaskMonitor.DUMMY, ignored -> { }).equals(expected),
                        "metadata refusal changed subsequent merge extraction");
                }
            }
        }
        finally { foreign.flushEvents(); foreign.release(owner); }
        System.out.println("saved-mapping-metadata=PASS checks=" + checks);
    }

    private static List<Object> identity(Variable value) {
        return List.of(value.getSymbol().getID(), value.getName(), value.getFirstUseOffset(), value.getDataType(), value.getVariableStorage());
    }

    private static List<List<Object>> describe(List<GhidraLocalMappings.Group> groups) {
        return groups.stream().map(group -> List.<Object>of(group.canonical().getSymbol().getID(),
            group.mappings().stream().map(mapping -> List.of(mapping.variable().getSymbol().getID(), mapping.definition(), mapping.register())).toList())).toList();
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
