package ghidradwarfforge;

import java.io.IOException;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;
import java.util.TreeSet;

import ghidra.app.util.demangler.Demangled;
import ghidra.app.util.demangler.DemangledException;
import ghidra.app.util.demangler.Demangler;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.elf.EquateNameReservations;

/** Observe demangled spellings without applying names, signatures, comments or analysis. */
public final class GhidraEquateNames {
    private GhidraEquateNames() { }

    public static EquateNameReservations extend(Program program, EquateNameReservations original,
            TaskMonitor monitor) throws IOException, CancelledException {
        var demanglers = ClassSearcher.getInstances(Demangler.class).stream()
            .filter(demangler -> demangler.canDemangle(program))
            .sorted(java.util.Comparator.comparing(demangler -> demangler.getClass().getName())).toList();
        var names = new TreeSet<String>();
        for (String spelling : original.originalSpellings(monitor::isCancelled)) {
            monitor.checkCancelled();
            for (var demangler : demanglers) {
                monitor.checkCancelled();
                try {
                    var context = demangler.createMangledContext(spelling, demangler.createDefaultOptions(), program, null);
                    var value = demangler.demangle(context);
                    Set<Demangled> visited = Collections.newSetFromMap(new IdentityHashMap<>());
                    for (Demangled item = value; item != null; item = item.getNamespace()) {
                        monitor.checkCancelled();
                        if (!visited.add(item)) throw new IOException("cyclic demangled namespace");
                        if (item.getName() != null) names.add(item.getName());
                        if (item.getDemangledName() != null) names.add(item.getDemangledName());
                    }
                }
                catch (DemangledException failure) {
                    if (!failure.isInvalidMangledName()) {
                        throw new IOException("could not reserve retained consumer names with " +
                            demangler.getClass().getSimpleName() + ": " + failure.getMessage(), failure);
                    }
                }
            }
        }
        monitor.checkCancelled();
        return original.withNames(names, monitor::isCancelled);
    }
}
