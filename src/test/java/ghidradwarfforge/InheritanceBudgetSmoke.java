package ghidradwarfforge;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.targets.CxxAbiProfile;
import ghidradwarfforge.types.InheritanceModel;
import ghidradwarfforge.types.InheritanceModel.*;

/** Real saved layouts and bounded records: reject excess without replacing prior evidence. */
public final class InheritanceBudgetSmoke {
    private static final int BYTE_LIMIT = 1024 * 1024;
    private static final String GROUP = GhidraInheritanceBindings.OPTIONS_NAME;
    private static final String KEY = GhidraInheritanceBindings.KEY;
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        run();
    }

    static void run() throws Exception {
        Object owner = new Object();
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB("inheritance-budgets", language, language.getDefaultCompilerSpec(), owner);
        int transaction = program.startTransaction("explicit bounded layouts");
        try {
            encodedBytes(program);
            layoutBudget(program, false);
            layoutBudget(program, true);
        }
        finally {
            program.endTransaction(transaction, false);
            program.release(owner);
        }
        System.out.println("inheritance-budgets=PASS checks=" + checks);
    }

    private static long bind(ProgramDB program, String name, StructureDataType structure) throws Exception {
        var owner = program.getSymbolTable().createClass(program.getGlobalNamespace(), name, SourceType.USER_DEFINED);
        var saved = (Structure) program.getDataTypeManager().resolve(structure, DataTypeConflictHandler.DEFAULT_HANDLER);
        GhidraClassBindings.save(program, owner, saved, "explicit budget fixture", TaskMonitor.DUMMY);
        return owner.getID();
    }

    private static void encodedBytes(ProgramDB program) throws Exception {
        long parent = bind(program, "ByteParent", new StructureDataType("ByteParentLayout", 1));
        var bases = new ArrayList<Base>();
        for (int index = 0; index < 128; index++) {
            long child = bind(program, "ByteChild" + index, new StructureDataType("ByteChildLayout" + index, 1));
            bases.add(new Base(child, parent, 0, Access.PUBLIC, new FixedBase(0, 1), "x"));
        }
        var small = model(bases);
        save(program, small);
        String previous = encoded(program);
        int remaining = BYTE_LIMIT - raw(previous).length;
        for (int index = 0; index < bases.size(); index++) {
            int extra = Math.min(8191, remaining);
            bases.set(index, evidence(bases.get(index), "x".repeat(1 + extra)));
            remaining -= extra;
        }
        require(remaining == 0, "128 bounded ASCII provenance fields can fill exactly one MiB");
        var exact = model(bases);
        save(program, exact);
        String boundary = encoded(program);
        require(raw(boundary).length == BYTE_LIMIT, "independent decoded record length equals byte cap");
        require(read(program).equals(exact), "exact byte-cap record round trips");
        long modification = program.getModificationNumber();
        var oversized = new ArrayList<>(bases);
        int last = oversized.size() - 1;
        oversized.set(last, evidence(oversized.get(last), oversized.get(last).evidence() + "x"));
        rejectSave(program, model(oversized), "inheritance bytes exceed bound");
        require(encoded(program).equals(boundary) && program.getModificationNumber() == modification,
            "oversized save preserves previous complete record and saved program");
        require(read(program).equals(exact), "previous evidence remains usable after oversized save");

        // One extra decoded byte has the same Base64 length here. It must be
        // refused by the decoded-byte limit, not merely the text-length guard.
        byte[] tooMany = Arrays.copyOf(raw(boundary), BYTE_LIMIT + 1);
        String tooManyText = "GDFIB1:" + Base64.getEncoder().encodeToString(tooMany);
        require(tooManyText.length() == boundary.length(), "Base64 padding isolates decoded-byte admission");
        program.getOptions(GROUP).setString(KEY, tooManyText);
        modification = program.getModificationNumber();
        var diagnostics = new ArrayList<String>();
        var rejected = GhidraInheritanceBindings.read(program, TaskMonitor.DUMMY, diagnostics::add);
        require(rejected.status() == GhidraInheritanceBindings.Status.REJECTED && rejected.model() == null &&
            diagnostics.equals(List.of("Omitted explicit inheritance: oversized inheritance record")),
            "decoded excess is rejected at its own boundary");
        require(encoded(program).equals(tooManyText) && program.getModificationNumber() == modification,
            "rejected read does not repair or remove analyst evidence");
        program.getOptions(GROUP).setString(KEY, boundary);

        var counter = new CountingMonitor(Integer.MAX_VALUE);
        GhidraInheritanceBindings.save(program, small, counter);
        program.getOptions(GROUP).setString(KEY, boundary);
        for (int stop : List.of(1, counter.visits / 2, counter.visits)) {
            modification = program.getModificationNumber();
            var cancelled = new CountingMonitor(stop);
            try {
                GhidraInheritanceBindings.save(program, small, cancelled);
                throw new AssertionError("cancelled inheritance save replaced previous generation");
            }
            catch (CancelledException expected) { require(cancelled.visits == stop, "cancel promptly at observed save boundary"); }
            require(encoded(program).equals(boundary) && program.getModificationNumber() == modification,
                "early, traversal and final-write cancellation preserve previous evidence");
        }
        save(program, small);
        require(encoded(program).equals(previous), "clean retry deterministically restores small record");
    }

    private static void layoutBudget(ProgramDB program, boolean unique) throws Exception {
        String label = unique ? "Unique" : "Visits";
        long parent = bind(program, label + "Parent", new StructureDataType(label + "ParentLayout", 1));
        var rawLayout = new StructureDataType(label + "ChildLayout", 0);
        int members = unique ? 4095 : 65534;
        for (int index = 0; index < members; index++) {
            if (unique) {
                var enumeration = new EnumDataType("BudgetEnum" + index, 1);
                enumeration.add("VALUE", 0);
                rawLayout.add(enumeration, 1, null, null);
            }
            else rawLayout.add(ByteDataType.dataType, 1, null, null);
        }
        long child = bind(program, label + "Child", rawLayout);
        var layout = GhidraClassBindings.read(program, child, TaskMonitor.DUMMY, ignored -> { }).binding().type();
        require(layout.getNumDefinedComponents() == members, "all real saved layout components retained");
        var binding = model(List.of(new Base(child, parent, 0, Access.PUBLIC, new FixedBase(0, 1), "bounded layout")));
        // Empty parent visits one node; child visits one root plus each member.
        // Repeated members still count toward traversal, unique types toward the graph cap.
        save(program, binding);
        String prior = encoded(program);
        require(read(program).equals(binding), "exact " + label + " layout bound round trips");
        if (unique) {
            var extra = new EnumDataType("BudgetEnumExtra", 1);
            extra.add("VALUE", 0);
            layout.add(extra, 1, null, null);
        }
        else layout.add(ByteDataType.dataType, 1, null, null);
        long modification = program.getModificationNumber();
        rejectSave(program, binding, unique ? "inheritance layout graph exceeds bound" : "inheritance layout traversal exceeds bound");
        require(encoded(program).equals(prior) && program.getModificationNumber() == modification,
            "excess " + label + " save preserves old record and analyst layout edit");
        if (!unique) {
            layout.add(ByteDataType.dataType, 1, null, null);
            layout.add(ByteDataType.dataType, 1, null, null);
            rejectSave(program, binding, "inheritance layout components exceed bound");
            require(encoded(program).equals(prior), "excess component inventory preserves previous record");
            layout.delete(layout.getNumComponents() - 1);
            layout.delete(layout.getNumComponents() - 1);
        }
        layout.delete(layout.getNumComponents() - 1);
        require(read(program).equals(binding), "restoring physical layout recovers original evidence");
        save(program, binding);
        require(encoded(program).equals(prior), "bounded layout save is deterministic");
    }

    private static InheritanceModel model(List<Base> bases) {
        return new InheritanceModel(CxxAbiProfile.ITANIUM_X86_64, bases, List.of());
    }

    private static Base evidence(Base base, String value) {
        return new Base(base.derivedClassId(), base.baseClassId(), base.order(), base.access(), base.location(), value);
    }

    private static void save(ProgramDB program, InheritanceModel model) throws Exception {
        try { GhidraInheritanceBindings.save(program, model, TaskMonitor.DUMMY); }
        catch (IllegalArgumentException unexpected) { throw new AssertionError("valid bounded inheritance must be saved", unexpected); }
    }

    private static void rejectSave(ProgramDB program, InheritanceModel model, String message) throws Exception {
        try {
            GhidraInheritanceBindings.save(program, model, TaskMonitor.DUMMY);
            throw new AssertionError("accepted excessive inheritance: " + message);
        }
        catch (IllegalArgumentException expected) { require(expected.getMessage().equals(message), "correct budget rejection: " + expected); }
    }

    private static InheritanceModel read(ProgramDB program) throws Exception {
        var diagnostics = new ArrayList<String>();
        var result = GhidraInheritanceBindings.read(program, TaskMonitor.DUMMY, diagnostics::add);
        require(result.status() == GhidraInheritanceBindings.Status.VALID && diagnostics.isEmpty(), "valid saved evidence: " + diagnostics);
        return result.model();
    }

    private static String encoded(ProgramDB program) { return program.getOptions(GROUP).getString(KEY, null); }
    private static byte[] raw(String encoded) { return Base64.getDecoder().decode(encoded.substring("GDFIB1:".length())); }

    private static final class CountingMonitor extends TaskMonitorAdapter {
        private final int stop;
        private int visits;
        private CountingMonitor(int stop) { super(true); this.stop = stop; }
        @Override public void checkCancelled() throws CancelledException { if (++visits == stop) throw new CancelledException(); }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
