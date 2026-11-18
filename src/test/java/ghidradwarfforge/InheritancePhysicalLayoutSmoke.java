package ghidradwarfforge;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.targets.CxxAbiProfile;
import ghidradwarfforge.types.InheritanceModel;
import ghidradwarfforge.types.InheritanceModel.*;

/** Saved relationships depend on physical member details, not display spelling. */
final class InheritancePhysicalLayoutSmoke {
    private static int checks;

    private InheritancePhysicalLayoutSmoke() { }

    static void run() throws Exception {
        check("x86:LE:64:default", CxxAbiProfile.ITANIUM_X86_64);
        check("AARCH64:LE:64:v8A", CxxAbiProfile.ITANIUM_AARCH64);
        System.out.println("inheritance-physical-layout=PASS checks=" + checks);
    }

    private static void check(String languageId, CxxAbiProfile abi) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
        Object owner = new Object();
        var program = new ProgramDB("physical-inheritance", language, language.getDefaultCompilerSpec(), owner);
        try {
            int transaction = program.startTransaction("saved physical layouts");
            try {
                var manager = program.getDataTypeManager();
                var baseClass = program.getSymbolTable().createClass(program.getGlobalNamespace(), "Base", SourceType.USER_DEFINED);
                var childClass = program.getSymbolTable().createClass(program.getGlobalNamespace(), "Child", SourceType.USER_DEFINED);
                var base = (Structure) manager.resolve(new StructureDataType("BaseLayout", 1), DataTypeConflictHandler.DEFAULT_HANDLER);
                var proposed = new StructureDataType("ChildLayout", 16);
                proposed.insertBitFieldAt(0, 1, 0, UnsignedIntegerDataType.dataType, 3, "flags", "curated bits");
                proposed.replaceAtOffset(4, new TypedefDataType("Count", IntegerDataType.dataType), 4, "count", "curated alias");
                proposed.replaceAtOffset(8, new PointerDataType(null, 8, manager), 8, "pointer", "unspecified pointee");
                var child = (Structure) manager.resolve(proposed, DataTypeConflictHandler.DEFAULT_HANDLER);
                require(child.getLength() == 16, "fixture changed class extent");
                var bits = (BitFieldDataType) child.getComponentAt(0).getDataType();
                require(bits.getStorageSize() == 1 && bits.getBitSize() == 3 && bits.getBitOffset() == 0,
                    "fixture lacks exact one-byte bit-field storage");
                var alias = (TypeDef) child.getComponentAt(4).getDataType();
                long aliasId = alias.getUniversalID().getValue();
                var pointer = (Pointer) child.getComponentAt(8).getDataType();
                require(pointer.getDataType() == null, "pointer fixture unexpectedly has a pointee");
                GhidraClassBindings.save(program, baseClass, base, "base", TaskMonitor.DUMMY);
                GhidraClassBindings.save(program, childClass, child, "child", TaskMonitor.DUMMY);
                var model = new InheritanceModel(abi, List.of(new Base(childClass.getID(), baseClass.getID(), 0,
                    Access.PUBLIC, new FixedBase(0, 1), "explicit base layout")), List.of());
                GhidraInheritanceBindings.save(program, model, TaskMonitor.DUMMY);
                String original = encoded(program);
                valid(program, model, original);

                child.getComponentAt(0).setFieldName("renamed_flags");
                child.getComponentAt(4).setComment("display-only annotation");
                alias.setName("RenamedCount");
                valid(program, model, original);
                GhidraInheritanceBindings.save(program, model, TaskMonitor.DUMMY);
                require(encoded(program).equals(original), "display-only edits changed the physical snapshot");

                for (int[] layout : List.of(new int[] {1, 3}, new int[] {0, 4})) {
                    child.deleteAtOffset(0);
                    child.insertBitFieldAt(0, 1, layout[0], UnsignedIntegerDataType.dataType, layout[1], "flags", null);
                    require(child.getLength() == 16, "bit-field change altered outer extent");
                    rejected(program, original);
                    child.deleteAtOffset(0);
                    child.insertBitFieldAt(0, 1, 0, UnsignedIntegerDataType.dataType, 3, "flags", null);
                    valid(program, model, original);
                }

                alias.replaceWith(new TypedefDataType(alias.getName(), UnsignedIntegerDataType.dataType));
                require(alias.getUniversalID().getValue() == aliasId && alias.getLength() == 4,
                    "alias control changed identity or extent instead of its base type");
                rejected(program, original);
                alias.replaceWith(new TypedefDataType(alias.getName(), IntegerDataType.dataType));
                valid(program, model, original);

                child.replaceAtOffset(8, new PointerDataType(IntegerDataType.dataType, 8, manager), 8, "pointer", null);
                require(child.getLength() == 16 && child.getComponentAt(8).getLength() == 8,
                    "pointee control changed physical pointer extent");
                rejected(program, original);
                child.replaceAtOffset(8, pointer, 8, "pointer", null);
                valid(program, model, original);
                var typedPointer = manager.resolve(new PointerDataType(IntegerDataType.dataType, 8, manager),
                    DataTypeConflictHandler.DEFAULT_HANDLER);
                child.replaceAtOffset(8, typedPointer, 8, "pointer", null);
                GhidraInheritanceBindings.save(program, model, TaskMonitor.DUMMY);
                String typedRecord = encoded(program);
                valid(program, model, typedRecord);
                child.replaceAtOffset(8, new PointerDataType(UnsignedIntegerDataType.dataType, 8, manager), 8, "pointer", null);
                rejected(program, typedRecord);
                child.replaceAtOffset(8, typedPointer, 8, "pointer", null);
                valid(program, model, typedRecord);
            }
            finally { program.endTransaction(transaction, false); }
        }
        finally { program.flushEvents(); program.release(owner); }
    }

    private static void valid(ProgramDB program, InheritanceModel expected, String encoded) throws Exception {
        long modification = program.getModificationNumber();
        var messages = new ArrayList<String>();
        var actual = GhidraInheritanceBindings.read(program, TaskMonitor.DUMMY, messages::add);
        require(actual.status() == GhidraInheritanceBindings.Status.VALID && actual.model().equals(expected) && messages.isEmpty(),
            "unchanged/restored physical layout lost saved relationships: " + messages);
        require(encoded(program).equals(encoded) && program.getModificationNumber() == modification,
            "valid read rewrote analyst evidence");
    }

    private static void rejected(ProgramDB program, String encoded) throws Exception {
        long modification = program.getModificationNumber();
        var messages = new ArrayList<String>();
        var actual = GhidraInheritanceBindings.read(program, TaskMonitor.DUMMY, messages::add);
        require(actual.status() == GhidraInheritanceBindings.Status.REJECTED && actual.model() == null &&
            messages.equals(List.of("Omitted explicit inheritance: saved inheritance identity, layout or method snapshot is stale")),
            "changed member geometry retained saved relationships: " + actual + " " + messages);
        require(encoded(program).equals(encoded) && program.getModificationNumber() == modification,
            "stale read repaired or removed analyst evidence");
    }

    private static String encoded(ProgramDB program) {
        return program.getOptions(GhidraInheritanceBindings.OPTIONS_NAME).getString(GhidraInheritanceBindings.KEY, null);
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
