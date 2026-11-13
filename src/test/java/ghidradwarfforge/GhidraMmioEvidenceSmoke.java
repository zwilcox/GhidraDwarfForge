package ghidradwarfforge;

import java.io.File;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;

import db.DBHandle;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.MutabilitySettingsDefinition;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;

/** Saved Ghidra evidence for MMIO policy; not an export or hardware-access test. */
public final class GhidraMmioEvidenceSmoke {
    private static final long BASE = 0x40000000L;
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (String id : List.of("x86:LE:64:default", "ARM:LE:32:Cortex", "MIPS:BE:32:default")) {
            var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(id));
            Object owner = new Object();
            var program = new ProgramDB("mmio-evidence", language, language.getDefaultCompilerSpec(), owner);
            var directory = Files.createTempDirectory("forge-mmio-evidence-");
            var saved = directory.resolve("saved.db");
            try {
                int tx = program.startTransaction("analyst peripheral evidence");
                try {
                    var space = program.getAddressFactory().getDefaultAddressSpace();
                    var memory = program.getMemory();
                    var block = memory.createUninitializedBlock("peripheral", space.getAddress(BASE), 32, false);
                    block.setPermissions(true, false, false);
                    block.setVolatile(true);
                    var type = new UnsignedIntegerDataType(program.getDataTypeManager());
                    for (int offset : List.of(0, 4, 8, 12)) {
                        var address = space.getAddress(BASE + offset);
                        var data = program.getListing().createData(address, type);
                        program.getSymbolTable().createLabel(address, "register_" + offset, SourceType.USER_DEFINED);
                        if (offset == 4) MutabilitySettingsDefinition.DEF.setChoice(data, MutabilitySettingsDefinition.VOLATILE);
                        if (offset == 8) MutabilitySettingsDefinition.DEF.setChoice(data, MutabilitySettingsDefinition.CONSTANT);
                        if (offset == 12) {
                            MutabilitySettingsDefinition.DEF.setChoice(data, MutabilitySettingsDefinition.VOLATILE);
                            MutabilitySettingsDefinition.DEF.setChoice(data, MutabilitySettingsDefinition.CONSTANT);
                        }
                    }
                    program.getSymbolTable().createLabel(space.getAddress(BASE), "status_alias", SourceType.USER_DEFINED);
                    var register = new UnionDataType(ghidra.program.model.data.CategoryPath.ROOT,
                        "RegisterView", program.getDataTypeManager());
                    register.add(type, "raw", null);
                    var aggregate = new StructureDataType("PeripheralView", 0, program.getDataTypeManager());
                    aggregate.add(register, "status", null);
                    aggregate.add(type, "counter", null);
                    var object = program.getListing().createData(space.getAddress(BASE + 16), aggregate);
                    MutabilitySettingsDefinition.DEF.setChoice(object, MutabilitySettingsDefinition.VOLATILE);
                    MutabilitySettingsDefinition.DEF.setChoice(object.getComponent(0).getDefaultSettings(),
                        MutabilitySettingsDefinition.CONSTANT);
                    MutabilitySettingsDefinition.DEF.setChoice(object.getComponent(1), MutabilitySettingsDefinition.VOLATILE);
                    var overlay = memory.createUninitializedBlock("overlay", space.getAddress(BASE), 4, true);
                    program.getListing().createData(overlay.getStart(), type);
                    program.getSymbolTable().createLabel(overlay.getStart(), "overlay_status", SourceType.USER_DEFINED);
                    memory.createByteMappedBlock("mapped_alias", space.getAddress(BASE + 0x100),
                        space.getAddress(BASE), 4, false);
                }
                finally { program.endTransaction(tx, true); }
                observe(program);
                program.getDBHandle().saveAs(saved.toFile(), false, TaskMonitor.DUMMY);
                byte[] before = Files.readAllBytes(saved);
                var modified = Files.getLastModifiedTime(saved);
                Object reader = new Object();
                DBHandle handle = new DBHandle(saved.toFile());
                ProgramDB reopened = null;
                try {
                    reopened = new ProgramDB(handle, OpenMode.IMMUTABLE, TaskMonitor.DUMMY, reader);
                    observe(reopened);
                }
                finally {
                    if (reopened == null) handle.close();
                    else reopened.release(reader);
                }
                require(Arrays.equals(before, Files.readAllBytes(saved)), "saved analysis bytes changed");
                require(modified.equals(Files.getLastModifiedTime(saved)), "saved analysis timestamp changed");
                System.out.println("mmio-evidence-profile=" + id + " PASS");
            }
            finally {
                program.release(owner);
                Files.deleteIfExists(saved);
                Files.delete(directory);
            }
        }
        System.out.println("ghidra-mmio-evidence=PASS checks=" + checks);
    }

    private static void observe(ProgramDB program) throws Exception {
        long modification = program.getModificationNumber();
        var space = program.getAddressFactory().getDefaultAddressSpace();
        var start = space.getAddress(BASE);
        var block = program.getMemory().getBlock(start);
        require(block.isLoaded() && !block.isInitialized(), "unknown peripheral bytes were initialized");
        require(block.isVolatile() && !block.isWrite(), "block attributes lost");
        var ordinary = program.getListing().getDataAt(start);
        require(!ordinary.isVolatile() && !ordinary.isConstant(), "block attributes became object qualifiers");
        var volatileData = program.getListing().getDataAt(start.add(4));
        require(volatileData.isVolatile() && !volatileData.isConstant(), "explicit volatile setting lost");
        var constantData = program.getListing().getDataAt(start.add(8));
        require(constantData.isConstant() && !constantData.isVolatile(), "explicit constant setting lost");
        var replaced = program.getListing().getDataAt(start.add(12));
        require(replaced.isConstant() && !replaced.isVolatile(), "mutability modes unexpectedly combine");
        var aggregate = program.getListing().getDataAt(start.add(16));
        require(MutabilitySettingsDefinition.DEF.getChoice(aggregate) == MutabilitySettingsDefinition.NORMAL,
            "unsupported structure instance setting unexpectedly accepted");
        require(!aggregate.isVolatile() && !aggregate.getComponent(0).isConstant(),
            "unsupported aggregate settings unexpectedly became native type qualifiers");
        require(aggregate.getComponent(1).isVolatile(), "supported scalar component qualifier lost");
        var labels = program.getSymbolTable().getSymbols(start);
        require(labels.length == 2 && Arrays.stream(labels).filter(s -> s.isPrimary()).count() == 1,
            "overlapping labels lost identity");
        var overlay = program.getMemory().getBlock("overlay");
        require(overlay.isOverlay() && overlay.getStart().getOffset() == BASE &&
            !overlay.getStart().equals(start), "overlay offset collapsed into physical address");
        var alias = program.getMemory().getBlock("mapped_alias");
        require(alias.isMapped() && !alias.isOverlay() && alias.getStart().getOffset() == BASE + 0x100,
            "mapped alias became an independent physical register");
        require(program.getModificationNumber() == modification, "observation modified program");
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
