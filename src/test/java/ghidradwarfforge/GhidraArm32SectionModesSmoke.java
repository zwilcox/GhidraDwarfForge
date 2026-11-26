package ghidradwarfforge;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.elf.Arm32SectionModes;
import ghidradwarfforge.elf.Arm32SectionModesSmoke;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.nativeapi.DwarfTarget;

/** Real listing and immutable decode context, with controlled inconsistent current contexts. */
public final class GhidraArm32SectionModesSmoke {
    private static final DwarfTarget TARGET = new DwarfTarget("arm", "arm", 4, true, "ARM");
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        var input = Files.createTempFile("arm-mapping-extraction-", ".elf");
        Files.write(input, Arm32SectionModesSmoke.fixture());
        var image = ElfImage.read(input);
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("ARM:LE:32:v8"));
        Object owner = new Object();
        var program = new ProgramDB("section-modes", language, language.getDefaultCompilerSpec(), owner);
        try {
            int transaction = program.startTransaction("mixed function and explicit literal");
            var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(Arm32SectionModesSmoke.START);
            program.getMemory().createInitializedBlock(".text", start, 44, (byte) 0, TaskMonitor.DUMMY, false).setExecute(true);
            program.getMemory().setBytes(start, HexFormat.of().parseHex(Arm32SectionModesSmoke.CODE));
            for (int[] region : new int[][] { {0, 16, 0}, {16, 8, 1}, {24, 16, 0} }) {
                var body = new AddressSet(start.add(region[0]), start.add(region[0] + region[1] - 1));
                program.getProgramContext().setValue(program.getRegister("TMode"), body.getMinAddress(),
                    body.getMaxAddress(), BigInteger.valueOf(region[2]));
                require(new DisassembleCommand(body.getMinAddress(), body, false).applyTo(program, TaskMonitor.DUMMY),
                    "mixed fixture decode");
            }
            program.getListing().createData(start.add(40), Undefined4DataType.dataType);
            program.getFunctionManager().createFunction("mixed", start, new AddressSet(start, start.add(39)), SourceType.USER_DEFINED);
            program.endTransaction(transaction, true);
            require(extract(program, image, 0, TaskMonitor.DUMMY, new ArrayList<>()).equals(List.of(Arm32SectionModesSmoke.evidence())),
                "exact complete section evidence includes explicit undefined4 data");
            int added = program.startTransaction("analyst block outside the original ELF");
            try {
                var outside = start.add(0x200000);
                program.getMemory().createInitializedBlock("analysis_only", outside, 4, (byte) 0,
                    TaskMonitor.DUMMY, false).setExecute(true);
                program.getFunctionManager().createFunction("analysis_only", outside,
                    new AddressSet(outside, outside.add(3)), SourceType.USER_DEFINED);
                var admitted = GhidraFunctionSymbols.extractDetailed(program, TaskMonitor.DUMMY, ignored -> { }, 0, image);
                require(admitted.functions().size() == 1 && admitted.functions().getFirst().name().equals("mixed") &&
                    admitted.skippedFunctions().equals(List.of(new GhidraFunctionSymbols.SkippedFunction("analysis_only",
                        GhidraFunctionSymbols.SkipReason.UNMAPPED_MEMORY))),
                    "ELF load-range admission lost the original function or exported analysis-only memory");
            }
            finally { program.endTransaction(added, false); }
            allocationBoundaries(program, image, start);
            transaction = program.startTransaction("literal is unknown");
            try {
                program.getListing().clearCodeUnits(start.add(40), start.add(43), false);
                omitted(program, image, "unknown bytes");
            }
            finally { program.endTransaction(transaction, false); }
            transaction = program.startTransaction("instruction hole");
            try {
                program.getListing().clearCodeUnits(start.add(18), start.add(19), false);
                omitted(program, image, "unknown bytes");
            }
            finally { program.endTransaction(transaction, false); }
            transaction = program.startTransaction("changed literal byte");
            try {
                program.getMemory().setByte(start.add(40), (byte) 0x35);
                var evidence = extract(program, image, 0, TaskMonitor.DUMMY, new ArrayList<>());
                var messages = new ArrayList<String>();
                require(Arm32SectionModes.plan(image, evidence, List.of(), () -> false, messages::add).isEmpty()
                    && messages.stream().anyMatch(m -> m.contains("listing bytes differ")), "original-byte binding rejects edited literal");
            }
            finally { program.endTransaction(transaction, false); }
            var register = program.getRegister("TMode");
            omitted(context(program, start.add(17), new RegisterValue(register)), image, "unknown or inconsistent");
            omitted(context(program, start.add(16), new RegisterValue(register, BigInteger.ZERO)), image, "instruction length");
            omitted(context(program, start.add(0), new RegisterValue(register, BigInteger.ONE)), image, "stored instruction mode");
            var fullPolls = new AtomicInteger();
            extract(program, image, 0, new TaskMonitorAdapter(true) {
                @Override
                public void checkCancelled() { fullPolls.incrementAndGet(); }
            }, new ArrayList<>());
            require(fullPolls.get() > 50, "cancellation fixture reaches extraction and byte checks");
            for (int stop = 1; stop <= fullPolls.get(); stop++) {
                final int stopAt = stop;
                var failure = new CancelledException("mapping cancellation");
                var calls = new AtomicInteger();
                var monitor = new TaskMonitorAdapter(true) {
                    @Override
                    public void checkCancelled() throws CancelledException {
                        if (calls.incrementAndGet() == stopAt) throw failure;
                    }
                };
                try { extract(program, image, 0, monitor, new ArrayList<>()); throw new AssertionError("cancel ignored " + stop); }
                catch (CancelledException actual) { require(actual == failure, "cancellation propagated unchanged"); }
            }
            var runtime = new IllegalArgumentException("monitor runtime identity");
            var calls = new AtomicInteger();
            var monitor = new TaskMonitorAdapter(true) {
                @Override
                public void checkCancelled() {
                    if (calls.incrementAndGet() == 50) throw runtime;
                }
            };
            try { extract(program, image, 0, monitor, new ArrayList<>()); throw new AssertionError("runtime monitor swallowed"); }
            catch (IllegalArgumentException actual) { require(actual == runtime, "runtime monitor identity retained"); }
            transaction = program.startTransaction("rebase entire program");
            try {
                program.setImageBase(program.getAddressFactory().getDefaultAddressSpace().getAddress(0x200000), true);
                require(extract(program, image, 0x200000, TaskMonitor.DUMMY, new ArrayList<>())
                    .equals(List.of(Arm32SectionModesSmoke.evidence())), "rebasing normalizes section evidence");
            }
            finally { program.endTransaction(transaction, false); }
        }
        finally {
            program.release(owner);
            Files.delete(input);
        }
        System.out.println("ghidra-arm32-section-modes-smoke=PASS checks=" + checks);
    }

    private static void allocationBoundaries(ProgramDB program, ElfImage original, Address start)
            throws Exception {
        var baseline = List.of(Arm32SectionModesSmoke.evidence());
        // Each tuple is section type, address displacement, file displacement and
        // extent. Only the tiny metadata changes; large NOBITS extents allocate no payload.
        int[][] cases = {
            {1, 2, 2, 42}, // begins inside the first ARM instruction
            {1, 0, 0, 42}, // ends inside the explicit four-byte literal
            {1, 0, 0, 48}, // mapped original allocation exceeds saved initialized memory
            {8, 0, 0, 44},
            {8, 0, 0, 256 * 1024 * 1024},
            {8, 0, 0, 256 * 1024 * 1024 + 1}
        };
        String[] reasons = {"not exactly tiled", "not exactly tiled", "unmapped or uninitialized",
            "not completely file-backed", "not completely file-backed", "mapping byte budget exceeded"};
        var path = Files.createTempFile("arm-mapping-allocation-", ".elf");
        try {
            for (int index = 0; index < cases.length; index++) {
                byte[] bytes = Arm32SectionModesSmoke.fixture();
                var fields = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
                int row = fields.getInt(32) + 40;
                fields.putInt(row + 4, cases[index][0]);
                fields.putInt(row + 12, (int) Arm32SectionModesSmoke.START + cases[index][1]);
                fields.putInt(row + 16, 0x100 + cases[index][2]);
                fields.putInt(row + 20, cases[index][3]);
                Files.write(path, bytes);
                var changed = ElfImage.read(path);
                long modification = program.getModificationNumber();
                omitted(program, changed, reasons[index]);
                require(program.getModificationNumber() == modification, "allocation rejection changed saved program");
                require(java.util.Arrays.equals(bytes, Files.readAllBytes(path)), "allocation rejection changed ELF");
                require(extract(program, original, 0, TaskMonitor.DUMMY, new ArrayList<>()).equals(baseline),
                    "rejected allocation contaminated the complete mapping retry");
            }
        }
        finally { Files.delete(path); }

        var selected = GhidraFunctionSymbols.extract(program, TaskMonitor.DUMMY, ignored -> { }, 0);
        for (long delta : new long[] {-Arm32SectionModesSmoke.START - 1,
                0x1_0000_0000L - Arm32SectionModesSmoke.START, Long.MAX_VALUE}) {
            var messages = new ArrayList<String>();
            long modification = program.getModificationNumber();
            require(GhidraArm32SectionModes.extract(program, original, selected, TARGET, delta,
                TaskMonitor.DUMMY, messages::add).isEmpty(), "invalid selection coordinate cannot wrap");
            require(messages.size() == 1 && messages.getFirst().startsWith("Omitted ARM32 section mapping selection for mixed:"),
                "selection address failure has a function-specific diagnostic");
            require(program.getModificationNumber() == modification, "selection address check changed program");
        }
        var messages = new ArrayList<String>();
        require(GhidraArm32SectionModes.extract(program, original,
            java.util.Collections.nCopies(16 * 1024 * 1024 + 1, selected.getFirst()), TARGET, 0,
            TaskMonitor.DUMMY, messages::add).isEmpty() && messages.size() == 1 &&
            messages.getFirst().contains("selection comparison budget exceeded"),
            "first selection comparison excess refused without expanding the virtual list");

        int transaction = program.startTransaction("literal became uninitialized");
        try {
            var memory = program.getMemory();
            memory.split(memory.getBlock(start), start.add(40));
            memory.convertToUninitialized(memory.getBlock(start.add(40)));
            require(!memory.getBlock(start.add(40)).isInitialized(), "literal fixture actually uninitialized");
            long modification = program.getModificationNumber();
            omitted(program, original, "unmapped or uninitialized");
            require(program.getModificationNumber() == modification, "uninitialized refusal changed program");
        }
        finally { program.endTransaction(transaction, false); }

        transaction = program.startTransaction("selected mixed function removed");
        try {
            require(program.getFunctionManager().removeFunction(start), "mixed function removed");
            messages.clear();
            long modification = program.getModificationNumber();
            require(GhidraArm32SectionModes.extract(program, original, selected, TARGET, 0,
                TaskMonitor.DUMMY, messages::add).isEmpty() && messages.isEmpty(),
                "removed selection cannot authorize a section mapping");
            require(program.getModificationNumber() == modification, "removed selection check changed program");
        }
        finally { program.endTransaction(transaction, false); }
        omitted(context(program, start, new RegisterValue(program.getRegister("TMode"))), original, "instruction TMode is unknown");
        require(extract(program, original, 0, TaskMonitor.DUMMY, new ArrayList<>()).equals(baseline),
            "saved mapping is unchanged after all admission controls");
        System.out.println("arm-section-allocation-boundaries=PASS");
    }

    private static Program context(Program real, Address at, RegisterValue value) {
        var altered = (ProgramContext) Proxy.newProxyInstance(ProgramContext.class.getClassLoader(),
            new Class<?>[] { ProgramContext.class }, (proxy, method, args) -> {
                if (method.getName().equals("getRegisterValue") && args[0].equals(value.getRegister()) && args[1].equals(at)) return value;
                try { return method.invoke(real.getProgramContext(), args); }
                catch (InvocationTargetException failure) { throw failure.getCause(); }
            });
        return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(), new Class<?>[] { Program.class },
            (proxy, method, args) -> {
                if (method.getName().equals("getProgramContext")) return altered;
                try { return method.invoke(real, args); }
                catch (InvocationTargetException failure) { throw failure.getCause(); }
            });
    }

    private static List<Arm32SectionModes.Evidence> extract(Program program, ElfImage image, long delta,
            TaskMonitor monitor, List<String> messages) throws Exception {
        var functions = GhidraFunctionSymbols.extract(program, TaskMonitor.DUMMY, ignored -> { }, delta);
        return GhidraArm32SectionModes.extract(program, image, functions, TARGET, delta, monitor, messages::add);
    }

    private static void omitted(Program program, ElfImage image, String reason) throws Exception {
        var messages = new ArrayList<String>();
        require(extract(program, image, 0, TaskMonitor.DUMMY, messages).isEmpty() &&
            messages.stream().anyMatch(m -> m.contains(reason)), "precise omission " + reason + ": " + messages);
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
