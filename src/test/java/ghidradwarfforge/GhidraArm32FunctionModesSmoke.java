package ghidradwarfforge;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.code.InstructionDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.elf.ElfFunctionModeCue;
import ghidradwarfforge.elf.ElfFunctionAlias;
import ghidradwarfforge.nativeapi.DwarfTarget;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** Real pinned instruction/prototype context and controlled inconsistent metadata. */
public final class GhidraArm32FunctionModesSmoke {
    private static final DwarfTarget TARGET = new DwarfTarget("arm", "arm", 4, true, "ARM");
    private static int checks;

    private GhidraArm32FunctionModesSmoke() {
    }

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        try (Fixture fixture = fixture()) {
            controls(fixture);
            aliasControls(fixture);
        }
        System.out.println("ghidra-arm32-function-modes-smoke=PASS checks=" + checks);
    }

    private static void aliasControls(Fixture f) throws Exception {
        int transaction = f.program().startTransaction("explicit alias mode controls");
        try {
            for (long entry : new long[] { 0x1000, 0x1020, 0x1040 }) {
                f.program().getSymbolTable().createLabel(f.address(entry), "alternate_" + entry,
                    SourceType.USER_DEFINED);
            }
            var aliases = aliases(f.program());
            require(aliases.size() == 3, "explicit aliases were not extracted");
            var messages = new ArrayList<String>();
            var cues = GhidraArm32FunctionModes.extractAliases(f.program(), aliases, TARGET, 0,
                TaskMonitor.DUMMY, messages::add);
            require(cues.size() == 3 && messages.isEmpty(), "alias evidence missing: " + messages);
            require(cues.equals(extract(f.program(), symbols(f.program()), new ArrayList<>(), TaskMonitor.DUMMY)),
                "ordinary alias mode evidence differs from primary proof");
            var armOnly = GhidraArm32FunctionModes.extractAliases(f.program(),
                aliases.stream().filter(a -> a.address() == 0x1020).toList(), TARGET, 0,
                TaskMonitor.DUMMY, messages::add);
            require(armOnly.size() == 1 && armOnly.get(0).symbolValue() == 0x1020,
                "ARM-only alias incorrectly requires a Thumb neighbor");
            var duplicate = new ArrayList<>(aliases);
            duplicate.add(aliases.get(0));
            java.util.Collections.reverse(duplicate);
            require(GhidraArm32FunctionModes.extractAliases(f.program(), duplicate, TARGET, 0,
                TaskMonitor.DUMMY, messages::add).equals(cues), "alias evidence duplicated or reordered");
            var shifted = aliases.stream().map(a -> new ElfFunctionAlias(a.name(), a.owner(), a.address() - 0x1000,
                a.ranges().stream().map(r -> new ElfFunctionAlias.CodeRange(r.address() - 0x1000,
                    r.size(), r.codeSha256())).toList())).toList();
            var rebased = GhidraArm32FunctionModes.extractAliases(f.program(), shifted, TARGET, 0x1000,
                TaskMonitor.DUMMY, messages::add);
            require(rebased.get(0).address() == 0 && rebased.get(0).symbolValue() == 1 &&
                rebased.get(0).codeSha256().equals(cues.get(0).codeSha256()), "alias rebasing lost evidence");
            var bad = new ElfFunctionAlias("bad", "thumb", 0x1000, 4, "0".repeat(64));
            aliasOmitted(f.program(), List.of(bad), "code changed after extraction");
            var register = f.program().getRegister("TMode");
            aliasOmitted(context(f.program(), 0x1000, 0x1003, new RegisterValue(register)), aliases,
                "entry TMode is not fully known");
            aliasOmitted(context(f.program(), 0x1001, 0x1001, new RegisterValue(register)), aliases,
                "unknown or mixed");
            aliasOmitted(context(f.program(), 0x1040, 0x1045, new RegisterValue(register, BigInteger.ZERO)),
                aliases, "stored instruction decode mode");
            require(GhidraArm32FunctionModes.extractAliases(program(f.program(), "getRegister",
                new AssertionError("other target accessed ARM mode")), aliases,
                new DwarfTarget("aarch64", "arm64", 8, true, "AARCH64"), 0,
                TaskMonitor.DUMMY, messages::add).isEmpty(), "other target received alias mode evidence");
            for (int stop : new int[] { 1, 3, 8, 14, 30 }) {
                var failure = new CancelledException("alias evidence cancelled");
                var polls = new AtomicInteger();
                var monitor = new TaskMonitorAdapter(true) {
                    @Override
                    public void checkCancelled() throws CancelledException {
                        if (polls.incrementAndGet() == stop) throw failure;
                    }
                };
                try {
                    GhidraArm32FunctionModes.extractAliases(f.program(), aliases, TARGET, 0, monitor, messages::add);
                    throw new AssertionError("alias cancellation ignored at " + stop);
                }
                catch (CancelledException actual) {
                    require(actual == failure, "alias cancellation identity changed");
                }
            }

            f.bytes(0x1080, "02207047");
            f.decode(0x1080, 4, 1);
            var split = new AddressSet(f.thumb().getBody());
            split.add(f.address(0x1080), f.address(0x1083));
            f.thumb().setBody(split);
            aliasOmitted(f.program(), aliases, "alias owner or body changed");
            var splitCues = GhidraArm32FunctionModes.extractAliases(f.program(), aliases(f.program()),
                TARGET, 0, TaskMonitor.DUMMY, messages::add);
            require(splitCues.get(0).address() == 0x1000 && splitCues.get(0).size() == 4,
                "discontiguous alias bridged a gap or lost its entry range");
            require(f.program().getFunctionManager().removeFunction(f.address(0x1000)), "remove original entry");
            var interior = f.program().getFunctionManager().createFunction("interior", f.address(0x1002),
                split, SourceType.USER_DEFINED);
            f.program().getSymbolTable().createLabel(interior.getEntryPoint(), "interior_alias", SourceType.USER_DEFINED);
            var interiorCues = GhidraArm32FunctionModes.extractAliases(f.program(), aliases(f.program()),
                TARGET, 0, TaskMonitor.DUMMY, messages::add);
            var cue = interiorCues.stream().filter(c -> c.displayName().equals("interior")).findFirst().orElseThrow();
            require(cue.address() == 0x1000 && cue.size() == 4 && cue.symbolValue() == 0x1001,
                "interior-entry range proof changed its extent or mode");
        }
        finally {
            f.program().endTransaction(transaction, false);
        }
    }

    private static List<ElfFunctionAlias> aliases(Program program) throws Exception {
        return GhidraFunctionAliases.extract(program, symbols(program), 0, TaskMonitor.DUMMY, ignored -> { });
    }

    private static void aliasOmitted(Program program, List<ElfFunctionAlias> aliases, String reason) throws Exception {
        var messages = new ArrayList<String>();
        var cues = GhidraArm32FunctionModes.extractAliases(program, aliases, TARGET, 0, TaskMonitor.DUMMY, messages::add);
        require(cues.size() < aliases.size() && messages.stream().anyMatch(m -> m.contains(reason)),
            "missing alias omission: " + reason + ": " + messages);
    }

    private static void controls(Fixture f) throws Exception {
        var messages = new ArrayList<String>();
        var symbols = symbols(f.program());
        var cues = extract(f.program(), symbols, messages, TaskMonitor.DUMMY);
        require(cues.size() == 3 && messages.isEmpty(), "expected all three complete bodies: " + messages);
        require(cues.get(0).equals(new ElfFunctionModeCue("thumb", 0x1000, 4, 0x1001,
            hash("01207047"))), "Thumb pointer/code/digest differ");
        require(cues.get(1).equals(new ElfFunctionModeCue("arm", 0x1020, 8, 0x1020,
            hash("0100a0e31eff2fe1"))), "ARM pointer/code/digest differ");
        require(cues.get(2).size() == 6 && cues.get(2).symbolValue() == 0x1041,
            "mixed instruction widths did not tile Thumb body");
        var reversed = new ArrayList<>(symbols);
        java.util.Collections.reverse(reversed);
        require(extract(f.program(), reversed, new ArrayList<>(), TaskMonitor.DUMMY).equals(cues),
            "mode evidence order is not deterministic");
        try {
            cues.clear();
            throw new AssertionError("mutable result");
        }
        catch (UnsupportedOperationException expected) {
            checks++;
        }
        var relocated = GhidraArm32FunctionModes.extract(f.program(),
            GhidraFunctionSymbols.extract(f.program(), TaskMonitor.DUMMY, ignored -> { }, 0x1000),
            TARGET, 0x1000, TaskMonitor.DUMMY, ignored -> { });
        require(relocated.get(0).address() == 0 && relocated.get(0).symbolValue() == 1 &&
            relocated.get(0).codeSha256().equals(cues.get(0).codeSha256()),
            "rebase changed bytes or confused code with tagged pointer");

        Program noBodyAccess = program(f.program(), "getListing", new AssertionError("body scanned"));
        messages.clear();
        require(extract(noBodyAccess, List.of(symbols.get(1)), messages, TaskMonitor.DUMMY).isEmpty() &&
            messages.isEmpty(), "ARM-only path scanned bodies or emitted diagnostics");
        require(GhidraArm32FunctionModes.extract(program(f.program(), "getRegister",
            new AssertionError("non-ARM context accessed")), symbols,
            new DwarfTarget("aarch64", "arm64", 8, true, "AARCH64"), 0,
            TaskMonitor.DUMMY, messages::add).isEmpty(), "other target received mode cues");

        int transaction = f.program().startTransaction("temporary shape controls");
        try {
            var gap = new AddressSet(f.address(0x1000), f.address(0x1005));
            f.thumb().setBody(gap);
            omitted(f.program(), "thumb", "without decoded instructions");
            gap.delete(f.address(0x1002), f.address(0x1003));
            f.thumb().setBody(gap);
            omitted(f.program(), "thumb", "contiguous entry-first");
        }
        finally {
            f.program().endTransaction(transaction, false);
        }
        transaction = f.program().startTransaction("interior entry control");
        try {
            require(f.program().getFunctionManager().removeFunction(f.address(0x1000)),
                "entry-first function was not removed");
            f.program().getFunctionManager().createFunction("interior", f.address(0x1002),
                new AddressSet(f.address(0x1000), f.address(0x1003)), SourceType.USER_DEFINED);
            omitted(f.program(), "interior", "contiguous entry-first");
        }
        finally {
            f.program().endTransaction(transaction, false);
        }
        transaction = f.program().startTransaction("length override control");
        try {
            var instruction = f.program().getListing().getInstructionAt(f.address(0x1040));
            require(instruction.getLength() == 4, "length override control is not wide Thumb");
            instruction.setLengthOverride(2);
            require(instruction.isLengthOverridden(), "length override was not retained");
            omitted(f.program(), "anchor", "overridden instruction length");
        }
        finally {
            f.program().endTransaction(transaction, false);
        }
        transaction = f.program().startTransaction("mixed decoded mode control");
        try {
            f.bytes(0x1060, "40f201000100a0e31eff2fe1");
            f.decode(0x1060, 4, 1);
            f.decode(0x1064, 8, 0);
            f.function("mixed", 0x1060, 12);
            require(mode(f.program(), 0x1060) == 1 && mode(f.program(), 0x1064) == 0,
                "mixed-mode fixture lost its current context");
            omitted(f.program(), "mixed", "stored instruction decode mode");
        }
        finally {
            f.program().endTransaction(transaction, false);
        }

        var register = f.program().getRegister("TMode");
        var decoded = (InstructionDB) f.program().getListing().getInstructionAt(f.address(0x1040));
        require(decoded.getOriginalPrototypeContext(register.getBaseRegister())
            .getRegisterValue(register).getUnsignedValue().equals(BigInteger.ONE),
            "fixture lacks stored Thumb decode context");
        // Controlled current-context views retain actual decoded InstructionDB objects.
        // Instruction.getRegisterValue alone cannot distinguish these from a decoder's context.
        // A four-byte decoded Thumb instruction also fits ARM's length/alignment.
        // This reaches the stored-context check rather than failing earlier on size.
        Program changed = context(f.program(), 0x1040, 0x1045, new RegisterValue(register, BigInteger.ZERO));
        omitted(changed, "anchor", "stored instruction decode mode");
        require(decoded.getOriginalPrototypeContext(register.getBaseRegister())
            .getRegisterValue(register).getUnsignedValue().equals(BigInteger.ONE),
            "current-context control changed the stored prototype");
        omitted(context(f.program(), 0x1001, 0x1001, new RegisterValue(register)),
            "thumb", "unknown or mixed");
        Program allUnknown = context(f.program(), 0x1000, 0x1045, new RegisterValue(register));
        messages.clear();
        require(extract(allUnknown, symbols, messages, TaskMonitor.DUMMY).isEmpty() && messages.isEmpty(),
            "unknown-entry scope invented known Thumb evidence");

        transaction = f.program().startTransaction("ordinary memory write controls");
        try {
            byte old = f.program().getMemory().getByte(f.address(0x1000));
            try {
                f.program().getMemory().setByte(f.address(0x1000), (byte) (old ^ 1));
                throw new AssertionError("ordinary write changed decoded instruction bytes");
            }
            catch (MemoryAccessException expected) {
                require(f.program().getMemory().getByte(f.address(0x1000)) == old,
                    "rejected instruction write changed memory");
            }
            f.program().getListing().clearCodeUnits(f.address(0x1000), f.address(0x1001), false);
            f.program().getMemory().setByte(f.address(0x1000), (byte) (old ^ 1));
            require(f.program().getListing().getInstructionAt(f.address(0x1000)) == null,
                "patch control retained decoded instruction");
            omitted(f.program(), "thumb", "not exactly tiled");
        }
        finally {
            f.program().endTransaction(transaction, false);
        }
        Memory mismatched = (Memory) Proxy.newProxyInstance(Memory.class.getClassLoader(),
            new Class<?>[] { Memory.class }, (proxy, method, arguments) -> {
                Object value = invoke(f.program().getMemory(), method, arguments);
                if (method.getName().equals("getBytes") && arguments.length == 2 &&
                        arguments[0].equals(f.address(0x1000))) {
                    ((byte[]) arguments[1])[0] ^= 1;
                }
                return value;
            });
        omitted(program(f.program(), "getMemory", mismatched), "thumb", "bytes disagree");
        cancellation(f, symbols);
        var callback = new IllegalArgumentException("diagnostic callback marker");
        try {
            GhidraArm32FunctionModes.extract(changed, symbols, TARGET, 0, TaskMonitor.DUMMY,
                ignored -> { throw callback; });
            throw new AssertionError("diagnostic callback failure was lost");
        }
        catch (IllegalArgumentException actual) {
            require(actual == callback, "diagnostic failure identity changed");
        }
    }

    private static void cancellation(Fixture f, List<FunctionSymbol> symbols) throws Exception {
        for (int stop : new int[] { 1, 3, 8, 14 }) {
            var failure = new CancelledException("mode extraction cancelled");
            var polls = new AtomicInteger();
            var monitor = new TaskMonitorAdapter(true) {
                @Override
                public void checkCancelled() throws CancelledException {
                    if (polls.incrementAndGet() == stop) {
                        throw failure;
                    }
                }
            };
            try {
                extract(f.program(), symbols, new ArrayList<>(), monitor);
                throw new AssertionError("cancellation was ignored at " + stop);
            }
            catch (CancelledException actual) {
                require(actual == failure, "cancellation identity changed");
            }
        }
        var failure = new IllegalArgumentException("monitor runtime marker");
        var polls = new AtomicInteger();
        var monitor = new TaskMonitorAdapter(true) {
            @Override
            public void checkCancelled() {
                if (polls.incrementAndGet() == 8) {
                    throw failure;
                }
            }
        };
        try {
            extract(f.program(), symbols, new ArrayList<>(), monitor);
            throw new AssertionError("runtime monitor failure was lost");
        }
        catch (IllegalArgumentException actual) {
            require(actual == failure, "monitor runtime failure identity changed");
        }
    }

    private static Program context(Program real, long start, long end, RegisterValue value) {
        ProgramContext context = (ProgramContext) Proxy.newProxyInstance(ProgramContext.class.getClassLoader(),
            new Class<?>[] { ProgramContext.class }, (proxy, method, arguments) -> {
                if (method.getName().equals("getRegisterValue") &&
                        arguments[0].equals(value.getRegister())) {
                    long address = ((Address) arguments[1]).getOffset();
                    if (start <= address && address <= end) {
                        return value;
                    }
                }
                return invoke(real.getProgramContext(), method, arguments);
            });
        return program(real, "getProgramContext", context);
    }

    private static Program program(Program real, String name, Object replacement) {
        return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(), new Class<?>[] { Program.class },
            (proxy, method, arguments) -> {
                if (method.getName().equals(name)) {
                    if (replacement instanceof Error error) {
                        throw error;
                    }
                    return replacement;
                }
                return invoke(real, method, arguments);
            });
    }

    private static Object invoke(Object receiver, Method method, Object[] arguments) throws Throwable {
        try {
            return method.invoke(receiver, arguments);
        }
        catch (InvocationTargetException failure) {
            throw failure.getCause();
        }
    }

    private static void omitted(Program program, String name, String reason) throws Exception {
        var messages = new ArrayList<String>();
        var cues = extract(program, symbols(program), messages, TaskMonitor.DUMMY);
        require(cues.stream().noneMatch(cue -> cue.displayName().equals(name)) &&
            messages.stream().anyMatch(message -> message.contains("for " + name + ":") &&
                message.contains(reason)), "missing precise omission for " + name + ": " + messages);
    }

    private static List<FunctionSymbol> symbols(Program program) throws Exception {
        return GhidraFunctionSymbols.extract(program, TaskMonitor.DUMMY, ignored -> { }, 0);
    }

    private static List<ElfFunctionModeCue> extract(Program program, List<FunctionSymbol> symbols,
            List<String> messages, TaskMonitor monitor) throws Exception {
        return GhidraArm32FunctionModes.extract(program, symbols, TARGET, 0, monitor, messages::add);
    }

    private static int mode(Program program, long address) {
        return program.getProgramContext().getRegisterValue(program.getRegister("TMode"),
            program.getAddressFactory().getDefaultAddressSpace().getAddress(address)).getUnsignedValue().intValueExact();
    }

    private static String hash(String bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(HexFormat.of().parseHex(bytes)));
    }

    private static Fixture fixture() throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("ARM:LE:32:v8"));
        Object owner = new Object();
        var program = new ProgramDB("function-modes", language, language.getDefaultCompilerSpec(), owner);
        var result = new Fixture(program, owner);
        int transaction = program.startTransaction("decoded ARM/Thumb modes");
        boolean complete = false;
        try {
            program.getMemory().createInitializedBlock("code", result.address(0x1000), 0x100,
                (byte) 0, TaskMonitor.DUMMY, false).setExecute(true);
            result.bytes(0x1000, "01207047");
            result.decode(0x1000, 4, 1);
            result.function("thumb", 0x1000, 4);
            result.bytes(0x1020, "0100a0e31eff2fe1");
            result.decode(0x1020, 8, 0);
            result.function("arm", 0x1020, 8);
            result.bytes(0x1040, "40f201007047");
            result.decode(0x1040, 6, 1);
            result.function("anchor", 0x1040, 6);
            complete = true;
            return result;
        }
        finally {
            program.endTransaction(transaction, complete);
            if (!complete) {
                program.release(owner);
            }
        }
    }

    private record Fixture(ProgramDB program, Object owner) implements AutoCloseable {
        Address address(long value) {
            return program.getAddressFactory().getDefaultAddressSpace().getAddress(value);
        }
        Function thumb() {
            return program.getFunctionManager().getFunctionAt(address(0x1000));
        }
        void bytes(long start, String hex) throws Exception {
            program.getMemory().setBytes(address(start), HexFormat.of().parseHex(hex));
        }
        void decode(long start, int size, int mode) throws Exception {
            var body = new AddressSet(address(start), address(start + size - 1));
            program.getProgramContext().setValue(program.getRegister("TMode"),
                body.getMinAddress(), body.getMaxAddress(), BigInteger.valueOf(mode));
            require(new DisassembleCommand(body.getMinAddress(), body, false).applyTo(program, TaskMonitor.DUMMY),
                "fixture failed to decode at " + start);
        }
        void function(String name, long start, int size) throws Exception {
            program.getFunctionManager().createFunction(name, address(start),
                new AddressSet(address(start), address(start + size - 1)), SourceType.USER_DEFINED);
        }
        @Override
        public void close() {
            program.release(owner);
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        checks++;
    }
}
