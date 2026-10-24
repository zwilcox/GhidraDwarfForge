package ghidradwarfforge;

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import db.DBHandle;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.StackStorage;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** Real pinned stack-variable APIs and extraction; no native producer or guessed ranges. */
public final class StackFirstUseSmoke {
    private record Target(String language, String map, String code) {
    }

    private StackFirstUseSmoke() {
    }

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (Target target : List.of(
                new Target("x86:LE:64:default", "x86_64", "4883ec10904883c410c3"),
                new Target("AARCH64:LE:64:v8A", "aarch64", "ff4300d11f2003d5ff430091c0035fd6"),
                new Target("ARM:LE:32:v8", "arm", "00f020e31eff2fe1"),
                new Target("MIPS:BE:32:default", "mips", "0000000003e0000800000000"),
                new Target("MIPS:LE:32:default", "mipsel", "000000000800e00300000000"))) {
            check(target);
        }
        System.out.println("stack-first-use-smoke=PASS");
    }

    private static void check(Target target) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(target.language()));
        Object owner = new Object();
        ProgramDB program = new ProgramDB("stack-first-use", language,
            language.getDefaultCompilerSpec(), owner);
        var directory = Files.createTempDirectory("forge-stack-first-use-");
        var saved = directory.resolve("program.db");
        try {
            int transaction = program.startTransaction("stack first-use controls");
            try {
                byte[] code = HexFormat.of().parseHex(target.code());
                var start = language.getDefaultSpace().getAddress(0x1000);
                var body = new AddressSet(start, start.add(code.length - 1));
                var block = program.getMemory().createInitializedBlock("code", start,
                    code.length, (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(start, code);
                if (target.map().equals("arm")) {
                    program.getProgramContext().setValue(program.getRegister("TMode"), start,
                        body.getMaxAddress(), BigInteger.ZERO);
                }
                require(new DisassembleCommand(start, body, true).applyTo(program, TaskMonitor.DUMMY),
                    "fixture instructions did not decode");
                Function function = program.getFunctionManager().createFunction("fixture", start,
                    body, SourceType.USER_DEFINED);
                var type = new IntegerDataType(program.getDataTypeManager());
                var stack = program.getAddressFactory().getStackSpace();
                try {
                    new LocalVariableImpl("constructor", 4, type, stack.getAddress(-4),
                        program, SourceType.USER_DEFINED);
                    throw new AssertionError("nonzero stack constructor unexpectedly succeeded");
                }
                catch (InvalidInputException expected) {
                    require(expected.getMessage().contains("firstUseOffset of 0"), expected.getMessage());
                }
                var beforeInsertion = new LocalVariableImpl("before_insertion", type, -8,
                    program, SourceType.USER_DEFINED);
                beforeInsertion.setFirstUseOffset(4);
                try {
                    function.addLocalVariable(beforeInsertion, SourceType.USER_DEFINED);
                    throw new AssertionError("nonzero stack insertion unexpectedly succeeded");
                }
                catch (InvalidInputException expected) {
                    require(expected.getMessage().contains("firstUseOffset of 0"), expected.getMessage());
                }
                var local = (LocalVariable) function.addLocalVariable(new LocalVariableImpl(
                    "curated_stack", type, -4, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                var parameter = new ParameterImpl("stack_argument", type,
                    new VariableStorage(program, new Varnode(stack.getAddress(16), 4)),
                    program, SourceType.USER_DEFINED);
                function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true,
                    SourceType.USER_DEFINED, parameter);
                require(GhidraVariableStorage.stableParameter(program, function, parameter,
                    TargetRegisterMap.forTarget(target.map()), TaskMonitor.DUMMY).equals(new StackStorage(16)),
                    "stack parameter convention changed");
                var baseline = extract(program, function, target, 0);
                for (int firstUse : new int[] { 4, 1, -1, code.length + 4,
                        Integer.MIN_VALUE, Integer.MAX_VALUE }) {
                    require(local.setFirstUseOffset(firstUse), "setter refused curated first-use");
                    require(function.getLocalVariables().length == 1 &&
                        function.getLocalVariables()[0].getFirstUseOffset() == firstUse,
                        "stored first-use was reset or local identity changed");
                    extract(program, function, target, firstUse);
                }
                local.setFirstUseOffset(0);
                require(extract(program, function, target, 0).equals(baseline),
                    "restoring zero first-use did not restore the existing model");
                var cancelled = new TaskMonitorAdapter(true);
                cancelled.cancel();
                try {
                    GhidraTypeGraph.extract(program, List.of(symbol(function)), target.map(), 0,
                        cancelled, message -> { });
                    throw new AssertionError("cancelled extraction completed");
                }
                catch (CancelledException expected) {
                    // Cancellation is checked by the real extraction traversal.
                }
                local.setFirstUseOffset(4);
            }
            finally {
                program.endTransaction(transaction, true);
            }
            program.getDBHandle().saveAs(saved.toFile(), false, TaskMonitor.DUMMY);
            byte[] savedHash = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(saved));
            Object reopenedOwner = new Object();
            DBHandle handle = new DBHandle(saved.toFile());
            ProgramDB reopened = null;
            try {
                reopened = new ProgramDB(handle, OpenMode.IMMUTABLE, TaskMonitor.DUMMY, reopenedOwner);
                var function = reopened.getFunctionManager().getFunctionAt(
                    reopened.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000));
                require(function != null && function.getLocalVariables().length == 1 &&
                    function.getLocalVariables()[0].getFirstUseOffset() == 4,
                    "fresh database reopen lost the explicit nonzero stack first-use");
                extract(reopened, function, target, 4);
            }
            finally {
                if (reopened != null) {
                    reopened.release(reopenedOwner);
                }
                else {
                    handle.close();
                }
            }
            require(Arrays.equals(savedHash,
                MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(saved))),
                "read-only database proof changed its saved input");
            System.out.println("stack-first-use=" + target.language() + " PASS");
        }
        finally {
            program.release(owner);
            Files.deleteIfExists(saved);
            Files.deleteIfExists(directory);
        }
    }

    private static VariableStorageModel extract(ProgramDB program, Function function,
            Target target, int firstUse) throws Exception {
        var messages = new ArrayList<String>();
        var model = GhidraTypeGraph.extract(program, List.of(symbol(function)), target.map(), 0,
            TaskMonitor.DUMMY, messages::add);
        require(model.functions().size() == 1 && model.functions().get(0).locals().size() == 1,
            "local declaration was dropped or duplicated");
        var declaration = model.functions().get(0).locals().get(0);
        require(declaration.name().equals("curated_stack") && declaration.byteSize() == 4 &&
            declaration.firstUseOffset() == firstUse && declaration.storageAssigned() &&
            declaration.source().equals("USER_DEFINED") && declaration.type() != null,
            "curated local metadata changed: " + declaration);
        var locations = model.variableStorage().variables();
        require(locations.size() == 2, "parameter or local location model was dropped");
        var local = locations.stream().filter(variable -> variable.name().equals("curated_stack"))
            .findFirst().orElseThrow();
        var parameter = locations.stream().filter(variable -> variable.name().equals("stack_argument"))
            .findFirst().orElseThrow();
        require(!parameter.locations().isEmpty() && parameter.locations().stream()
            .allMatch(location -> location.storage().available()), "stack parameter location changed");
        if (firstUse == 0) {
            require(!local.locations().isEmpty() && local.locations().stream()
                .allMatch(location -> location.storage().available()), "ordinary stack location was omitted");
            require(messages.stream().noneMatch(message -> message.startsWith("Omitted location")),
                "ordinary stack convention acquired an omission diagnostic");
        }
        else {
            require(local.locations().size() == 1 &&
                local.locations().get(0).start() == function.getEntryPoint().getOffset() &&
                local.locations().get(0).end() == function.getBody().getMaxAddress().getOffset() + 1,
                "unsupported first-use was clipped into a guessed interval");
            var storage = local.locations().get(0).storage();
            require(storage instanceof UnavailableStorage unavailable &&
                unavailable.reason() == OmissionReason.UNKNOWN_LIFETIME &&
                unavailable.diagnostic().equals("stack local has unsupported nonzero first-use offset " +
                    firstUse + "; its lifetime is not established"), "unexpected stack lifetime policy: " + storage);
            require(messages.stream().filter(message -> message.equals(
                "Omitted location for fixture::curated_stack: " +
                    ((UnavailableStorage) storage).diagnostic())).count() == 1,
                "unsupported stack first-use diagnostic was lost or duplicated");
        }
        return model.variableStorage();
    }

    private static FunctionSymbol symbol(Function function) {
        return new FunctionSymbol(function.getName(), function.getEntryPoint().getOffset(),
            function.getBody().getNumAddresses());
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
