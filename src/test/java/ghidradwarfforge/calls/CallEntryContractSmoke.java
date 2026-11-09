package ghidradwarfforge.calls;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.util.exception.CancelledException;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.GhidraCallParameters;
import ghidradwarfforge.GhidraTypeGraph;
import ghidradwarfforge.GhidraParameterAllocation;
import ghidradwarfforge.locations.VariableStorageModel.VariableKind;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;

/** Ordinary outgoing calls must not seed entry values at a split-frame label. */
public final class CallEntryContractSmoke {
    private static int checks;
    private static void require(boolean yes, String why) { if (!yes) throw new AssertionError(why); checks++; }
    private static String word(int value) {
        return HexFormat.of().formatHex(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array());
    }
    private static String transfer(boolean arm, boolean call, int from, int to) {
        return arm ? word((call ? 0x94000000 : 0x14000000) | (((to - from) >> 2) & 0x03ffffff)) :
            (call ? "e8" : "e9") + word(to - from - 5);
    }
    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])), new HeadlessGhidraApplicationConfiguration());
        Path output = Path.of(args[1]); Files.createDirectories(output);
        for (boolean arm : List.of(false, true)) {
            for (String mode : List.of("ordinary", "clean-tail", "dirty-tail", "annotated", "unselected", "interior", "patched-call", "fallthrough")) {
                check(arm, mode, output);
            }
        }
        System.out.println("call-entry-contract=PASS cases=16 checks=" + checks);
    }
    private static void check(boolean arm, String mode, Path output) throws Exception {
        String prefix = arm ? "fd7bbfa9" : "4883ec08";
        String returnCode = arm ? "c0035fd6" : "c3";
        String falling = mode.equals("fallthrough") ? (arm ? "1f2003d5" : "90") : "";
        int entryOffset = falling.length() / 2;
        byte[] caller = HexFormat.of().parseHex(falling + prefix + transfer(arm, true, 0x1004 + entryOffset, 0x2010) +
            (arm ? "fd7bc1a8" : "4883c408") + returnCode);
        String dirty = List.of("dirty-tail", "annotated").contains(mode) ? (arm ? "f37bbfa9" : "53") : "";
        int incomingAddress = 0x2000 + dirty.length() / 2;
        boolean ordinary = mode.equals("ordinary") || mode.equals("fallthrough");
        byte[] predecessor = HexFormat.of().parseHex(dirty + transfer(arm, ordinary, incomingAddress,
            mode.equals("interior") ? 0x1004 : 0x1000 + entryOffset) + (ordinary ? returnCode : ""));
        byte[] second = new byte[16 + returnCode.length() / 2];
        System.arraycopy(predecessor, 0, second, 0, predecessor.length);
        System.arraycopy(HexFormat.of().parseHex(returnCode), 0, second, 16, returnCode.length() / 2);
        byte[] original = GhidraTailStateProofSmoke.elf(arm, caller, second);
        Path path = output.resolve((arm ? "arm-" : "x86-") + mode + ".elf"); Files.write(path, original);
        var image = ElfImage.read(path);
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(arm ? "AARCH64:LE:64:v8A" : "x86:LE:64:default"));
        Object owner = new Object();
        var program = new ProgramDB("ordinary-entry", language,
            language.getCompilerSpecByID(new CompilerSpecID(arm ? "default" : "gcc")), owner);
        try {
            int tx = program.startTransaction("entry controls");
            try {
                var start = language.getDefaultSpace().getAddress(0x1000);
                var entry = start.add(entryOffset);
                var incoming = language.getDefaultSpace().getAddress(0x2000);
                var leaf = language.getDefaultSpace().getAddress(0x2010);
                program.getMemory().createInitializedBlock("caller", start, caller.length, (byte) 0, TaskMonitor.DUMMY, false).setExecute(true);
                program.getMemory().setBytes(start, caller);
                program.getMemory().createInitializedBlock("incoming", incoming, second.length, (byte) 0, TaskMonitor.DUMMY, false).setExecute(true);
                program.getMemory().setBytes(incoming, second);
                if (mode.equals("patched-call")) {
                    program.getMemory().setBytes(incoming, HexFormat.of().parseHex(transfer(arm, true, 0x2000, 0x1000)));
                }
                var body = new AddressSet(entry, start.add(caller.length - 1));
                var predecessorBody = new AddressSet(incoming, incoming.add(predecessor.length - 1));
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "caller decode");
                require(new DisassembleCommand(incoming, predecessorBody, true).applyTo(program, TaskMonitor.DUMMY), "incoming decode");
                var leafBody = new AddressSet(leaf, leaf.add(returnCode.length() / 2 - 1));
                require(new DisassembleCommand(leaf, leafBody, true).applyTo(program, TaskMonitor.DUMMY), "leaf decode");
                var function = program.getFunctionManager().createFunction("ordinary_caller", entry, body, SourceType.USER_DEFINED);
                if (entryOffset != 0) {
                    var fallingBody = new AddressSet(start, entry.previous());
                    require(new DisassembleCommand(start, fallingBody, true).applyTo(program, TaskMonitor.DUMMY), "fallthrough decode");
                    program.getFunctionManager().createFunction("falling_predecessor", start, fallingBody, SourceType.USER_DEFINED);
                }
                var predecessorFunction = program.getFunctionManager().createFunction("predecessor", incoming, predecessorBody, SourceType.USER_DEFINED);
                program.getFunctionManager().createFunction("leaf", leaf, leafBody, SourceType.USER_DEFINED);
                if (mode.equals("annotated")) program.getListing().getInstructionAt(incoming.add(dirty.length() / 2)).setFlowOverride(FlowOverride.CALL_RETURN);
                var selected = List.of("clean-tail", "dirty-tail", "annotated").contains(mode) ? List.of(function, predecessorFunction) : List.of(function);
                var proof = GhidraTailStateProof.verify(program, selected, image, 0, TaskMonitor.DUMMY);
                var values = GhidraCallArgumentFlow.analyze(program, proof, image, 0, TaskMonitor.DUMMY);
                boolean accepted = List.of("ordinary", "clean-tail").contains(mode);
                require(values.transfers().containsKey(entry.add(4)) == accepted,
                    (arm ? "arm/" : "x86/") + mode + " seeded an invalid entry state: " + values);
                require(proof.omissions().containsKey(entry) != accepted, "entry omission not recorded: " + mode);
                if (mode.equals("fallthrough")) require(proof.omissions().get(entry).contains("external fallthrough"), "missed actual fallthrough entry");
                if (mode.equals("patched-call")) require(proof.omissions().get(entry).contains("differs from original ELF"), "missed original-byte disagreement");
                var symbols = selected.stream().map(f -> new FunctionSymbol(f.getName(), f.getEntryPoint().getOffset(),
                    java.util.stream.StreamSupport.stream(f.getBody().spliterator(), false)
                        .map(r -> new FunctionRange(r.getMinAddress().getOffset(), r.getLength())).toList())).toList();
                var plan = GhidraCallSitePlan.recover(program, symbols, null, List.of(),
                    TargetRegisterMap.forElf(arm ? "aarch64" : "x86_64", image, () -> false), image, 0, TaskMonitor.DUMMY);
                var callerPlan = plan.plan().functions().stream().filter(f -> f.caller() == entry.getOffset()).findFirst().orElseThrow();
                require((callerPlan.completeness() == CallSitePlan.Completeness.ALL_CALLS) == accepted,
                    "entry contract did not constrain completeness: " + mode);
                require(callerPlan.sites().size() == 1 && !callerPlan.sites().getFirst().tail() &&
                    callerPlan.sites().getFirst().instructionAddress() == entry.add(4).getOffset(), "lost independently verified ordinary call");
                require(callerPlan.sites().getFirst().callee() == null && callerPlan.sites().getFirst().arguments().isEmpty(),
                    "invented unexported callee/formals");
                function.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true,
                    SourceType.USER_DEFINED, new ParameterImpl("incoming", IntegerDataType.dataType, program));
                var leafFunction = program.getFunctionManager().getFunctionAt(leaf);
                leafFunction.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true,
                    SourceType.USER_DEFINED, new ParameterImpl("received", IntegerDataType.dataType, program));
                var typedSymbols = new ArrayList<>(symbols);
                typedSymbols.add(new FunctionSymbol("leaf", leaf.getOffset(), List.of(new FunctionRange(leaf.getOffset(), leafBody.getNumAddresses()))));
                var entryRegisters = TargetRegisterMap.forElf(arm ? "aarch64" : "x86_64", image, () -> false);
                var entries = new ArrayList<GhidraCallParameters.Entry>();
                var types = GhidraTypeGraph.extract(program, typedSymbols, entryRegisters, 0, TaskMonitor.DUMMY, ignored -> { },
                    java.util.Map.of(), java.util.Map.of(), java.util.Map.of(), GhidraParameterAllocation.UNCHANGED, entries::add);
                var typed = GhidraCallSitePlan.recover(program, typedSymbols, types, entries, entryRegisters, image, 0, TaskMonitor.DUMMY);
                var parameter = typed.types().variableStorage().variables().stream().filter(v ->
                    v.functionAddress() == entry.getOffset() && v.kind() == VariableKind.PARAMETER && v.name().equals("incoming"))
                    .findFirst().orElseThrow();
                boolean availableEntry = parameter.locations().stream().anyMatch(r ->
                    r.start() <= entry.getOffset() && entry.getOffset() < r.end() && r.storage().available());
                // A recorded register location at the entry PC describes current
                // storage, not an inferred incoming call or historical value.
                // Rejected incoming paths must still suppress call-value facts.
                require(availableEntry, "lost recorded formal register storage at entry: " + mode);
                require(parameter.locations().stream().filter(r -> r.storage().available()).allMatch(r ->
                    r.start() == entry.getOffset() && r.end() == entry.getOffset() + 1),
                    "extended recorded storage into an unproved body lifetime: " + mode);
                var typedCaller = typed.plan().functions().stream().filter(f -> f.caller() == entry.getOffset()).findFirst().orElseThrow();
                require((typedCaller.completeness() == CallSitePlan.Completeness.ALL_CALLS) == accepted,
                    "formal register location invented a caller entry contract: " + mode);
                require(typedCaller.sites().size() == 1 && typedCaller.sites().getFirst().callee() == leaf.getOffset(),
                    "lost independently known ordinary callee identity: " + mode);
                require(typedCaller.sites().getFirst().arguments().size() == (accepted ? 1 : 0),
                    "formal register location changed justified call-value inference: " + mode);
                if (mode.equals("ordinary")) {
                    var registers = TargetRegisterMap.forElf(arm ? "aarch64" : "x86_64", image, () -> false);
                    int[] planPolls = {0};
                    var repeated = GhidraCallSitePlan.recover(program, symbols, null, List.of(), registers, image, 0,
                        new TaskMonitorAdapter(true) { @Override public void checkCancelled() { planPolls[0]++; } });
                    require(plan.equals(repeated), "non-deterministic call-site composition");
                    for (int index = 1; index <= planPolls[0]; index++) {
                        final int stop = index; int[] count = {0};
                        try {
                            GhidraCallSitePlan.recover(program, symbols, null, List.of(), registers, image, 0,
                                new TaskMonitorAdapter(true) { @Override public void checkCancelled() throws CancelledException {
                                    if (++count[0] == stop) throw new CancelledException();
                                } });
                            throw new AssertionError("missed plan cancellation " + stop);
                        }
                        catch (CancelledException expected) { checks++; }
                    }
                    for (boolean loader : List.of(false, true)) {
                        byte[] unsupported = original.clone();
                        // Non-audited ABI flags or an unreviewed program-header
                        // extension: neither may break the existing exporter.
                        ByteBuffer.wrap(unsupported).order(ByteOrder.LITTLE_ENDIAN).putInt(loader ? 120 : 48,
                            loader ? 0x60000042 : 1);
                        Path other = output.resolve((arm ? "arm-" : "x86-") + (loader ? "loader" : "abi") + ".elf");
                        Files.write(other, unsupported);
                        var omitted = GhidraCallSitePlan.recover(program, symbols, null, List.of(), registers,
                            ElfImage.read(other), 0, TaskMonitor.DUMMY);
                        require(omitted.plan().equals(CallSitePlan.EMPTY) && !omitted.diagnostics().isEmpty(),
                            "unsupported profile was not explicitly omitted");
                        require(Arrays.equals(unsupported, Files.readAllBytes(other)), "unsupported input changed");
                    }
                    int[] polls = {0};
                    GhidraTailStateProof.verify(program, selected, image, 0,
                        new TaskMonitorAdapter(true) { @Override public void checkCancelled() { polls[0]++; } });
                    for (int index = 1; index <= polls[0]; index++) {
                        final int stop = index; int[] count = {0};
                        try {
                            GhidraTailStateProof.verify(program, selected, image, 0,
                                new TaskMonitorAdapter(true) { @Override public void checkCancelled() throws CancelledException {
                                    if (++count[0] == stop) throw new CancelledException();
                                } });
                            throw new AssertionError("missed incoming-call cancellation " + stop);
                        }
                        catch (CancelledException expected) { checks++; }
                    }
                }
                require(Arrays.equals(original, Files.readAllBytes(path)), "changed original ELF");
            }
            finally { program.endTransaction(tx, false); }
        }
        finally { program.release(owner); }
    }
}
