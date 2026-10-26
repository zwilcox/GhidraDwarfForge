package ghidradwarfforge;

import java.io.File;
import java.util.HexFormat;
import java.util.List;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;

/** Real decoded control flow; excluded instructions must not prove register stability. */
public final class OutsideBodyFlowSmoke {
    private static int checks;

    private record Profile(String name, String language, String target, String register,
            String code, int hiddenStart, int hiddenEnd, boolean available) { }

    private OutsideBodyFlowSmoke() { }

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (var profile : List.of(
                // These two bodies come from the retained compiler/GDB reproduction.
                new Profile("x86-excluded-branch", "x86:LE:64:default", "x86_64", "ESI",
                    "f30f1efa89f0eb02eb0431f6ebfa83c007c3", 10, 14, false),
                new Profile("aarch64-excluded-branch", "AARCH64:LE:64:v8A", "aarch64", "w1",
                    "e003012a0200001403000014e1031f2afeffff17001c0011c0035fd6", 12, 20, false),
                new Profile("x86-excluded-fallthrough", "x86:LE:64:default", "x86_64", "ESI",
                    "9031f6c3", 1, 3, false),
                new Profile("aarch64-excluded-fallthrough", "AARCH64:LE:64:v8A", "aarch64", "w1",
                    "1f2003d5e1031f2ac0035fd6", 4, 8, false),
                // A declared gap is valid when a real direct jump bypasses it.
                new Profile("x86-jump-over-gap", "x86:LE:64:default", "x86_64", "ESI",
                    "eb029090c3", 2, 4, true),
                new Profile("aarch64-jump-over-gap", "AARCH64:LE:64:v8A", "aarch64", "w1",
                    "020000141f2003d5c0035fd6", 4, 8, true),
                new Profile("mipsbe-excluded-branch", "MIPS:BE:32:default", "mips", "a1",
                    "10000001000000000000282503e0000800000000", 8, 12, false),
                new Profile("mipsle-excluded-branch", "MIPS:LE:32:default", "mips", "a1",
                    "0100001000000000252800000800e00300000000", 8, 12, false),
                new Profile("mipsbe-jump-over-gap", "MIPS:BE:32:default", "mips", "a1",
                    "10000002000000000000000003e0000800000000", 8, 12, true),
                new Profile("mipsle-jump-over-gap", "MIPS:LE:32:default", "mips", "a1",
                    "0200001000000000000000000800e00300000000", 8, 12, true),
                new Profile("mipsbe-orphan-slot", "MIPS:BE:32:default", "mips", "a1",
                    "0000000003e0000800000000", 4, 8, false),
                new Profile("x86-unknown-jump", "x86:LE:64:default", "x86_64", "ESI",
                    "ffe0", -1, -1, false),
                new Profile("aarch64-unknown-jump", "AARCH64:LE:64:v8A", "aarch64", "w1",
                    "40001fd6", -1, -1, false))) {
            check(profile);
        }
        System.out.println("outside-body-flow-smoke=PASS checks=" + checks);
    }

    private static void check(Profile profile) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(profile.language()));
        var owner = new Object();
        var program = new ProgramDB(profile.name(), language, language.getDefaultCompilerSpec(), owner);
        try {
            int transaction = program.startTransaction("decode exact flow fixture");
            try {
                byte[] bytes = HexFormat.of().parseHex(profile.code());
                var start = language.getDefaultSpace().getAddress(0x1000);
                var fullBody = new AddressSet(start, start.add(bytes.length - 1));
                var block = program.getMemory().createInitializedBlock("code", start, bytes.length,
                    (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(start, bytes);
                require(new DisassembleCommand(start, fullBody, true).applyTo(program, TaskMonitor.DUMMY), "decode");
                var function = program.getFunctionManager().createFunction("fixture", start, fullBody, SourceType.USER_DEFINED);
                var register = program.getRegister(profile.register());
                var parameter = new ParameterImpl("value", IntegerDataType.dataType, register, program);
                var map = TargetRegisterMap.forTarget(profile.target());
                if (profile.hiddenStart() >= 0 && !profile.available() && !profile.name().contains("orphan")) {
                    var complete = GhidraVariableStorage.stableParameter(program, function, parameter, map, TaskMonitor.DUMMY);
                    require(complete instanceof UnavailableStorage unavailable &&
                        unavailable.reason() == OmissionReason.REGISTER_MODIFIED, "complete body must expose its clobber");
                }
                if (profile.hiddenStart() >= 0) {
                    var body = new AddressSet(fullBody);
                    body.deleteRange(start.add(profile.hiddenStart()), start.add(profile.hiddenEnd() - 1));
                    function.setBody(body);
                }
                var storage = GhidraVariableStorage.stableParameter(program, function, parameter, map, TaskMonitor.DUMMY);
                require(storage.available() == profile.available(), profile.name() + ": " + storage);
                var local = new LocalVariableImpl("local", 0, IntegerDataType.dataType, register, program);
                require(GhidraVariableStorage.stableLocal(program, function, local, map, TaskMonitor.DUMMY)
                    .available() == profile.available(), profile.name() + " local");
                if (!profile.available()) {
                    require(storage instanceof UnavailableStorage unavailable &&
                        unavailable.reason() == OmissionReason.UNKNOWN_LIFETIME &&
                        unavailable.diagnostic().contains("control flow"), "wrong flow diagnostic: " + storage);
                    require(GhidraVariableStorage.parameterPrefix(program, function, parameter, map,
                        storage, TaskMonitor.DUMMY).isEmpty(), "unproven flow invented a prefix");
                }
                if (profile.name().equals("x86-jump-over-gap")) {
                    var manager = program.getReferenceManager();
                    var external = start.add(0x100);
                    // Calls to the entry establish the normal invocation contract.
                    for (var type : List.of(RefType.UNCONDITIONAL_CALL, RefType.UNCONDITIONAL_JUMP,
                            RefType.INDIRECTION)) {
                        var incoming = manager.addMemoryReference(external, start, type, SourceType.USER_DEFINED, -1);
                        require(GhidraVariableStorage.stableParameter(program, function, parameter, map,
                            TaskMonitor.DUMMY).available(), "ordinary entry reference was rejected: " + type);
                        manager.delete(incoming);
                    }
                    for (var destination : List.of(start.add(1), start.add(4))) {
                        var incoming = manager.addMemoryReference(external, destination, RefType.UNCONDITIONAL_JUMP,
                            SourceType.USER_DEFINED, -1);
                        require(!GhidraVariableStorage.stableParameter(program, function, parameter, map,
                            TaskMonitor.DUMMY).available(), "alternate entry was accepted");
                        manager.delete(incoming);
                    }
                    var instruction = program.getListing().getInstructionAt(start);
                    instruction.setFallThrough(start.add(4));
                    require(!GhidraVariableStorage.stableParameter(program, function, parameter, map,
                        TaskMonitor.DUMMY).available(), "fallthrough override was accepted");
                    instruction.clearFallThroughOverride();
                    instruction.setFlowOverride(FlowOverride.RETURN);
                    require(!GhidraVariableStorage.stableParameter(program, function, parameter, map,
                        TaskMonitor.DUMMY).available(), "flow override was accepted");
                    instruction.setFlowOverride(FlowOverride.NONE);
                }
                if (profile.name().equals("mipsbe-jump-over-gap")) {
                    var incoming = program.getReferenceManager().addMemoryReference(start.add(0x100), start.add(4),
                        RefType.UNCONDITIONAL_JUMP, SourceType.USER_DEFINED, -1);
                    require(!GhidraVariableStorage.stableParameter(program, function, parameter, map,
                        TaskMonitor.DUMMY).available(), "independent delay-slot entry was accepted");
                    program.getReferenceManager().delete(incoming);
                }
                if (profile.name().equals("x86-excluded-branch")) {
                    // Deleting database flow references cannot erase the decoded jump.
                    for (var instruction : program.getListing().getInstructions(fullBody, true)) {
                        for (var reference : program.getReferenceManager().getReferencesFrom(instruction.getAddress())) {
                            if (reference.getReferenceType().isFlow()) {
                                program.getReferenceManager().delete(reference);
                            }
                        }
                    }
                    require(!GhidraVariableStorage.stableParameter(program, function, parameter, map,
                        TaskMonitor.DUMMY).available(), "deleted references hid a decoded external jump");
                }
                byte[] after = new byte[bytes.length];
                program.getMemory().getBytes(start, after);
                require(java.util.Arrays.equals(bytes, after), "curation changed target bytes");
            }
            finally { program.endTransaction(transaction, true); }
        }
        finally { program.release(owner); }
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
