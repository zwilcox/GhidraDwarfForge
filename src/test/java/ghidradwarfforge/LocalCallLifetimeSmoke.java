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
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.locations.TargetRegisterMap;

/** Later-local call boundaries using actual caller/callee instructions and selected ABIs. */
public final class LocalCallLifetimeSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (boolean x86 : new boolean[] {true, false}) {
            for (String mode : List.of("preserve", "clobber", "partial", "missing", "body-hole", "volatile", "call-definition")) {
                check(x86, mode);
            }
            for (String identity : List.of("merged-register", "stack-copy", "stack-only", "merged-stack")) {
                checkMapped(x86, identity, false);
                checkMapped(x86, identity, true);
            }
        }
        System.out.println("local-call-lifetime-smoke=PASS checks=" + checks);
    }

    private static void check(boolean x86, String mode) throws Exception {
        boolean volatileRegister = mode.equals("volatile");
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
            x86 ? "x86:LE:64:default" : "AARCH64:LE:64:v8A"));
        Object owner = new Object();
        var program = new ProgramDB("local-call", language, language.getDefaultCompilerSpec(), owner);
        try {
            int tx = program.startTransaction("saved later-local call");
            try {
                var entry = language.getDefaultSpace().getAddress(0x1000);
                var calleeEntry = entry.add(0x1000);
                byte[] caller = HexFormat.of().parseHex(x86 ? (volatileRegister ?
                    "41529049c7c207000000e8f10f00004c89d0415ac3" :
                    "41549049c7c407000000e8f10f00004c89e0415cc3") : (volatileRegister ?
                    "e97bbfa91f2003d5e90080d2fd030094e00309aae97bc1a8c0035fd6" :
                    "f37bbfa91f2003d5f30080d2fd030094e00313aaf37bc1a8c0035fd6"));
                String write = switch (mode) {
                    case "clobber" -> x86 ? "49c7c42a000000" : "530580d2";
                    case "partial" -> x86 ? "41b42a" : "53058052";
                    default -> "";
                };
                byte[] calleeCode = HexFormat.of().parseHex(write + (x86 ? "c3" : "c0035fd6"));
                var memory = program.getMemory().createInitializedBlock("code", entry, 0x1100,
                    (byte) 0, TaskMonitor.DUMMY, false);
                memory.setExecute(true);
                program.getMemory().setBytes(entry, caller);
                program.getMemory().setBytes(calleeEntry, calleeCode);
                var body = new AddressSet(entry, entry.add(caller.length - 1));
                var calleeBody = new AddressSet(calleeEntry, calleeEntry.add(calleeCode.length - 1));
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "caller decode");
                require(new DisassembleCommand(calleeEntry, calleeBody, true).applyTo(program, TaskMonitor.DUMMY), "callee decode");
                var function = program.getFunctionManager().createFunction("local_call", entry, body, SourceType.USER_DEFINED);
                function.setCallingConvention(program.getCompilerSpec().getDefaultCallingConvention().getName());
                if (!mode.equals("missing")) {
                    if (mode.equals("body-hole")) calleeBody.add(calleeEntry.add(calleeCode.length));
                    var callee = program.getFunctionManager().createFunction("callee", calleeEntry, calleeBody, SourceType.USER_DEFINED);
                    callee.setCallingConvention(function.getCallingConventionName());
                }
                var register = program.getRegister(x86 ? (volatileRegister ? "R10" : "R12") :
                    (volatileRegister ? "x9" : "x19"));
                boolean callDefinition = mode.equals("call-definition");
                if (callDefinition) register = program.getRegister(x86 ? "RSP" : "x30");
                var local = (LocalVariable) function.addLocalVariable(new LocalVariableImpl("held",
                    callDefinition ? (x86 ? 10 : 12) : (x86 ? 3 : 8),
                    LongLongDataType.dataType, register, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                var registers = TargetRegisterMap.forTarget(x86 ? "x86_64" : "aarch64");
                var rejected = GhidraVariableStorage.stableLocal(program, function, local, registers, TaskMonitor.DUMMY);
                var locations = RegisterDefinitionFlow.prove(program, function, local, registers, rejected, TaskMonitor.DUMMY);
                String context = (x86 ? "x86" : "arm") + "/" + mode + " " + locations;
                if (mode.equals("missing") || mode.equals("body-hole") || callDefinition) {
                    require(locations.isEmpty(), "uninspected call accepted " + context);
                    return;
                }
                require(!available(locations, 0x1000), "stale entry " + context);
                require(!available(locations, 0x1000 + local.getFirstUseOffset()), "unfinished definition " + context);
                require(available(locations, x86 ? 0x100a : 0x100c), "missing before-call value " + context);
                require(available(locations, x86 ? 0x100f : 0x1010) == mode.equals("preserve"),
                    "wrong return boundary " + context);
                require(!available(locations, x86 ? 0x1014 : 0x1018), "restored caller value leaked " + context);
                for (var interval : locations) {
                    require(body.contains(entry.getAddressSpace().getAddress(interval.start()),
                        entry.getAddressSpace().getAddress(interval.end() - 1)), "callee interval leaked " + context);
                }
                var cancelled = new TaskMonitorAdapter(true);
                cancelled.cancel();
                try {
                    RegisterDefinitionFlow.prove(program, function, local, registers, rejected, cancelled);
                    throw new AssertionError("cancellation ignored");
                }
                catch (CancelledException expected) { checks++; }
            }
            finally { program.endTransaction(tx, false); }
        }
        finally { program.release(owner); }
    }

    private static void checkMapped(boolean x86, String identity, boolean clobber) throws Exception {
        boolean stack = !identity.equals("merged-register");
        boolean merged = identity.startsWith("merged-");
        String nop = x86 ? "90" : "1f2003d5";
        var code = new StringBuilder(x86 ? "41544883ec2090" : "f37bbfa9ff8300d11f2003d5");
        int definition = code.length() / 2;
        code.append(stack ? (x86 ? "48897c2408" : "e00700f9") :
            (x86 ? "49c7c207000000" : "e90080d2"));
        int ready = code.length() / 2;
        code.append(nop);
        int transfer = code.length() / 2;
        code.append(switch (identity) {
            case "merged-register" -> x86 ? "4d89d4" : "f30309aa";
            case "stack-copy" -> x86 ? "4c8b642408" : "f30740f9";
            case "merged-stack" -> x86 ? "49c7c407000000" : "f30080d2";
            default -> nop;
        });
        int call = code.length() / 2;
        if (x86) {
            int displacement = 0x2000 - (0x1000 + call + 5);
            code.append("e8").append(HexFormat.of().formatHex(java.nio.ByteBuffer.allocate(4)
                .order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt(displacement).array()));
        }
        else {
            int opcode = 0x94000000 | ((0x2000 - (0x1000 + call)) / 4);
            code.append(HexFormat.of().formatHex(java.nio.ByteBuffer.allocate(4)
                .order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt(opcode).array()));
        }
        int after = code.length() / 2;
        code.append(nop);
        // A stale caller slot cannot revive a lost carrier after the call.
        code.append(x86 ? "4c8b542408" : "e90740f9");
        int reload = code.length() / 2;
        code.append(nop).append(x86 ? "4883c420415c" : "ff830091f37bc1a8");
        int lost = code.length() / 2;
        code.append(x86 ? "c3" : "c0035fd6");
        var machine = HexFormat.of().parseHex(code.toString());
        var calleeCode = HexFormat.of().parseHex((clobber ? (x86 ? "49c7c42a000000" : "530580d2") : "") +
            (x86 ? "c3" : "c0035fd6"));
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
            x86 ? "x86:LE:64:default" : "AARCH64:LE:64:v8A"));
        Object owner = new Object();
        var program = new ProgramDB("mapped-local-call", language, language.getDefaultCompilerSpec(), owner);
        try {
            int tx = program.startTransaction("saved mapping and call");
            try {
                var entry = language.getDefaultSpace().getAddress(0x1000);
                var calleeEntry = entry.add(0x1000);
                var memory = program.getMemory().createInitializedBlock("code", entry, 0x1100,
                    (byte) 0, TaskMonitor.DUMMY, false);
                memory.setExecute(true);
                program.getMemory().setBytes(entry, machine);
                program.getMemory().setBytes(calleeEntry, calleeCode);
                var body = new AddressSet(entry, entry.add(machine.length - 1));
                var calleeBody = new AddressSet(calleeEntry, calleeEntry.add(calleeCode.length - 1));
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "mapped caller decode");
                require(new DisassembleCommand(calleeEntry, calleeBody, true).applyTo(program, TaskMonitor.DUMMY), "mapped callee decode");
                var function = program.getFunctionManager().createFunction("mapped", entry, body, SourceType.USER_DEFINED);
                var callee = program.getFunctionManager().createFunction("callee", calleeEntry, calleeBody, SourceType.USER_DEFINED);
                function.setCallingConvention(program.getCompilerSpec().getDefaultCallingConvention().getName());
                callee.setCallingConvention(function.getCallingConventionName());
                LocalVariable local;
                if (stack) {
                    local = (LocalVariable) function.addLocalVariable(new LocalVariableImpl("held",
                        LongLongDataType.dataType, x86 ? -32 : -40, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                    local.setFirstUseOffset(definition);
                }
                else local = (LocalVariable) function.addLocalVariable(new LocalVariableImpl("held", definition,
                    LongLongDataType.dataType, program.getRegister(x86 ? "R10" : "x9"), program,
                    SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                if (merged) function.addLocalVariable(new LocalVariableImpl("held$1", transfer,
                    LongLongDataType.dataType, program.getRegister(x86 ? "R12" : "x19"), program,
                    SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                var registers = TargetRegisterMap.forTarget(x86 ? "x86_64" : "aarch64");
                List<GhidraVariableStorage.StorageInterval> locations;
                if (merged) {
                    var group = GhidraLocalMappings.extract(program, function, TaskMonitor.DUMMY, unused -> {}).getFirst();
                    require(group.mappings().size() == 2, "two saved assignments");
                    locations = MergedLocalLifetime.prove(program, function, group, registers, TaskMonitor.DUMMY);
                }
                else {
                    var rejected = GhidraVariableStorage.stableLocal(program, function, local, registers, TaskMonitor.DUMMY);
                    locations = StackLocalLifetime.prove(program, function, local, registers, rejected, TaskMonitor.DUMMY);
                }
                String context = (x86 ? "x86/" : "arm/") + identity + "/clobber=" + clobber + " " + locations;
                require(!available(locations, 0x1000 + definition), "unfinished local " + context);
                require(available(locations, 0x1000 + ready), "initialized local " + context);
                require(available(locations, 0x1000 + call), "before call " + context);
                // Stack-owned identities also need a memory-effect proof: an
                // unmodeled callee write could change the logical local while
                // leaving its old register copy untouched. That separate
                // proof is still pending; do not present stale copies here.
                boolean survives = !clobber && !stack;
                require(available(locations, 0x1000 + after) == survives, "after call " + context);
                require(available(locations, 0x1000 + reload) == survives, "stale-slot reload " + context);
                require(!available(locations, 0x1000 + lost), "restored caller register " + context);
            }
            finally { program.endTransaction(tx, false); }
        }
        finally { program.release(owner); }
    }

    private static boolean available(List<GhidraVariableStorage.StorageInterval> locations, long address) {
        return locations.stream().anyMatch(i -> i.start() <= address && address < i.end() && i.storage().available());
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
