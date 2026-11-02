package ghidradwarfforge;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.util.HexFormat;
import java.util.List;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.RegisterRelativeStorage;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.locations.VariableStorageModel.Storage;

/** Partial objects retain byte identity across wider transfers and adjacent/clobber controls. */
public final class RegisterByteSliceFlowSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (String target : List.of("arm", "be8", "x86_64", "aarch64")) {
            for (int width : target.equals("arm") || target.equals("be8") ? new int[] {1, 2, 3} : new int[] {1, 2, 3, 5, 7}) {
                for (String shape : List.of("adjacent", "overlap", "unknown", "left", "right", "nonbyte", "dynamic")) check(target, width, shape);
            }
        }
        System.out.println("register-byte-slice-flow=PASS checks=" + checks);
    }

    private static void check(String target, int width, String shape) throws Exception {
        boolean arm = target.equals("arm") || target.equals("be8");
        boolean big = target.equals("be8");
        boolean x86 = target.equals("x86_64");
        String id = arm ? (big ? "ARM:LEBE:32:v8LEInstruction" : "ARM:LE:32:v8") :
            x86 ? "x86:LE:64:default" : "AARCH64:LE:64:v8A";
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(id));
        Object owner = new Object();
        var program = new ProgramDB("byte-slices", language, language.getDefaultCompilerSpec(), owner);
        try {
            int transaction = program.startTransaction("partial transfers");
            try {
                String incoming = arm ? "r3" : x86 ? "RDI" : "x0";
                int slot = arm ? 4 : 8;
                int offset = slot + width - (shape.equals("adjacent") ? 0 : 1);
                String overwrite = arm ? HexFormat.of().toHexDigits(0xe5cd0000 | offset) :
                    x86 ? "c64424" + HexFormat.of().toHexDigits((byte) offset) + "00" :
                    HexFormat.of().toHexDigits(0x390003ff | offset << 10);
                if (!x86) overwrite = word(Integer.parseUnsignedInt(overwrite, 16));
                if (shape.equals("unknown")) overwrite = arm ? "0000c1e5" : x86 ? "c60600" : "3f000039";
                String nop = arm ? "00f020e3" : x86 ? "90" : "1f2003d5";
                var machine = new StringBuilder(arm ? "10d04de2" : x86 ? "4883ec20" : "ff8300d1");
                machine.append(arm ? "0340a0e1" : x86 ? "4989fa" : "e90300aa");
                machine.append(arm ? "04308de5" : x86 ? "48897c2408" : "e00700f9");
                machine.append(arm ? "0030a0e3" : x86 ? "31ff" : "e0031faa");
                int backup = machine.length() / 2;
                machine.append(nop).append(arm ? "0040a0e3" : x86 ? "4531d2" : "e9031faa");
                int spilled = machine.length() / 2;
                machine.append(nop).append(arm ? "04509de5" : x86 ? "4c8b5c2408" : "ea0740f9");
                int loaded = machine.length() / 2;
                machine.append(nop).append(overwrite);
                int overwritten = machine.length() / 2;
                boolean shift = List.of("left", "right", "nonbyte", "dynamic").contains(shape);
                String kill = arm ? "0050a0e3" : x86 ? "4531db" : "ea031faa";
                if (shift) {
                    if (shape.equals("dynamic")) kill = arm ? word(0xe1a05115) : x86 ? "49d3e3" : word(0x9ac1214a);
                    else if (arm) kill = word(shape.equals("left") ? 0xe1a05405 : shape.equals("right") ? 0xe1a05425 : 0xe1a05085);
                    else if (x86) kill = shape.equals("left") ? "49c1e308" : shape.equals("right") ? "49c1eb08" : "49c1e301";
                    else kill = word(shape.equals("left") ? 0xd378dd4a : shape.equals("right") ? 0xd348fd4a : 0xd37ff94a);
                }
                machine.append(nop).append(kill);
                int killed = machine.length() / 2;
                machine.append(nop).append(arm ? "04609de5" : x86 ? "4c8b642408" : "eb0740f9");
                int reloaded = machine.length() / 2;
                machine.append(nop).append(arm ? "10d08de2" : x86 ? "4883c420" : "ff830091");
                int released = machine.length() / 2;
                machine.append(arm ? "1eff2fe1" : x86 ? "c3" : "c0035fd6");
                byte[] code = HexFormat.of().parseHex(machine.toString());
                var entry = language.getDefaultSpace().getAddress(0x1000);
                var body = new AddressSet(entry, entry.add(code.length - 1));
                var block = program.getMemory().createInitializedBlock("code", entry, code.length,
                    (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(entry, code);
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "decode");
                var function = program.getFunctionManager().createFunction("transfer", entry, body, SourceType.USER_DEFINED);
                var object = new StructureDataType("ObjectBytes", 0, program.getDataTypeManager());
                object.add(new ArrayDataType(ByteDataType.dataType, width, 1, program.getDataTypeManager()), "bytes", null);
                var register = program.getRegister(incoming);
                var node = new Varnode(register.getAddress().add(big ? 4 - width : 0), width);
                var storage = new VariableStorage(program, node);
                function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED,
                    new ParameterImpl("value", object, storage, program, SourceType.USER_DEFINED));
                var map = targetMap(target);
                var intervals = StackValueFlow.prove(program, function, function.getParameter(0), map, TaskMonitor.DUMMY);
                String context = target + "/" + width + "/" + shape + " " + intervals + " transfer=" +
                    java.util.Arrays.toString(program.getListing().getInstructionAt(entry.add(killed - kill.length() / 2)).getPcode());
                int bitOffset = big ? (4 - width) * 8 : 0;
                expectRegister(at(intervals, 0), arm ? 3 : x86 ? 5 : 0, bitOffset, width, context);
                expectRegister(at(intervals, backup), arm ? 4 : x86 ? 10 : 9, bitOffset, width, context);
                require(at(intervals, spilled) instanceof RegisterRelativeStorage relative && relative.byteOffset() == slot,
                    "word spill used padding bytes " + context);
                expectRegister(at(intervals, loaded), arm ? 5 : x86 ? 11 : 10, bitOffset, width, context);
                expectRegister(at(intervals, overwritten), arm ? 5 : x86 ? 11 : 10, bitOffset, width, context);
                if (shape.equals("adjacent")) {
                    require(at(intervals, killed) instanceof RegisterRelativeStorage relative && relative.byteOffset() == slot,
                        "adjacent write killed live bytes " + context);
                    expectRegister(at(intervals, reloaded), arm ? 6 : x86 ? 12 : 11, bitOffset, width, context);
                    expectRegister(at(intervals, released), arm ? 6 : x86 ? 12 : 11, bitOffset, width, context);
                }
                else if (shift && (shape.equals("right") && big || shape.equals("left") && !big)) {
                    int moved = bitOffset + (shape.equals("left") ? 8 : -8);
                    for (int boundary : new int[] {killed, reloaded, released}) {
                        expectRegister(at(intervals, boundary), arm ? 5 : x86 ? 11 : 10, moved, width, context);
                    }
                }
                else {
                    require(!at(intervals, killed).available() && !at(intervals, reloaded).available() &&
                        !at(intervals, released).available(), "clobbered bytes reappeared " + context);
                }
                require(function.getParameter(0).getVariableStorage().equals(storage), "saved storage changed");
                if (target.equals("arm") && width == 3 && shape.equals("adjacent")) {
                    joinedTransfers(program, program.getListing().getInstructionAt(entry.add(backup)), map);
                    carryFreeJoins(program, program.getListing().getInstructionAt(entry.add(backup)), map);
                }
                var cancelled = new TaskMonitorAdapter(true); cancelled.cancel();
                try {
                    StackValueFlow.prove(program, function, function.getParameter(0), map, cancelled);
                    throw new AssertionError("cancellation ignored");
                }
                catch (ghidra.util.exception.CancelledException expected) { checks++; }
            }
            finally { program.endTransaction(transaction, true); }
        }
        finally { program.release(owner); }
    }

    private static void joinedTransfers(ProgramDB program, ghidra.program.model.listing.Instruction template,
            TargetRegisterMap map) throws Exception {
        var constantSpace = program.getAddressFactory().getConstantSpace();
        var uniqueSpace = program.getAddressFactory().getUniqueSpace();
        var address = template.getAddress();
        var source = new Varnode(program.getRegister("r3").getAddress(), 4);
        var destination = new Varnode(program.getRegister("r5").getAddress(), 4);
        var zero = new Varnode(constantSpace.getAddress(0), 4);
        var zeroByte = new Varnode(constantSpace.getAddress(0), 1);
        for (String shape : List.of("piece-high", "piece-low", "subpiece", "subpiece-drops", "duplicate")) {
            int bytes = shape.equals("duplicate") ? 1 : 3;
            var incoming = new Varnode(source.getAddress().add(shape.equals("subpiece") ? 1 : 0), bytes);
            var temporary = new Varnode(uniqueSpace.getAddress(0x100), bytes);
            var operations = new java.util.ArrayList<ghidra.program.model.pcode.PcodeOp>();
            int opcode = ghidra.program.model.pcode.PcodeOp.COPY;
            Varnode[] inputs = {incoming};
            if (shape.startsWith("subpiece")) {
                opcode = ghidra.program.model.pcode.PcodeOp.SUBPIECE;
                inputs = new Varnode[] {source, new Varnode(constantSpace.getAddress(1), 4)};
            }
            operations.add(new ghidra.program.model.pcode.PcodeOp(address, 0, opcode, inputs, temporary));
            if (shape.startsWith("piece")) {
                inputs = shape.equals("piece-high") ? new Varnode[] {temporary, zeroByte} : new Varnode[] {zeroByte, temporary};
                operations.add(new ghidra.program.model.pcode.PcodeOp(address, 1,
                    ghidra.program.model.pcode.PcodeOp.PIECE, inputs, destination));
            }
            else if (shape.equals("duplicate")) {
                var doubled = new Varnode(uniqueSpace.getAddress(0x200), 2);
                operations.add(new ghidra.program.model.pcode.PcodeOp(address, 1,
                    ghidra.program.model.pcode.PcodeOp.PIECE, new Varnode[] {temporary, temporary}, doubled));
                operations.add(new ghidra.program.model.pcode.PcodeOp(address, 2,
                    ghidra.program.model.pcode.PcodeOp.INT_ZEXT, new Varnode[] {doubled}, destination));
                // Lose only the low duplicate. The second byte must survive.
                operations.add(new ghidra.program.model.pcode.PcodeOp(address, 3,
                    ghidra.program.model.pcode.PcodeOp.COPY, new Varnode[] {zeroByte}, new Varnode(destination.getAddress(), 1)));
            }
            else operations.add(new ghidra.program.model.pcode.PcodeOp(address, 1,
                ghidra.program.model.pcode.PcodeOp.INT_ZEXT, new Varnode[] {temporary}, destination));
            operations.add(new ghidra.program.model.pcode.PcodeOp(address, 4,
                ghidra.program.model.pcode.PcodeOp.COPY, new Varnode[] {zero}, source));
            var instruction = (ghidra.program.model.listing.Instruction) java.lang.reflect.Proxy.newProxyInstance(
                ghidra.program.model.listing.Instruction.class.getClassLoader(),
                new Class<?>[] {ghidra.program.model.listing.Instruction.class}, (proxy, method, arguments) ->
                    method.getName().equals("getPcode") ? operations.toArray(ghidra.program.model.pcode.PcodeOp[]::new) :
                        method.invoke(template, arguments));
            var state = StackValueFlow.forIncomingPiece(program, incoming);
            require(state.advance(instruction, false, TaskMonitor.DUMMY), "joined transfer rejected " + shape);
            if (shape.equals("subpiece-drops")) require(!state.location(map).available(), "truncated bytes reappeared");
            else expectRegister(state.location(map), 5, shape.equals("piece-high") || shape.equals("duplicate") ? 8 : 0,
                bytes, "joined transfer " + shape);
        }
    }

    private static void carryFreeJoins(ProgramDB program, ghidra.program.model.listing.Instruction template,
            TargetRegisterMap map) throws Exception {
        var constants = program.getAddressFactory().getConstantSpace();
        var uniques = program.getAddressFactory().getUniqueSpace();
        var address = template.getAddress();
        var source = new Varnode(program.getRegister("r3").getAddress(), 4);
        var other = new Varnode(program.getRegister("r0").getAddress(), 4);
        var destination = new Varnode(program.getRegister("d0").getAddress(), 8);
        var high = new Varnode(uniques.getAddress(0x300), 8);
        var low = new Varnode(uniques.getAddress(0x400), 8);
        var zero = new Varnode(constants.getAddress(0), 4);
        for (String shape : List.of("add-high", "add-low", "or-high", "add-overlap", "or-overlap", "add-carry", "conditional-carry")) {
            var operations = new java.util.ArrayList<ghidra.program.model.pcode.PcodeOp>();
            operations.add(new ghidra.program.model.pcode.PcodeOp(address, 0,
                ghidra.program.model.pcode.PcodeOp.INT_ZEXT, new Varnode[] {source}, high));
            if (!shape.endsWith("overlap") && !shape.equals("add-low")) operations.add(new ghidra.program.model.pcode.PcodeOp(address, 1,
                ghidra.program.model.pcode.PcodeOp.INT_LEFT, new Varnode[] {high, new Varnode(constants.getAddress(32), 4)}, high));
            operations.add(new ghidra.program.model.pcode.PcodeOp(address, 2,
                ghidra.program.model.pcode.PcodeOp.INT_ZEXT, new Varnode[] {other}, low));
            if (shape.equals("conditional-carry")) operations.add(new ghidra.program.model.pcode.PcodeOp(address, 3,
                ghidra.program.model.pcode.PcodeOp.CBRANCH, new Varnode[] {new Varnode(constants.getAddress(2), 4),
                    new Varnode(program.getRegister("ZR").getAddress(), 1)}, null));
            if (shape.endsWith("carry") || shape.equals("add-low")) operations.add(new ghidra.program.model.pcode.PcodeOp(address, 4,
                ghidra.program.model.pcode.PcodeOp.INT_LEFT, new Varnode[] {low,
                    new Varnode(constants.getAddress(shape.equals("add-low") ? 32 : 1), 4)}, low));
            operations.add(new ghidra.program.model.pcode.PcodeOp(address, 5,
                shape.startsWith("or-") ? ghidra.program.model.pcode.PcodeOp.INT_OR : ghidra.program.model.pcode.PcodeOp.INT_ADD,
                new Varnode[] {high, low}, destination));
            operations.add(new ghidra.program.model.pcode.PcodeOp(address, 6,
                ghidra.program.model.pcode.PcodeOp.COPY, new Varnode[] {zero}, source));
            var instruction = (ghidra.program.model.listing.Instruction) java.lang.reflect.Proxy.newProxyInstance(
                ghidra.program.model.listing.Instruction.class.getClassLoader(),
                new Class<?>[] {ghidra.program.model.listing.Instruction.class}, (proxy, method, arguments) ->
                    method.getName().equals("getPcode") ? operations.toArray(ghidra.program.model.pcode.PcodeOp[]::new) :
                        method.invoke(template, arguments));
            var state = StackValueFlow.forIncomingPiece(program, new Varnode(source.getAddress(), 3));
            require(state.advance(instruction, false, TaskMonitor.DUMMY), "arithmetic join rejected " + shape);
            if (shape.endsWith("high") || shape.equals("add-low")) {
                expectRegister(state.location(map), 256, shape.equals("add-low") ? 0 : 32, 3, "carry-free join " + shape);
            }
            else require(!state.location(map).available(), "carry/overlap discarded without proof " + shape);
        }
    }

    private static String word(int value) {
        return HexFormat.of().formatHex(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array());
    }

    private static TargetRegisterMap targetMap(String target) throws Exception {
        if (!target.equals("be8")) return TargetRegisterMap.forTarget(target);
        var file = Files.createTempFile("be8-byte-slice", ".elf");
        try {
            var header = ByteBuffer.allocate(52).order(ByteOrder.BIG_ENDIAN);
            header.put(new byte[] {0x7f, 'E', 'L', 'F', 1, 2, 1});
            header.putShort(16, (short) 2).putShort(18, (short) 40).putInt(20, 1);
            header.putInt(36, 0x05800400).putShort(40, (short) 52);
            Files.write(file, header.array());
            return TargetRegisterMap.forElf("arm", ElfImage.read(file), () -> false);
        }
        finally { Files.delete(file); }
    }

    private static Storage at(List<GhidraVariableStorage.StorageInterval> intervals, int offset) {
        return intervals.stream().filter(row -> row.start() <= 0x1000 + offset && row.end() > 0x1000 + offset)
            .findFirst().orElseThrow().storage();
    }

    private static void expectRegister(Storage storage, int number, int offset, int width, String context) {
        require(storage instanceof RegisterStorage register && register.register().dwarfNumber() == number &&
            register.valueBitOffset() == offset && register.bitSize() == width * 8, "wrong register bytes " + context + " got=" + storage);
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
