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
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.RegisterRelativeStorage;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.locations.VariableStorageModel.Storage;

/** Logical upper slices survive disjoint writes, but never overlapping writes or slot reuse. */
public final class UpperAliasValueFlowSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (String id : List.of("ARM:LE:32:v8", "ARM:LEBE:32:v8LEInstruction")) {
            for (String shape : List.of("neighbor", "upper", "wide", "reused")) check(id, shape);
        }
        System.out.println("upper-alias-value-flow=PASS checks=" + checks);
    }

    private static void check(String id, String shape) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(id));
        Object owner = new Object();
        var program = new ProgramDB("upper-alias", language, language.getDefaultCompilerSpec(), owner);
        try {
            int tx = program.startTransaction("source-known VFP body");
            try {
                byte[] bytes = HexFormat.of().parseHex("04b02de500b08de20cd04de2020a0bed030a4bed" +
                    "027a1bed037a5bed277a77ee670ab0ee00d08be204b09de41eff2fe1");
                if (!shape.equals("neighbor")) {
                    byte[] write = HexFormat.of().parseHex(shape.equals("wide") ? "020b1bed" : "670af0ee");
                    System.arraycopy(write, 0, bytes, 32, 4);
                }
                if (shape.equals("reused")) System.arraycopy(HexFormat.of().parseHex("0c000be5"), 0, bytes, 24, 4);
                var entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                var block = program.getMemory().createInitializedBlock("code", entry, bytes.length, (byte) 0,
                    TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(entry, bytes);
                var body = new AddressSet(entry, entry.add(bytes.length - 1));
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "decode");
                var function = program.getFunctionManager().createFunction("sum", entry, body, SourceType.USER_DEFINED);
                function.setCallingConvention("__stdcall");
                function.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true,
                    SourceType.USER_DEFINED, new ParameterImpl("first", FloatDataType.dataType, program, SourceType.USER_DEFINED),
                    new ParameterImpl("second", FloatDataType.dataType, program, SourceType.USER_DEFINED));
                require(function.getParameter(1).getRegister().getName().equals("s1"), "dynamic upper parameter");
                var map = targetMap(id);
                if (id.contains("LEBE") && shape.equals("neighbor")) {
                    for (var invalid : List.of(
                            new TargetRegisterMap.RegisterSlice("d0", 64, 0, 32, 32),
                            new TargetRegisterMap.RegisterSlice("d0", 64, 4, 16, 32),
                            new TargetRegisterMap.RegisterSlice("d1", 64, 4, 32, 32))) {
                        var slices = new java.util.HashMap<>(map.registerSlices());
                        slices.put("s1", invalid);
                        var wrong = new TargetRegisterMap(map.target(), map.provenance(), map.dwarfNumbers(),
                            map.registerPairs(), slices, map.registerStorageByteOrder());
                        require(!GhidraVariableStorage.mappedRegister(program.getRegister("s1"), 4, wrong,
                            "contradictory physical alias").available(), "mismatched language slice accepted");
                    }
                }
                var intervals = StackValueFlow.prove(program, function, function.getParameter(1), map, TaskMonitor.DUMMY);
                require(!intervals.isEmpty(), "upper slice rejected " + id + "/" + shape);
                for (int offset = 0; offset <= 32; offset += 4) {
                    Storage value = at(intervals, offset);
                    require(value instanceof RegisterStorage r && r.register().dwarfNumber() == 256 &&
                        r.valueBitOffset() == 32 && r.bitSize() == 32, "upper slice before write " + id + "/" + shape + " " + value);
                }
                for (int offset : new int[] {36, 40, 44}) {
                    Storage value = at(intervals, offset);
                    if (shape.equals("neighbor")) {
                        require(value instanceof RegisterStorage r && r.register().dwarfNumber() == 256 &&
                            r.valueBitOffset() == 32, "disjoint write killed upper bits " + value);
                    }
                    else if (!shape.equals("reused") && offset == 36) {
                        require(value instanceof RegisterRelativeStorage r && r.byteOffset() == 0,
                            "overlap must use allocated saved copy " + value);
                    }
                    else require(!value.available(), "overwritten/released value resurrected " + value);
                }
                var parameter = function.getParameter(1);
                var rejected = GhidraVariableStorage.stableParameter(program, function, parameter, map, TaskMonitor.DUMMY);
                var exported = GhidraVariableStorage.parameterPrefix(program, function, parameter, map, rejected, TaskMonitor.DUMMY);
                require(at(exported, 36).available() == !shape.equals("reused"), "public handoff differs");
                require(at(exported, 44).available() == shape.equals("neighbor"), "public terminal differs");
                var pair = new ghidra.program.model.data.StructureDataType("FloatPair", 0,
                    program.getDataTypeManager());
                pair.add(FloatDataType.dataType, "first", null);
                pair.add(FloatDataType.dataType, "second", null);
                var first = program.getRegister("s0");
                var second = program.getRegister("s1");
                var joined = new ghidra.program.model.listing.VariableStorage(program,
                    language.isBigEndian() ? first : second, language.isBigEndian() ? second : first);
                function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true,
                    SourceType.USER_DEFINED, new ParameterImpl("pair", pair, joined, program, SourceType.USER_DEFINED));
                var pieces = CompositeValueFlow.prove(program, function, function.getParameter(0), map, TaskMonitor.DUMMY);
                require(!pieces.isEmpty(), "upper incoming composite rejected " + id + "/" + shape);
                for (int offset = 0; offset <= 32; offset += 4) {
                    require(at(pieces, offset) instanceof ghidradwarfforge.locations.VariableStorageModel.CompositeStorage,
                        "whole incoming pair lost before write " + offset);
                }
                require(at(pieces, 36).available() == !shape.equals("reused"), "saved composite availability " + pieces);
                require(at(pieces, 40).available() == shape.equals("neighbor") &&
                    at(pieces, 44).available() == shape.equals("neighbor"),
                    "released composite slot or surviving copy differs " + pieces);
                if (shape.equals("neighbor")) {
                    var joinedValue = (ghidradwarfforge.locations.VariableStorageModel.CompositeStorage) at(pieces, 44);
                    require(joinedValue.pieces().get(0).storage() instanceof RegisterStorage backup &&
                        backup.register().dwarfNumber() == 263 && backup.valueBitOffset() == 0,
                        "completed s14 backup lost after frame release");
                }

            }
            finally { program.endTransaction(tx, true); }
        }
        finally { program.release(owner); }
    }

    private static Storage at(List<GhidraVariableStorage.StorageInterval> intervals, long offset) {
        return intervals.stream().filter(i -> i.start() <= 0x1000 + offset && i.end() > 0x1000 + offset)
            .findFirst().orElseThrow().storage();
    }

    private static TargetRegisterMap targetMap(String id) throws Exception {
        if (!id.contains("LEBE")) return TargetRegisterMap.forTarget("arm");
        var file = java.nio.file.Files.createTempFile("be8-register-map-", ".elf");
        try {
            var header = java.nio.ByteBuffer.allocate(52).order(java.nio.ByteOrder.BIG_ENDIAN);
            header.put(new byte[] {0x7f, 'E', 'L', 'F', 1, 2, 1});
            header.putShort(16, (short) 2).putShort(18, (short) 40).putInt(20, 1);
            header.putInt(36, 0x05800400).putShort(40, (short) 52);
            java.nio.file.Files.write(file, header.array());
            return TargetRegisterMap.forElf("arm", ghidradwarfforge.elf.ElfImage.read(file), () -> false);
        }
        finally { java.nio.file.Files.delete(file); }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
