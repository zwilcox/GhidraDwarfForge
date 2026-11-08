package ghidradwarfforge;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.CompositeStorage;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;

/** Actual MIPS alias trees, instruction writes and explicit ABI selection. */
public final class MipsFp32PairSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        Path directory = Files.createTempDirectory("forge-fp32-pair-");
        Path elf = directory.resolve("metadata.elf");
        try {
            for (boolean big : new boolean[] { true, false }) {
                String target = big ? "mips" : "mipsel";
                var language = DefaultLanguageService.getLanguageService()
                    .getLanguage(new LanguageID("MIPS:" + (big ? "BE" : "LE") + ":32:default"));
                metadata(elf, big, 1);
                var mapped = TargetRegisterMap.forElf(target, ElfImage.read(elf), () -> false);
                require(mapped.registerPairs().size() == 16, "missing explicit FP32 map");
                require(TargetRegisterMap.forElf(big ? "mipsel" : "mips", ElfImage.read(elf),
                    () -> false).registerPairs().isEmpty(), "endian mismatch accepted");
                for (int first = 0; first < 32; first += 2) {
                    var alias = language.getRegister("f" + first + "_" + (first + 1));
                    var location = GhidraVariableStorage.mappedRegister(alias, 8, mapped, "pair");
                    require(location instanceof CompositeStorage, "whole pair not mapped: " + alias);
                    var pieces = ((CompositeStorage) location).pieces();
                    for (int i = 0; i < 2; i++) {
                        var piece = pieces.get(i);
                        int number = first + (big ? 1 - i : i);
                        require(piece.bitSize() == 32 && piece.storage() instanceof RegisterStorage r &&
                            r.register().dwarfNumber() == 32 + number && r.valueBitOffset() == 0,
                            "pair not in object-memory order");
                    }
                    require(!GhidraVariableStorage.mappedRegister(alias, 4, mapped, "partial").available(),
                        "partial pair invented a slice");
                    require(!GhidraVariableStorage.mappedRegister(alias, 8,
                        TargetRegisterMap.forTarget(target), "unclassified").available(),
                        "unclassified target enabled pair");
                }
                for (int write : new int[] { 0, 0x44846000, 0x44846800 }) {
                    Object owner = new Object();
                    var program = new ProgramDB("fp32", language, language.getDefaultCompilerSpec(), owner);
                    try {
                        int transaction = program.startTransaction("real paired-register instructions");
                        try {
                            ByteBuffer code = ByteBuffer.allocate(write == 0 ? 8 : 12)
                                .order(big ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
                            if (write != 0) {
                                code.putInt(write); // mtc1 a0,f12 or mtc1 a0,f13
                            }
                            code.putInt(0x03e00008).putInt(0); // jr ra; delay-slot nop
                            var start = language.getDefaultSpace().getAddress(0x1000);
                            var body = new AddressSet(start, start.add(code.capacity() - 1));
                            var block = program.getMemory().createInitializedBlock("code", start,
                                code.capacity(), (byte) 0, TaskMonitor.DUMMY, false);
                            block.setExecute(true);
                            program.getMemory().setBytes(start, code.array());
                            require(new DisassembleCommand(start, body, true).applyTo(program, TaskMonitor.DUMMY),
                                "MIPS decode failed");
                            var function = program.getFunctionManager().createFunction("pair", start,
                                body, SourceType.USER_DEFINED);
                            function.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
                            function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true,
                                SourceType.USER_DEFINED, new ParameterImpl("value", DoubleDataType.dataType,
                                    program.getRegister("f12_13"), program, SourceType.USER_DEFINED));
                            var parameter = function.getParameter(0);
                            var stable = GhidraVariableStorage.stableParameter(program, function, parameter,
                                mapped, TaskMonitor.DUMMY);
                            require(write == 0 ? stable instanceof CompositeStorage :
                                stable instanceof UnavailableStorage u && u.reason() == OmissionReason.REGISTER_MODIFIED,
                                "pair write was missed: " + stable);
                            if (write != 0) {
                                var prefix = GhidraVariableStorage.parameterPrefix(program, function, parameter,
                                    mapped, stable, TaskMonitor.DUMMY);
                                require(prefix.size() == 2 && prefix.getFirst().start() == 0x1000 &&
                                    prefix.getFirst().end() == 0x1004 && prefix.getFirst().storage() instanceof CompositeStorage,
                                    "decoded pair prefix must end immediately after either member write: " + prefix);
                                require(prefix.getLast().start() == 0x1004 && prefix.getLast().end() == 0x100c &&
                                    !prefix.getLast().storage().available(), "partially clobbered pair remained available");
                                program.getReferenceManager().addMemoryReference(start.add(0x40), start.add(4),
                                    RefType.UNCONDITIONAL_JUMP, SourceType.USER_DEFINED, 0);
                                require(GhidraVariableStorage.parameterPrefix(program, function, parameter,
                                    mapped, stable, TaskMonitor.DUMMY).isEmpty(), "alternate-entry pair prefix accepted");
                            }
                        }
                        finally {
                            program.endTransaction(transaction, true);
                        }
                    }
                    finally {
                        program.release(owner);
                    }
                }
                for (int abi : new int[] { 0, 3, 5, 6, 7 }) {
                    metadata(elf, big, abi);
                    require(TargetRegisterMap.forElf(target, ElfImage.read(elf), () -> false)
                        .registerPairs().isEmpty(), "other FP ABI enabled pairs");
                }
            }
        }
        finally {
            Files.deleteIfExists(elf);
            Files.delete(directory);
        }
        System.out.println("mips-fp32-pair-smoke=PASS checks=" + checks);
    }

    private static void metadata(Path path, boolean big, int abi) throws Exception {
        ByteBuffer file = ByteBuffer.allocate(120).order(big ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
        file.put(new byte[] { 0x7f, 'E', 'L', 'F', 1, (byte) (big ? 2 : 1), 1, 0 });
        file.putShort(16, (short) 2).putShort(18, (short) 8).putInt(20, 1);
        file.putInt(28, 52).putInt(36, 0x70001007).putShort(40, (short) 52);
        file.putShort(42, (short) 32).putShort(44, (short) 1);
        file.putInt(52, 0x70000003).putInt(56, 96).putInt(68, 24).putInt(72, 24).putInt(80, 8);
        file.position(96);
        file.putShort((short) 0).put(new byte[] { 32, 2, 1, (byte) (abi >= 6 ? 2 : 1), 0, (byte) abi });
        file.putInt(0).putInt(0).putInt(1).putInt(0);
        Files.write(path, file.array());
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) {
            throw new AssertionError(message);
        }
    }
}
