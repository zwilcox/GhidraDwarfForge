// Curates scalar floating signatures and storage at independent compiler addresses.
// @category DWARF.Tests

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.AddressNormalizer;
import ghidradwarfforge.GhidraImageBase;

public class PrepareFloatingRegisters extends GhidraScript {
    private final Map<String, Long> labels = new LinkedHashMap<>();
    private long delta;

    @Override
    protected void run() throws Exception {
        if ("mips-fp32".equals(System.getenv("FORGE_FP_ABI_PROFILE"))) {
            println("floating-storage-origin=" + ghidradwarfforge.GhidraVariableStorage.class
                .getProtectionDomain().getCodeSource().getLocation().toExternalForm());
        }
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException("expected target labels-file");
        }
        delta = AddressNormalizer.rebaseDelta(currentProgram.getImageBase().getOffset(),
            GhidraImageBase.originalImageBase(currentProgram));
        for (String line : Files.readAllLines(Path.of(args[1]))) {
            String[] parts = line.split(" ");
            labels.put(parts[0], Math.addExact(Long.decode(parts[1]), delta));
        }
        String[] single;
        String[] wide;
        switch (args[0]) {
            case "x86_64" -> { single = new String[] { "XMM0", "XMM1" }; wide = single; }
            case "aarch64" -> {
                single = new String[] { "s0", "s1" }; wide = new String[] { "d0", "d1" };
            }
            case "arm32" -> {
                single = new String[] { "s0", "s1" }; wide = new String[] { "d0", "d1" };
            }
            case "mips32be", "mips32le" -> {
                single = new String[] { "f12", "f14" };
                wide = new String[] { "f12_13", "f14_15" };
            }
            default -> throw new IllegalArgumentException("unsupported fixture target " + args[0]);
        }
        var manager = currentProgram.getDataTypeManager();
        DataType floatType = new FloatDataType(manager);
        DataType doubleType = new DoubleDataType(manager);
        function("fp_float", floatType, single, new String[] { "first", "second" });
        function("fp_double", doubleType, wide, new String[] { "first", "second" });
        if (labels.containsKey("fp_clobbered")) {
            function("fp_clobbered", floatType, new String[] { single[0] },
                new String[] { "value" });
            if (args[0].equals("arm32")) {
                verifyArmOpaqueReturn();
            }
        }
        for (String name : new String[] { "fp_float_first", "fp_float_second",
                "fp_double_first", "fp_double_second", "fp_clobber_sink" }) {
            DataType type = name.startsWith("fp_double") ? doubleType : floatType;
            var address = toAddr(labels.get(name));
            DataUtilities.createData(currentProgram, address, type, type.getLength(),
                DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
            currentProgram.getSymbolTable().createLabel(address, name,
                SourceType.USER_DEFINED).setPrimary();
        }
        println("floating-register-preparation=PASS");
    }

    private void verifyArmOpaqueReturn() {
        Function function = getFunctionAt(toAddr(labels.get("fp_clobbered")));
        var instruction = currentProgram.getListing()
            .getInstructionContaining(function.getBody().getMaxAddress());
        if (instruction == null || !instruction.getFlowType().isTerminal() ||
                instruction.getFallThrough() != null) {
            throw new IllegalStateException("expected terminal ARM floating fixture return");
        }
        boolean opaque = false;
        boolean returns = false;
        for (var operation : instruction.getPcode()) {
            if (operation.getOpcode() == PcodeOp.CALLOTHER &&
                    operation.getNumInputs() == 1 && operation.getInput(0).isConstant()) {
                String name = currentProgram.getLanguage().getUserDefinedOpName(
                    Math.toIntExact(operation.getInput(0).getOffset()));
                if ("setISAMode".equals(name)) {
                    opaque = true;
                    println("floating-register-arm-return=" + instruction.getAddress() +
                        " CALLOTHER " + name);
                }
            }
            returns |= operation.getOpcode() == PcodeOp.RETURN;
        }
        if (!opaque || !returns) {
            throw new IllegalStateException("ARM omission oracle requires setISAMode and RETURN");
        }
        println("floating-register-arm-opaque-return=PASS");
    }

    private void function(String name, DataType type, String[] registers, String[] names)
            throws Exception {
        Function function = getFunctionAt(toAddr(labels.get(name)));
        if (function == null) {
            throw new IllegalStateException("missing floating fixture function " + name);
        }
        function.setName(name, SourceType.USER_DEFINED);
        function.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);
        function.setReturnType(DataType.VOID, SourceType.USER_DEFINED);
        ParameterImpl[] parameters = new ParameterImpl[registers.length];
        for (int index = 0; index < registers.length; index++) {
            var register = currentProgram.getRegister(registers[index]);
            if (register == null) {
                throw new IllegalStateException("missing register " + registers[index]);
            }
            if (name.equals("fp_double") &&
                    "explicit-pieces".equals(System.getenv("FORGE_FP_STORAGE_FORM"))) {
                if (!"mips-fp32".equals(System.getenv("FORGE_FP_ABI_PROFILE"))) {
                    throw new IllegalStateException("explicit FPR pairs require the FP32 fixture");
                }
                // Ghidra joins are MSB first. The compiler/GDB FP32 oracle
                // establishes these physical high/low carriers independently.
                String[] pair = index == 0 ? new String[] { "f13", "f12" }
                    : new String[] { "f15", "f14" };
                var high = currentProgram.getRegister(pair[0]);
                var low = currentProgram.getRegister(pair[1]);
                var storage = new ghidra.program.model.listing.VariableStorage(currentProgram,
                    new ghidra.program.model.pcode.Varnode(high.getAddress(), 4),
                    new ghidra.program.model.pcode.Varnode(low.getAddress(), 4));
                parameters[index] = new ParameterImpl(names[index], type, storage, currentProgram,
                    SourceType.USER_DEFINED);
            }
            else {
                parameters[index] = new ParameterImpl(names[index], type, register, currentProgram,
                    SourceType.USER_DEFINED);
            }
        }
        function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE,
            true, SourceType.USER_DEFINED, parameters);
        if (name.equals("fp_double") &&
                "explicit-pieces".equals(System.getenv("FORGE_FP_STORAGE_FORM"))) {
            for (var parameter : function.getParameters()) {
                if (!function.hasCustomVariableStorage() ||
                        parameter.getVariableStorage().getVarnodeCount() != 2) {
                    throw new AssertionError("explicit two-register storage was not retained");
                }
                println("floating-fp32-pieces=" + parameter.getName() + " storage=" +
                    parameter.getVariableStorage());
            }
        }
        println("floating-register-function=" + name + " body=" + function.getBody());
    }
}
