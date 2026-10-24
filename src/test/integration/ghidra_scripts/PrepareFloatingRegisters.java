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
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.AddressNormalizer;
import ghidradwarfforge.GhidraImageBase;

public class PrepareFloatingRegisters extends GhidraScript {
    private final Map<String, Long> labels = new LinkedHashMap<>();
    private long delta;

    @Override
    protected void run() throws Exception {
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
            parameters[index] = new ParameterImpl(names[index], type, register, currentProgram,
                SourceType.USER_DEFINED);
        }
        function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE,
            true, SourceType.USER_DEFINED, parameters);
        println("floating-register-function=" + name + " body=" + function.getBody());
    }
}
