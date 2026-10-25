// Curates the compiler-oracle scalar/pointer signature and checks the SVC fixture.
// @category DWARF.Tests

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.AddressNormalizer;
import ghidradwarfforge.GhidraImageBase;

public class PrepareOpaqueRegisterEffects extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (getScriptArgs().length != 2) {
            throw new IllegalArgumentException("expected compiler labels file and listing profile");
        }
        long delta = AddressNormalizer.rebaseDelta(currentProgram.getImageBase().getOffset(),
            GhidraImageBase.originalImageBase(currentProgram));
        Map<String, Long> labels = new LinkedHashMap<>();
        for (String line : Files.readAllLines(Path.of(getScriptArgs()[0]))) {
            String[] parts = line.split(" ");
            labels.put(parts[0], Math.addExact(Long.decode(parts[1]), delta));
        }
        Function function = getFunctionAt(toAddr(labels.get("opaque_value")));
        if (function == null || function.getBody().getNumAddressRanges() != 1 ||
                !function.getEntryPoint().equals(function.getBody().getMinAddress())) {
            throw new IllegalStateException("expected one contiguous incoming-register fixture");
        }
        Register incoming = currentProgram.getRegister("w0");
        Register pointer = currentProgram.getRegister("x1");
        if (incoming == null || pointer == null || incoming.getBitLength() != 32 ||
                pointer.getBitLength() != 64) {
            throw new IllegalStateException("unexpected AArch64 fixture registers");
        }
        long expected = function.getEntryPoint().getOffset();
        int opaqueCount = 0;
        var instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            var instruction = instructions.next();
            if (instruction.getAddress().getOffset() != expected ||
                    instruction.isInDelaySlot() || instruction.getDelaySlotDepth() != 0 ||
                    instruction.getFlowOverride() != FlowOverride.NONE) {
                throw new IllegalStateException("fixture is not fully decoded ordinary code");
            }
            expected = Math.addExact(instruction.getMaxAddress().getOffset(), 1);
            for (Object result : instruction.getResultObjects()) {
                if (result instanceof Register register &&
                        register.getBaseRegister().equals(incoming.getBaseRegister())) {
                    throw new IllegalStateException("explicit incoming-register write masks SVC bug");
                }
            }
            for (var operation : instruction.getPcode()) {
                var output = operation.getOutput();
                if (output != null && output.isRegister()) {
                    long start = incoming.getBaseRegister().getAddress().getOffset();
                    long end = Math.addExact(start, incoming.getBaseRegister().getMinimumByteSize());
                    if (output.getAddress().getAddressSpace().equals(
                            incoming.getAddress().getAddressSpace()) &&
                            output.getOffset() < end &&
                            Math.addExact(output.getOffset(), output.getSize()) > start) {
                        throw new IllegalStateException("p-code explicitly overwrites incoming x0");
                    }
                }
                if (operation.getOpcode() == PcodeOp.CALLOTHER) {
                    opaqueCount++;
                    if (instruction.getAddress().getOffset() != labels.get("opaque_before") ||
                            !instruction.getMnemonicString().equalsIgnoreCase("svc") ||
                            !instruction.getFlowType().isFallthrough() ||
                            operation.getOutput() != null) {
                        throw new IllegalStateException("expected output-less fallthrough SVC");
                    }
                    println("opaque-pcode=" + instruction.getAddress() + " " + operation);
                }
                if (operation.getOpcode() == PcodeOp.CALL ||
                        operation.getOpcode() == PcodeOp.CALLIND ||
                        operation.getOpcode() == PcodeOp.BRANCH ||
                        operation.getOpcode() == PcodeOp.CBRANCH ||
                        operation.getOpcode() == PcodeOp.BRANCHIND ||
                        operation.getOpcode() == PcodeOp.UNIMPLEMENTED) {
                    throw new IllegalStateException("unexpected opaque-fixture control flow");
                }
            }
        }
        var store = getInstructionAt(toAddr(labels.get("opaque_store")));
        var terminal = getInstructionAt(toAddr(labels.get("opaque_return")));
        if (opaqueCount != 1 || store == null ||
                !store.getMnemonicString().equalsIgnoreCase("str") ||
                labels.get("opaque_store") <= labels.get("opaque_before") + 4 ||
                terminal == null || !terminal.getFlowType().isTerminal() ||
                terminal.getFallThrough() != null ||
                terminal.getMaxAddress().getOffset() != function.getBody().getMaxAddress().getOffset() ||
                expected != Math.addExact(function.getBody().getMaxAddress().getOffset(), 1)) {
            throw new IllegalStateException("unexpected SVC/store/return fixture boundaries");
        }

        var manager = currentProgram.getDataTypeManager();
        var integer = new IntegerDataType(manager);
        var pointerType = new PointerDataType(integer, 8, manager);
        function.setName("opaque_value", SourceType.USER_DEFINED);
        function.setReturnType(DataType.VOID, SourceType.USER_DEFINED);
        function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true,
            SourceType.USER_DEFINED,
            new ParameterImpl("value", integer, incoming, currentProgram, SourceType.USER_DEFINED),
            new ParameterImpl("destination", pointerType, pointer, currentProgram,
                SourceType.USER_DEFINED));
        var sink = toAddr(labels.get("opaque_sink"));
        DataUtilities.createData(currentProgram, sink, integer, integer.getLength(),
            DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
        currentProgram.getSymbolTable().createLabel(sink, "opaque_sink",
            SourceType.USER_DEFINED).setPrimary();
        String profile = getScriptArgs()[1];
        if (profile.equals("gap")) {
            var body = new ghidra.program.model.address.AddressSet(function.getBody());
            var start = toAddr(labels.get("opaque_before"));
            var end = getInstructionAt(start).getMaxAddress();
            byte[] bytes = getBytes(start, Math.toIntExact(end.subtract(start) + 1));
            currentProgram.getListing().clearCodeUnits(start, end, false);
            function.setBody(body);
            if (getInstructionAt(start) != null || !function.getBody().equals(body) ||
                    !java.util.Arrays.equals(bytes, getBytes(start, bytes.length))) {
                throw new IllegalStateException("failed to preserve bytes/body around listing gap");
            }
            println("opaque-listing-gap=" + start + ".." + end);
        }
        else if (!profile.equals("complete")) {
            throw new IllegalArgumentException("unknown listing profile " + profile);
        }
        println("opaque-register-preparation=PASS body=" + function.getBody());
    }
}
