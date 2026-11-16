package ghidradwarfforge;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.targets.I386ParameterAllocation;

/** Actual i386 compiler-model limits, without editing computed or analyst storage. */
final class I386AllocationBoundarySmoke {
    private static int checks;
    private static long nextAddress;

    private I386AllocationBoundarySmoke() { }

    static void run() throws Exception {
        checks = 0;
        nextAddress = 0x1000;
        Object owner = new Object();
        var program = program("x86:LE:32:default", owner);
        var foreign = program("x86:LE:32:default", owner);
        var differentLanguage = program("x86:LE:64:default", owner);
        Path file = Files.createTempFile("forge-i386-boundaries-", ".elf");
        int transaction = program.startTransaction("allocation boundaries");
        int foreignTransaction = foreign.startTransaction("foreign allocation");
        try {
            profiles(program, differentLanguage, file);
            Files.write(file, header(2, 3, 0, 0, 0));
            var image = ElfImage.read(file);
            var policy = I386ParameterAllocation.forProgram(program, image, TaskMonitor.DUMMY, ignored -> { });
            require(policy.hasReturnCorrections(), "audited i386 profile advertises return correction");
            ghidradwarfforge.targets.I386StackInputProofSmoke.run(program);
            limits(program, policy);
            unassignedAggregate(program, policy);
            ownership(program, foreign, policy);
            aliases(program, policy);
            cancellation(program, image, policy);
        }
        finally {
            foreign.endTransaction(foreignTransaction, false);
            program.endTransaction(transaction, false);
            program.release(owner);
            foreign.release(owner);
            differentLanguage.release(owner);
            Files.deleteIfExists(file);
        }
        System.out.println("i386-allocation-boundaries=PASS checks=" + checks);
    }

    private static ProgramDB program(String languageId, Object owner) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
        return new ProgramDB("i386-allocation-boundary", language,
            language.getCompilerSpecByID(new CompilerSpecID("gcc")), owner);
    }

    private static void profiles(ProgramDB program, ProgramDB differentLanguage, Path file) throws Exception {
        // type, machine, OS ABI, ABI revision, flags, selected language, expected eligibility
        int[][] profiles = {
            { 2, 3, 0, 0, 0, 0, 1 }, { 3, 3, 0, 0, 0, 0, 1 },
            { 2, 3, 3, 0, 0, 0, 1 }, { 3, 3, 3, 0, 0, 0, 1 },
            { 1, 3, 0, 0, 0, 0, 0 }, { 2, 40, 0, 0, 0, 0, 0 },
            { 2, 3, 0, 1, 0, 0, 0 }, { 2, 3, 0, 255, 0, 0, 0 },
            { 2, 3, 9, 0, 0, 0, 0 }, { 2, 3, 0, 0, 1, 0, 0 },
            { 2, 3, 0, 0, 0, 1, 0 }
        };
        for (int[] profile : profiles) {
            byte[] bytes = header(profile[0], profile[1], profile[2], profile[3], profile[4]);
            Files.write(file, bytes);
            ProgramDB selected = profile[5] == 0 ? program : differentLanguage;
            var diagnostics = new ArrayList<String>();
            var policy = I386ParameterAllocation.forProgram(selected, ElfImage.read(file), TaskMonitor.DUMMY, diagnostics::add);
            require(policy.hasReturnCorrections() == (profile[6] == 1), "exact ELF/compiler profile: " + Arrays.toString(profile));
            require((policy == GhidraParameterAllocation.UNCHANGED) == (profile[6] == 0), "unadmitted profile receives no correction policy");
            require(diagnostics.isEmpty() && Arrays.equals(bytes, Files.readAllBytes(file)), "profile inspection leaves original ELF unchanged");
        }
    }

    private static void limits(ProgramDB program, GhidraParameterAllocation policy) throws Exception {
        var extended = new LongDoubleDataType(program.getDataTypeManager());
        // The pinned x86gcc.cspec input region is 500 bytes. With the saved
        // automatic return pointer it fits 124 explicit four-byte integers.
        // Count admission alone is not proof that all storage was allocated.
        for (int count : List.of(0, 1, 124, 125, 126, 4095, 4096)) {
            var signature = signature(program, extended, count);
            String before = signature.getPrototypeString();
            var monitor = new CountingMonitor(Integer.MAX_VALUE);
            GhidraParameterAllocation.SignatureResolution result;
            try { result = policy.resolveSignature(signature, monitor); }
            catch (IllegalStateException unexpected) {
                throw new AssertionError("bounded real signature must be corrected or conservatively declined", unexpected);
            }
            if (count <= 125) {
                require(result != null, "admit complete compiler-proven call allocation");
                carrier(result.returnStorage());
                require(result.parameters().size() == count, "call signature retains every explicit argument");
                for (int index = 0; index < count; index++) stack(result.parameters().get(index), index);
            }
            else require(result == null, "incomplete or excessive call signature remains uncorrected");
            if (count == 4096) require(monitor.visits == 1, "count limit rejects before traversing argument types");
            require(signature.getPrototypeString().equals(before), "call correction does not rewrite formal signature");

            var function = function(program, extended, count, "__cdecl");
            before = snapshot(function);
            require(function.getParameterCount() == count + 1 && function.getParameters()[0].isAutoParameter(),
                "actual baseline exposes one automatic result pointer");
            if (count > 124) require(function.getParameters()[count].getVariableStorage().isUnassignedStorage(),
                "saved compiler allocation supplies no carrier beyond its bounded input region");
            GhidraParameterAllocation.Resolution resolved;
            try { resolved = policy.resolve(function, TaskMonitor.DUMMY, ignored -> { }); }
            catch (IllegalStateException unexpected) {
                throw new AssertionError("real bounded definition must preserve available and unavailable arguments", unexpected);
            }
            if (count <= 4095) {
                carrier(resolved.returnStorage());
                int proven = Math.min(count, 125);
                require(resolved.omittedAutomaticParameters().equals(Set.of(0)) && resolved.storage().size() == proven,
                    "omit only automatic pointer; map only compiler-proven explicit carriers");
                for (int index = 0; index < proven; index++) stack(resolved.storage().get(index + 1), index);
                for (int index = proven; index < count; index++) require(!resolved.storage().containsKey(index + 1),
                    "arguments outside the adjusted region acquire no fabricated storage");
                require(policy.corrections(function, TaskMonitor.DUMMY, ignored -> { }).equals(resolved.storage()),
                    "corrections entrypoint agrees with resolved definition");
                require(policy.resolveDeclaration(function, TaskMonitor.DUMMY, ignored -> { }).equals(resolved),
                    "external declaration entrypoint uses the same effective allocation");
            }
            else unchanged(resolved, "oversized saved definition");
            require(resolved.equals(policy.resolve(function, TaskMonitor.DUMMY, ignored -> { })), "allocation is deterministic");
            require(snapshot(function).equals(before), "computed correction preserves saved types, ordinals and storage");
        }
    }

    private static void ownership(ProgramDB program, ProgramDB foreign, GhidraParameterAllocation policy) throws Exception {
        var alien = function(foreign, new LongDoubleDataType(foreign.getDataTypeManager()), 2, "__cdecl");
        String before = snapshot(alien);
        unchanged(policy.resolve(alien, TaskMonitor.DUMMY, ignored -> { }), "foreign program");
        require(snapshot(alien).equals(before), "foreign signature unchanged");
        var otherConvention = function(program, new LongDoubleDataType(program.getDataTypeManager()), 2, "__stdcall");
        before = snapshot(otherConvention);
        unchanged(policy.resolve(otherConvention, TaskMonitor.DUMMY, ignored -> { }), "nondefault saved calling convention");
        require(snapshot(otherConvention).equals(before), "saved nondefault convention unchanged");
    }

    private static void unassignedAggregate(ProgramDB program, GhidraParameterAllocation policy) throws Exception {
        var manager = program.getDataTypeManager();
        var large = new StructureDataType("BeyondStackInputRegion", 600, manager);
        var extended = new LongDoubleDataType(manager);
        var function = function(program, extended, 0, "__cdecl");
        function.updateFunction("__cdecl", new ReturnParameterImpl(extended, program),
            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
            new ParameterImpl("large", large, program));
        require(function.getParameterCount() == 2 && function.getParameters()[1].getVariableStorage().isUnassignedStorage(),
            "real compiler leaves oversized by-value aggregate unassigned");
        String before = snapshot(function);
        GhidraParameterAllocation.Resolution resolved;
        try { resolved = policy.resolve(function, TaskMonitor.DUMMY, ignored -> { }); }
        catch (IllegalStateException unexpected) {
            throw new AssertionError("definition correction must preserve genuinely unassigned aggregate storage", unexpected);
        }
        carrier(resolved.returnStorage());
        require(resolved.storage().isEmpty() && resolved.omittedAutomaticParameters().equals(Set.of(0)),
            "correct result pointer while preserving genuinely unassigned aggregate storage");
        require(snapshot(function).equals(before), "unassigned aggregate declaration and saved storage unchanged");
        var signature = signature(program, extended, 0);
        signature.setArguments(new ParameterDefinition[] { new ParameterDefinitionImpl("large", large, null) });
        require(policy.resolveSignature(signature, TaskMonitor.DUMMY) == null,
            "call override conservatively declines missing aggregate storage");
    }

    private static void aliases(ProgramDB program, GhidraParameterAllocation policy) throws Exception {
        var manager = program.getDataTypeManager();
        DataType type = new LongDoubleDataType(manager);
        for (int depth = 1; depth <= 65; depth++) {
            type = new TypedefDataType(CategoryPath.ROOT, "SavedExtendedDepth" + depth, type, manager);
            if (depth != 64 && depth != 65) continue;
            // TypeDef.getBaseDataType() resolves the whole chain in Ghidra's
            // public contract. These real chains do not exercise the exporter's
            // defensive loop-depth guard, and must not be made to fail for it.
            require(((TypeDef) type).getBaseDataType() instanceof LongDoubleDataType,
                "real typedef API supplies the underlying floating type");
            var signature = signature(program, type, 1);
            String before = signature.getPrototypeString();
            var result = policy.resolveSignature(signature, TaskMonitor.DUMMY);
            require(result != null, "real alias chain retains eligible return at depth " + depth);
            carrier(result.returnStorage());
            require(signature.getPrototypeString().equals(before), "typedef names and formal return retained");
            var function = function(program, type, 1, "__cdecl");
            before = snapshot(function);
            var saved = policy.resolve(function, TaskMonitor.DUMMY, ignored -> { });
            carrier(saved.returnStorage());
            require(snapshot(function).equals(before), "saved alias chain unchanged");
        }
    }

    private static void cancellation(ProgramDB program, ElfImage image, GhidraParameterAllocation policy) throws Exception {
        var extended = new LongDoubleDataType(program.getDataTypeManager());
        var function = function(program, extended, 9, "__cdecl");
        var signature = signature(program, extended, 9);
        String before = snapshot(function);
        String callBefore = signature.getPrototypeString();
        for (int operation = 0; operation < 3; operation++) {
            int selected = operation;
            var completed = new CountingMonitor(Integer.MAX_VALUE);
            invoke(selected, program, image, policy, function, signature, completed);
            for (int stop : new java.util.LinkedHashSet<>(List.of(1, completed.visits))) {
                var monitor = new CountingMonitor(stop);
                try {
                    invoke(selected, program, image, policy, function, signature, monitor);
                    throw new AssertionError("cancelled allocation returned a result");
                }
                catch (CancelledException expected) { require(monitor.visits == stop, "cancel promptly at observed traversal boundary"); }
                require(snapshot(function).equals(before) && signature.getPrototypeString().equals(callBefore),
                    "cancelled calculation preserves saved definition and call signature");
            }
        }
    }

    private static void invoke(int operation, ProgramDB program, ElfImage image, GhidraParameterAllocation policy,
            Function function, FunctionDefinitionDataType signature, TaskMonitor monitor) throws Exception {
        if (operation == 0) I386ParameterAllocation.forProgram(program, image, monitor, ignored -> { });
        else if (operation == 1) policy.resolveSignature(signature, monitor);
        else policy.resolve(function, monitor, ignored -> { });
    }

    private static final class CountingMonitor extends TaskMonitorAdapter {
        private final int stop;
        private int visits;
        private CountingMonitor(int stop) { super(true); this.stop = stop; }
        @Override public void checkCancelled() throws CancelledException { if (++visits == stop) throw new CancelledException(); }
    }

    private static FunctionDefinitionDataType signature(ProgramDB program, DataType returned, int count) throws Exception {
        var type = new FunctionDefinitionDataType("CallBoundary", program.getDataTypeManager());
        type.setReturnType(returned);
        var arguments = new ParameterDefinition[count];
        for (int index = 0; index < count; index++) arguments[index] = new ParameterDefinitionImpl("arg" + index,
            new IntegerDataType(program.getDataTypeManager()), null);
        type.setArguments(arguments);
        type.setCallingConvention("__cdecl");
        return type;
    }

    private static Function function(ProgramDB program, DataType returned, int count, String convention) throws Exception {
        var entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(nextAddress);
        nextAddress += 0x10;
        var function = program.getFunctionManager().createFunction("boundary_" + nextAddress, entry,
            new AddressSet(entry, entry), SourceType.USER_DEFINED);
        var arguments = new Parameter[count];
        for (int index = 0; index < count; index++) arguments[index] = new ParameterImpl("arg" + index,
            new IntegerDataType(program.getDataTypeManager()), program);
        function.updateFunction(convention, new ReturnParameterImpl(returned, program),
            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED, arguments);
        return function;
    }

    private static void carrier(VariableStorage storage) {
        require(storage != null && storage.isRegisterStorage() && storage.size() == 10 && storage.getRegister().getName().equals("ST0"),
            "SysV extended float is returned in ten-byte ST0");
    }

    private static void stack(VariableStorage storage, int index) {
        require(storage != null && storage.isStackStorage() && storage.size() == 4 && storage.getStackOffset() == 4L + 4L * index &&
            !storage.isAutoStorage() && !storage.isForcedIndirect(), "integer argument uses its exact stack slot after return address");
    }

    private static void unchanged(GhidraParameterAllocation.Resolution result, String label) {
        require(result.storage().isEmpty() && result.omittedAutomaticParameters().isEmpty() && result.returnStorage() == null,
            label + " cannot receive an allocation correction");
    }

    private static String snapshot(Function function) {
        return function.getPrototypeString(false, false) + ":" + function.getReturn().getVariableStorage() + ":" +
            Arrays.stream(function.getParameters()).map(p -> p.getName() + ":" + p.getOrdinal() + ":" + p.getFormalDataType().getPathName() +
                ":" + p.getVariableStorage() + ":" + p.getSource()).toList();
    }

    private static byte[] header(int type, int machine, int osAbi, int revision, int flags) {
        var bytes = ByteBuffer.allocate(52).order(ByteOrder.LITTLE_ENDIAN);
        bytes.putInt(0, 0x464c457f);
        bytes.put(4, (byte) 1); bytes.put(5, (byte) 1); bytes.put(6, (byte) 1);
        bytes.put(7, (byte) osAbi); bytes.put(8, (byte) revision);
        bytes.putShort(16, (short) type); bytes.putShort(18, (short) machine); bytes.putInt(20, 1);
        bytes.putInt(36, flags); bytes.putShort(40, (short) 52); bytes.putShort(42, (short) 32); bytes.putShort(46, (short) 40);
        return bytes.array();
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
