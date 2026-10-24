package ghidradwarfforge;

import java.io.File;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;

/** Pinned real register/decoder controls plus adversarial ordered p-code. */
public final class RegisterCopySmoke {
    private RegisterCopySmoke() {
    }

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (String target : List.of("x86_64", "aarch64")) {
            for (int bytes : new int[] { 4, 8 }) {
                try (Fixture fixture = fixture(target, bytes, false)) {
                    controls(fixture);
                }
                try (Fixture decoded = fixture(target, bytes, true)) {
                    actualDecoded(decoded);
                }
            }
        }
        System.out.println("register-copy-smoke=PASS");
    }

    private static void controls(Fixture f) throws Exception {
        var original = f.node(f.incoming());
        var backup = f.node(f.saved());
        List<Instruction> good = f.instructions();
        expect(f, good, 0x1018);
        Parameter parameter = f.parameter();
        Program program = withInstructions(f.program(), good);
        var rejected = GhidraVariableStorage.stableParameter(program, f.function(), parameter,
            f.map(), TaskMonitor.DUMMY);
        require(rejected instanceof UnavailableStorage, "modified input became stable");
        var intervals = GhidraVariableStorage.parameterPrefix(program, f.function(), parameter,
            f.map(), rejected, TaskMonitor.DUMMY);
        require(intervals.size() == 2 && intervals.get(0).start() == 0x1000 &&
            intervals.get(0).end() == 0x100c && intervals.get(1).start() == 0x100c &&
            intervals.get(1).end() == 0x1018 && intervals.get(1).storage().available(),
            "public extraction lost exact handoff: " + intervals);
        Parameter mismatch = (Parameter) Proxy.newProxyInstance(Parameter.class.getClassLoader(),
            new Class<?>[] { Parameter.class }, (proxy, method, arguments) ->
                method.getName().equals("getFormalDataType")
                    ? (f.bytes() == 4 ? LongLongDataType.dataType : IntegerDataType.dataType)
                    : method.invoke(parameter, arguments));
        var limited = GhidraVariableStorage.parameterPrefix(program, f.function(), mismatch,
            f.map(), rejected, TaskMonitor.DUMMY);
        require(limited.size() == 2 && !limited.get(1).storage().available(),
            "formal/storage size disagreement invented a backup");
        Parameter storageMismatch = (Parameter) Proxy.newProxyInstance(Parameter.class.getClassLoader(),
            new Class<?>[] { Parameter.class }, (proxy, method, arguments) ->
                switch (method.getName()) {
                    case "getLength" -> f.bytes() == 4 ? 8 : 4;
                    case "getFormalDataType" -> f.bytes() == 4 ? LongLongDataType.dataType
                        : IntegerDataType.dataType;
                    default -> method.invoke(parameter, arguments);
                });
        var storageLimited = GhidraVariableStorage.parameterPrefix(program, f.function(),
            storageMismatch, f.map(), rejected, TaskMonitor.DUMMY);
        require(storageLimited.stream().filter(interval -> interval.storage().available()).count() <= 1,
            "physical storage width disagreement invented a backup");
        for (long destination : new long[] { 0x1004, 0x1001, 0x100d }) {
            int transaction = f.program().startTransaction("temporary secondary entry");
            try {
                f.program().getReferenceManager().addMemoryReference(f.address(0x2000),
                    f.address(destination), RefType.UNCONDITIONAL_JUMP, SourceType.USER_DEFINED, 0);
                require(hasReference(f.program(), f.address(0x2000), f.address(destination),
                    RefType.UNCONDITIONAL_JUMP), "secondary-entry fixture reference was not retained");
                require(GhidraVariableStorage.parameterPrefix(program, f.function(), parameter,
                    f.map(), rejected, TaskMonitor.DUMMY).isEmpty(),
                    "a secondary entry at " + destination + " could bypass the register copy");
            }
            finally {
                f.program().endTransaction(transaction, false);
            }
        }
        for (var type : List.of(RefType.DATA, RefType.UNCONDITIONAL_CALL)) {
            int transaction = f.program().startTransaction("harmless fixture reference");
            try {
                long from = 0x2000;
                long destination = type == RefType.DATA ? 0x1001 : 0x1000;
                f.program().getReferenceManager().addMemoryReference(f.address(from),
                    f.address(destination), type, SourceType.USER_DEFINED, 0);
                require(hasReference(f.program(), f.address(from), f.address(destination), type),
                    "positive fixture reference was not retained");
                var retained = GhidraVariableStorage.parameterPrefix(program, f.function(), parameter,
                    f.map(), rejected, TaskMonitor.DUMMY);
                require(retained.size() == 2 && retained.get(1).storage().available(),
                    "data, ordinary fallthrough or true-entry reference rejected the proof: " + type);
            }
            finally {
                f.program().endTransaction(transaction, false);
            }
        }
        var ordinaryReference = GhidraVariableStorage.parameterPrefix(
            withFallthrough(program, f.address(0x1000), f.address(0x1004)), f.function(),
            parameter, f.map(), rejected, TaskMonitor.DUMMY);
        require(ordinaryReference.size() == 2 && ordinaryReference.get(1).storage().available(),
            "ordinary adjacent decoded fallthrough was rejected");
        for (long[] edge : new long[][] { { 0x2000, 0x1004 }, { 0x2000, 0x1001 },
                { 0x1001, 0x1004 }, { 0x1000, 0x1001 } }) {
            require(GhidraVariableStorage.parameterPrefix(
                withFallthrough(program, f.address(edge[0]), f.address(edge[1])), f.function(),
                parameter, f.map(), rejected, TaskMonitor.DUMMY).isEmpty(),
                "external/offcut fallthrough could bypass the proof");
        }
        int externalTransaction = f.program().startTransaction("decoded external fallthrough source");
        try {
            var from = f.address(0x2000);
            var externalBody = new AddressSet(from, from.add(3));
            var block = f.program().getMemory().createInitializedBlock("external-code", from,
                4, (byte) 0, TaskMonitor.DUMMY, false);
            block.setExecute(true);
            f.program().getMemory().setBytes(from, HexFormat.of().parseHex(
                f.target().equals("x86_64") ? "90909090" : "1f2003d5"));
            require(new DisassembleCommand(from, externalBody, true).applyTo(f.program(), TaskMonitor.DUMMY),
                "external reference source did not decode");
            f.program().getReferenceManager().addMemoryReference(from, f.address(0x1001),
                RefType.FALL_THROUGH, SourceType.USER_DEFINED, 0);
            require(hasReference(f.program(), from, f.address(0x1001), RefType.FALL_THROUGH),
                "real external fallthrough reference was not retained");
            require(GhidraVariableStorage.parameterPrefix(program, f.function(), parameter,
                f.map(), rejected, TaskMonitor.DUMMY).isEmpty(),
                "real decoded external fallthrough bypassed the proof");
        }
        finally {
            f.program().endTransaction(externalTransaction, false);
        }

        // The location holds at the writing instruction; its next PC ends it.
        var partial = new Varnode(backup.getAddress().add(1), 1);
        expect(f, replace(good, 4, f.insn(4, f.op(PcodeOp.COPY,
            partial, f.constant(7, 1)))), 0x1014);
        var killed = replace(good, 4, f.insn(4, f.op(PcodeOp.COPY,
            backup, f.constant(7, f.bytes()))));
        var killIntervals = GhidraVariableStorage.parameterPrefix(
            withInstructions(f.program(), killed), f.function(), parameter, f.map(), rejected,
            TaskMonitor.DUMMY);
        require(killIntervals.size() == 3 && killIntervals.get(1).end() == 0x1014 &&
            killIntervals.get(2).start() == 0x1014 && !killIntervals.get(2).storage().available(),
            "backup write did not leave explicit unavailable tail");

        // No instruction-local partial result or same-instruction source kill
        // can publish a new backup. No copy after a kill resurrects the value.
        expect(f, replace(good, 0, f.insn(0, concatenate(f.copy(),
            f.op(PcodeOp.COPY, partial, f.constant(0, 1))))), -1);
        expect(f, replace(good, 0, f.insn(0, concatenate(f.copy(),
            f.op(PcodeOp.COPY, original, f.constant(0, f.bytes()))))), -1);
        expect(f, replace(good, 0, f.insn(0, concatenate(
            new PcodeOp[] { f.op(PcodeOp.COPY, original, f.constant(0, f.bytes())) },
            f.copy()))), -1);
        var noReacquire = replace(good, 1, f.insn(1,
            f.op(PcodeOp.COPY, backup, f.constant(0, f.bytes()))));
        noReacquire = replace(noReacquire, 2, f.insn(2, f.copy()));
        noReacquire = replace(noReacquire, 3, f.insn(3,
            f.op(PcodeOp.COPY, original, f.constant(0, f.bytes()))));
        expect(f, noReacquire, -1);
        expect(f, replace(good, 0, f.insn(0,
            f.op(PcodeOp.COPY, original, original))), -1);
        // A copy into a third register is not a new tracked candidate. Losing
        // the earliest completed backup cannot select this later chain.
        Varnode third = f.node(f.target().equals("x86_64")
            ? (f.bytes() == 4 ? "EDX" : "RDX") : (f.bytes() == 4 ? "w2" : "x2"));
        var chain = replace(good, 1, f.insn(1, f.op(PcodeOp.COPY, third, backup)));
        chain = replace(chain, 3, f.insn(3, f.op(PcodeOp.COPY,
            backup, f.constant(0, f.bytes()))));
        expect(f, chain, 0x1010);
        var laterCopy = replace(chain, 1, f.insn(1, f.op(PcodeOp.COPY, third, original)));
        expect(f, laterCopy, 0x1010);

        // Result objects are independent evidence: an uncovered register result
        // kills the proof even when raw p-code has no explicit output.
        expect(f, replace(good, 4, decorate(f.insn(4), "getResultObjects",
            new Object[] { f.program().getRegister(f.saved()).getBaseRegister() })), 0x1014);
        expect(f, replace(good, 0, decorate(good.get(0), "getResultObjects",
            new Object[] { f.program().getRegister(f.saved()).getBaseRegister() })), 0x1018);
        Register separateAlias = new Register("separate", "physical overlap outside parent tree",
            backup.getAddress().add(1), 1, false, 0);
        expect(f, replace(good, 4, decorate(f.insn(4), "getResultObjects",
            new Object[] { separateAlias })), 0x1014);
        expect(f, replace(good, 2, decorate(f.insn(2,
            f.op(PcodeOp.COPY, backup, original)), "getResultObjects",
                new Object[] { f.program().getRegister(f.incoming()).getBaseRegister() })), -1);
        Register separateOriginal = new Register("separate-original", "physical original overlap",
            original.getAddress().add(1), 1, false, 0);
        var ambiguousCopy = replace(good, 0, decorate(good.get(0), "getResultObjects",
            new Object[] { separateOriginal }));
        expect(f, ambiguousCopy, -1);
        require(GhidraVariableStorage.writesRegister(ambiguousCopy.get(0),
            f.program().getRegister(f.incoming()).getBaseRegister()),
            "physical original result bypassed the shared write proof");
        var shortPrefix = GhidraVariableStorage.parameterPrefix(
            withInstructions(f.program(), ambiguousCopy), f.function(), parameter, f.map(),
            rejected, TaskMonitor.DUMMY);
        require(shortPrefix.size() == 2 && shortPrefix.get(0).end() == 0x1004 &&
            shortPrefix.get(1).start() == 0x1004 && !shortPrefix.get(1).storage().available(),
            "caller original interval outlived the physically overlapping write");
        var earlierKill = replace(good, 1, decorate(f.insn(1), "getResultObjects",
            new Object[] { separateOriginal }));
        var earlyHandoff = GhidraVariableStorage.parameterPrefix(
            withInstructions(f.program(), earlierKill), f.function(), parameter, f.map(),
            rejected, TaskMonitor.DUMMY);
        require(earlyHandoff.size() == 2 && earlyHandoff.get(0).end() == 0x1008 &&
            earlyHandoff.get(1).start() == 0x1008 && earlyHandoff.get(1).storage().available(),
            "caller/helper disagree on physical-alias handoff");

        // An ordinary RAM STORE neither creates a memory fact nor kills a copy.
        Register pointer = f.program().getRegister(f.incoming()).getBaseRegister();
        Varnode offset = new Varnode(pointer.getAddress(), pointer.getMinimumByteSize());
        expect(f, replace(good, 3, f.insn(3, f.op(PcodeOp.STORE, null,
            f.constant(f.program().getAddressFactory().getDefaultAddressSpace().getSpaceID(), 4),
            offset, backup))), 0x1018);
        int registerSpace = backup.getAddress().getAddressSpace().getSpaceID();
        for (Varnode address : List.of(offset, f.constant(backup.getOffset() + 1, 8))) {
            expect(f, replace(good, 3, f.insn(3, f.op(PcodeOp.STORE, null,
                f.constant(registerSpace, 4), address, backup))), -1);
        }
        for (PcodeOp store : List.of(f.op(PcodeOp.STORE, null),
                f.op(PcodeOp.STORE, null, offset, offset, backup),
                f.op(PcodeOp.STORE, null, null, offset, backup))) {
            expect(f, replace(good, 3, f.insn(3, store)), -1);
        }
        // A STORE before the original kill invalidates the backup as well.
        expect(f, replace(good, 1, f.insn(1, f.op(PcodeOp.STORE, null,
            f.constant(registerSpace, 4), offset, backup))), -1);
        int memorySpace = f.program().getAddressFactory().getDefaultAddressSpace().getSpaceID();
        int unknownSpace = 0x12345678;
        require(f.program().getAddressFactory().getAddressSpace(unknownSpace) == null,
            "negative STORE space unexpectedly exists");
        for (long space : new long[] { unknownSpace,
                f.program().getAddressFactory().getConstantSpace().getSpaceID(),
                f.program().getAddressFactory().getUniqueSpace().getSpaceID(),
                Integer.toUnsignedLong(memorySpace) + (1L << 32) }) {
            expect(f, replace(good, 3, f.insn(3, f.op(PcodeOp.STORE, null,
                f.constant(space, 8), offset, backup))), -1);
        }
        expect(f, replace(good, 3, f.insn(3, f.op(PcodeOp.STORE, null,
            f.constant(memorySpace, 4), new Varnode(offset.getAddress(), 4), backup))), -1);
        var badStore = f.insn(1, f.op(PcodeOp.STORE, null,
            f.constant(unknownSpace, 4), offset, backup));
        var beforeHandoff = replace(good, 1, badStore);
        require(GhidraVariableStorage.parameterPrefix(withInstructions(f.program(), beforeHandoff),
            f.function(), parameter, f.map(), rejected, TaskMonitor.DUMMY).isEmpty(),
            "unproven STORE left an original-prefix interval");
        var noModeledWrite = replace(beforeHandoff, 2, f.insn(2));
        var unknownStore = GhidraVariableStorage.stableParameter(
            withInstructions(f.program(), noModeledWrite), f.function(), parameter,
            f.map(), TaskMonitor.DUMMY);
        require(unknownStore instanceof UnavailableStorage unavailable &&
            unavailable.reason() == ghidradwarfforge.locations.VariableStorageModel.OmissionReason.UNKNOWN_LIFETIME,
            "unproven STORE retained a whole-function stable register");

        // The same complete body gate applies even to hazards after the backup
        // would have been killed; no prefix-only scan can miss later effects.
        for (int opcode : new int[] { PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.CALLOTHER,
                PcodeOp.UNIMPLEMENTED, PcodeOp.BRANCH, PcodeOp.BRANCHIND, PcodeOp.CBRANCH }) {
            expect(f, replace(killed, 5, f.insn(5,
                f.op(opcode, null), f.returnOp())), -1);
        }
        for (Instruction hazard : List.of(
                decorate(good.get(4), "isLengthOverridden", true),
                decorate(good.get(4), "isFallThroughOverridden", true),
                decorate(good.get(4), "isInDelaySlot", true),
                decorate(good.get(4), "getDelaySlotDepth", 1),
                decorate(good.get(4), "getFlowOverride", FlowOverride.RETURN),
                decorate(good.get(4), "getFlowType", RefType.UNCONDITIONAL_CALL),
                decorate(good.get(4), "getFallThrough", f.address(0x1018)))) {
            expect(f, replace(good, 4, hazard), -1);
        }
        var otherSpace = new GenericAddressSpace("other-code", 64, AddressSpace.TYPE_RAM, 59);
        for (String api : List.of("getAddress", "getMaxAddress", "getFallThrough")) {
            long addressOffset = api.equals("getAddress") ? 0x1010 :
                api.equals("getMaxAddress") ? 0x1013 : 0x1014;
            expect(f, replace(good, 4, decorate(good.get(4), api,
                otherSpace.getAddress(addressOffset))), -1);
        }
        expect(f, replace(good, 5, decorate(good.get(5), "getFlowType",
            RefType.CONDITIONAL_TERMINATOR)), -1);
        expect(f, replace(good, 5, f.insn(5, f.op(PcodeOp.RETURN, null))), -1);
        expect(f, replace(good, 5, f.insn(5, f.returnOp(), f.op(PcodeOp.COPY,
            backup, backup))), -1);
        expect(f, replace(good, 4, f.insn(5)), -1);
        expect(f, good.subList(0, 5), -1);

        // Exact named width is essential: Ghidra returns a containing register
        // for an unnamed three-byte varnode. It is deliberately rejected here.
        var small = new Varnode(backup.getAddress(), 3);
        require(f.program().getRegister(small) != null &&
            f.program().getRegister(small).getBitLength() != 24,
            "fixture no longer exercises containing-register lookup");
        expect(f, replace(good, 0, f.insn(0, f.op(PcodeOp.COPY,
            small, new Varnode(original.getAddress(), 3)))), -1);
        expect(f, replace(good, 0, f.insn(0, f.op(PcodeOp.INT_ZEXT,
            backup, new Varnode(original.getAddress(), Math.max(1, f.bytes() / 2))))), -1);
        expect(f, replace(good, 0, f.insn(0, f.op(PcodeOp.COPY, backup))), -1);
        expect(f, replace(good, 0, f.insn(0, f.op(PcodeOp.INT_ZEXT,
            backup, original))), -1); // equal width is not ZEXT
        for (PcodeOp malformed : List.of(f.op(PcodeOp.COPY, null, backup),
                f.op(PcodeOp.COPY, backup), f.op(PcodeOp.COPY, backup, (Varnode) null),
                f.op(PcodeOp.COPY, backup, new Varnode(backup.getAddress(), 1)),
                f.op(PcodeOp.INT_ZEXT, backup, backup))) {
            expect(f, replace(good, 4, f.insn(4, malformed)), -1);
        }
        if (f.target().equals("x86_64")) {
            require(RegisterCopyLifetime.prove(f.program(), 0x1000, 0x1018, good,
                f.node("AH"), 1, f.map(), TaskMonitor.DUMMY) == null,
                "high incoming slice acquired a low-slice copy fact");
            var highOutput = replace(good, 0, f.insn(0,
                f.op(PcodeOp.COPY, f.node("AH"), f.node("DIL"))));
            require(RegisterCopyLifetime.prove(f.program(), 0x1000, 0x1018, highOutput,
                f.node("DIL"), 1, f.map(), TaskMonitor.DUMMY) == null,
                "high destination slice acquired a low-slice copy fact");
        }
        var unmapped = new TargetRegisterMap("test", "negative unmapped backup",
            Map.of(f.program().getRegister(f.incoming()).getBaseRegister().getName(), 99));
        require(RegisterCopyLifetime.prove(f.program(), 0x1000, 0x1018, good,
            original, f.bytes(), unmapped, TaskMonitor.DUMMY) == null,
            "unmapped copied register acquired a location");

        var cancelled = new TaskMonitorAdapter(true);
        cancelled.cancel();
        try {
            GhidraVariableStorage.parameterPrefix(program, f.function(), parameter,
                f.map(), rejected, cancelled);
            throw new AssertionError("cancelled public prefix proof completed");
        }
        catch (CancelledException expected) {
            // The reference/listing preflight must also honor cancellation.
        }
        try {
            RegisterCopyLifetime.prove(f.program(), 0x1000, 0x1018, good,
                original, f.bytes(), f.map(), cancelled);
            throw new AssertionError("cancelled copy proof completed");
        }
        catch (CancelledException expected) {
            // Propagate cancellation rather than returning a partial proof.
        }
    }

    private static void actualDecoded(Fixture f) throws Exception {
        var parameter = f.parameter();
        var rejected = GhidraVariableStorage.stableParameter(f.program(), f.function(),
            parameter, f.map(), TaskMonitor.DUMMY);
        require(rejected instanceof UnavailableStorage, "decoded input was not clobbered");
        var intervals = GhidraVariableStorage.parameterPrefix(f.program(), f.function(),
            parameter, f.map(), rejected, TaskMonitor.DUMMY);
        require(intervals.size() == 2 && intervals.stream().allMatch(i -> i.storage().available()),
            "decoded real copy did not extend the lifetime: " + intervals);
        require(intervals.get(1).storage() instanceof RegisterStorage register &&
            register.bitSize() == f.bytes() * 8 && register.valueBitOffset() == 0,
            "decoded copy lost its exact low-bit width");
        System.out.printf("decoded-copy=%s/%d intervals=%s PASS%n", f.target(), f.bytes(), intervals);
    }

    private static void expect(Fixture f, List<Instruction> instructions, long expected)
            throws Exception {
        var actual = RegisterCopyLifetime.prove(f.program(), 0x1000, 0x1018,
            instructions, f.node(f.incoming()), f.bytes(), f.map(), TaskMonitor.DUMMY);
        require(expected == -1 ? actual == null : actual != null && actual.end() == expected &&
            actual.storage().bitSize() == f.bytes() * 8 && actual.storage().valueBitOffset() == 0,
            f.target() + "/" + f.bytes() + " expected backup end " + expected + " got " + actual);
    }

    private static Fixture fixture(String target, int bytes, boolean decode) throws Exception {
        String id = target.equals("x86_64") ? "x86:LE:64:default" : "AARCH64:LE:64:v8A";
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(id));
        Object owner = new Object();
        ProgramDB program = new ProgramDB("register-copy", language,
            language.getDefaultCompilerSpec(), owner);
        boolean complete = false;
        try {
            int transaction = program.startTransaction("register-copy fixture");
            try {
                String encoded = target.equals("x86_64")
                    ? (bytes == 4 ? "89f8906631ffc3" : "4889f8904831ffc3")
                    : (bytes == 4 ? "e103002a1f2003d5e0031f2ac0035fd6"
                        : "e10300aa1f2003d5e0031faac0035fd6");
                byte[] code = decode ? HexFormat.of().parseHex(encoded) : new byte[24];
                var start = language.getDefaultSpace().getAddress(0x1000);
                var body = new AddressSet(start, start.add(code.length - 1));
                var block = program.getMemory().createInitializedBlock("code", start,
                    code.length, (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(start, code);
                if (decode) {
                    require(new DisassembleCommand(start, body, true).applyTo(program, TaskMonitor.DUMMY),
                        "actual copy fixture did not disassemble");
                }
                Function function = program.getFunctionManager().createFunction("copy", start,
                    body, SourceType.USER_DEFINED);
                complete = true;
                return new Fixture(target, bytes, program, function, owner);
            }
            finally {
                program.endTransaction(transaction, complete);
            }
        }
        finally {
            if (!complete) {
                program.release(owner);
            }
        }
    }

    private record Fixture(String target, int bytes, ProgramDB program, Function function,
            Object owner) implements AutoCloseable {
        public void close() { program.release(owner); }
        String incoming() {
            return target.equals("x86_64") ? (bytes == 4 ? "EDI" : "RDI")
                : (bytes == 4 ? "w0" : "x0");
        }
        String saved() {
            return target.equals("x86_64") ? (bytes == 4 ? "EAX" : "RAX")
                : (bytes == 4 ? "w1" : "x1");
        }
        TargetRegisterMap map() { return TargetRegisterMap.forTarget(target); }
        Parameter parameter() throws Exception {
            return new ParameterImpl("value", bytes == 4 ? IntegerDataType.dataType
                : LongLongDataType.dataType, program.getRegister(incoming()), program);
        }
        Varnode node(String name) {
            Register r = program.getRegister(name);
            return new Varnode(r.getAddress(), r.getMinimumByteSize());
        }
        Varnode constant(long value, int size) {
            return new Varnode(program.getAddressFactory().getConstantSpace().getAddress(value), size);
        }
        ghidra.program.model.address.Address address(long offset) {
            return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        }
        PcodeOp op(int opcode, Varnode output, Varnode... inputs) {
            return new PcodeOp(address(0x1000), 0, opcode, inputs, output);
        }
        PcodeOp[] copy() {
            if (bytes == 4 && target.equals("x86_64")) {
                return new PcodeOp[] { op(PcodeOp.COPY, node("EAX"), node("EDI")),
                    op(PcodeOp.INT_ZEXT, node("RAX"), node("EAX")) };
            }
            return new PcodeOp[] { op(bytes == 4 ? PcodeOp.INT_ZEXT : PcodeOp.COPY,
                bytes == 4 ? node("x1") : node(saved()), node(incoming())) };
        }
        PcodeOp returnOp() {
            return op(PcodeOp.RETURN, null, node(target.equals("x86_64") ? "RIP" : "x30"));
        }
        Instruction insn(int index, PcodeOp... operations) {
            var at = address(0x1000 + index * 4L);
            boolean returns = java.util.Arrays.stream(operations)
                .anyMatch(operation -> operation.getOpcode() == PcodeOp.RETURN);
            return (Instruction) Proxy.newProxyInstance(Instruction.class.getClassLoader(),
                new Class<?>[] { Instruction.class }, (proxy, method, arguments) ->
                    switch (method.getName()) {
                        case "getAddress" -> at;
                        case "getMaxAddress" -> at.add(3);
                        case "getFallThrough" -> returns ? null : at.add(4);
                        case "isInDelaySlot", "isLengthOverridden", "isFallThroughOverridden" -> false;
                        case "getDelaySlotDepth" -> 0;
                        case "getFlowOverride" -> FlowOverride.NONE;
                        case "getFlowType" -> returns ? RefType.TERMINATOR : RefType.FALL_THROUGH;
                        case "getPcode" -> operations;
                        case "getResultObjects" -> new Object[0];
                        default -> throw new AssertionError("unexpected instruction API " + method);
                    });
        }
        List<Instruction> instructions() {
            return List.of(insn(0, copy()), insn(1), insn(2,
                op(PcodeOp.COPY, node(incoming()), constant(0, bytes))), insn(3), insn(4),
                insn(5, returnOp()));
        }
    }

    private static PcodeOp[] concatenate(PcodeOp[] prefix, PcodeOp... suffix) {
        var result = new ArrayList<>(List.of(prefix));
        result.addAll(List.of(suffix));
        return result.toArray(PcodeOp[]::new);
    }

    private static List<Instruction> replace(List<Instruction> source, int index,
            Instruction replacement) {
        var result = new ArrayList<>(source);
        result.set(index, replacement);
        return List.copyOf(result);
    }

    private static Instruction decorate(Instruction original, String name, Object value) {
        return (Instruction) Proxy.newProxyInstance(Instruction.class.getClassLoader(),
            new Class<?>[] { Instruction.class }, (proxy, method, arguments) ->
                method.getName().equals(name) ? value : method.invoke(original, arguments));
    }

    private static Program withInstructions(Program real, List<Instruction> instructions) {
        Listing listing = (Listing) Proxy.newProxyInstance(Listing.class.getClassLoader(),
            new Class<?>[] { Listing.class }, (proxy, method, arguments) -> {
                if (!method.getName().equals("getInstructions")) {
                    throw new AssertionError("unexpected listing API " + method);
                }
                Iterator<Instruction> iterator = instructions.iterator();
                return new InstructionIterator() {
                    public boolean hasNext() { return iterator.hasNext(); }
                    public Instruction next() { return iterator.next(); }
                    public Iterator<Instruction> iterator() { return this; }
                };
            });
        return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
            new Class<?>[] { Program.class }, (proxy, method, arguments) ->
                method.getName().equals("getListing") ? listing : method.invoke(real, arguments));
    }

    private static Program withFallthrough(Program real,
            ghidra.program.model.address.Address from, ghidra.program.model.address.Address to) {
        // The pinned DB removes FALL_THROUGH refs with no decoded source. These
        // controlled metadata edges test the gate independently of that cleanup.
        Reference reference = (Reference) Proxy.newProxyInstance(Reference.class.getClassLoader(),
            new Class<?>[] { Reference.class }, (proxy, method, arguments) ->
                switch (method.getName()) {
                    case "getFromAddress" -> from;
                    case "getReferenceType" -> RefType.FALL_THROUGH;
                    default -> throw new AssertionError("unexpected reference API " + method);
                });
        ReferenceManager references = (ReferenceManager) Proxy.newProxyInstance(
            ReferenceManager.class.getClassLoader(), new Class<?>[] { ReferenceManager.class },
            (proxy, method, arguments) -> {
                if (method.getName().equals("getReferenceDestinationIterator")) {
                    return new AddressSet(to, to).getAddresses(true);
                }
                if (method.getName().equals("getReferencesTo")) {
                    Iterator<Reference> iterator = List.of(reference).iterator();
                    return new ReferenceIterator() {
                        public boolean hasNext() { return iterator.hasNext(); }
                        public Reference next() { return iterator.next(); }
                        public Iterator<Reference> iterator() { return this; }
                    };
                }
                throw new AssertionError("unexpected reference manager API " + method);
            });
        return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
            new Class<?>[] { Program.class }, (proxy, method, arguments) ->
                method.getName().equals("getReferenceManager") ? references : method.invoke(real, arguments));
    }

    private static boolean hasReference(Program program,
            ghidra.program.model.address.Address from, ghidra.program.model.address.Address to,
            ghidra.program.model.symbol.RefType type) {
        var references = program.getReferenceManager().getReferencesTo(to);
        while (references.hasNext()) {
            var reference = references.next();
            if (reference.getFromAddress().equals(from) && reference.getReferenceType() == type) {
                return true;
            }
        }
        return false;
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
