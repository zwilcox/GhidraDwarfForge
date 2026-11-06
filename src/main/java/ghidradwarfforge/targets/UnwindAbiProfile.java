package ghidradwarfforge.targets;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.AddressNormalizer;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.unwind.GhidraUnwindInstructions;
import ghidradwarfforge.unwind.UnwindFlow.*;

/** Ordinary integer profiles only; pinned ABI sources are in UNWIND-ABI-AUDIT.md. */
public final class UnwindAbiProfile {
    public record Description(String id, int machine, String language, String compiler,
            String convention, int stackNumber, int returnNumber, int counterNumber,
            int entryCfaOffset, int returnStackAdjustment, boolean stackReturn,
            List<String> registers, Set<Integer> calleeSaved, List<String> flags,
            Set<String> mnemonics, String modeRegister, BigInteger modeValue, String provenance) {
        public Description {
            registers = List.copyOf(registers);
            calleeSaved = Set.copyOf(calleeSaved);
            flags = List.copyOf(flags);
            mnemonics = Set.copyOf(mnemonics);
        }
    }

    public record Bound(Description description, Map<Integer, Cell> registers,
            List<Cell> permittedCells, Cell stackPointer, Cell programCounter, State entry) {
        public Bound {
            registers = Collections.unmodifiableMap(new LinkedHashMap<>(registers));
            permittedCells = List.copyOf(permittedCells);
        }
        public Set<Cell> calleeSavedCells() {
            var result = new LinkedHashSet<Cell>();
            for (int number : description.calleeSaved()) result.add(registers.get(number));
            return Collections.unmodifiableSet(result);
        }
        /** Guard hidden/unsupported semantics before interpreting native p-code. */
        public void requireInstruction(Instruction instruction, TaskMonitor monitor) throws CancelledException {
            monitor.checkCancelled();
            String mnemonic = instruction.getMnemonicString().toLowerCase(Locale.ROOT);
            if (!description.mnemonics().contains(mnemonic)) {
                throw new IllegalArgumentException("instruction is outside the audited ordinary profile: " + mnemonic);
            }
            if (!description.modeRegister().isEmpty()) {
                Register register = instruction.getProgram().getRegister(description.modeRegister());
                var value = register == null ? null : instruction.getRegisterValue(register);
                if (value == null || !description.modeValue().equals(value.getUnsignedValue())) {
                    throw new IllegalArgumentException("instruction mode is unproved for " + description.id());
                }
            }
            var operations = instruction.getPcode();
            if (operations == null || operations.length > 4096) {
                throw new IllegalArgumentException("missing or unbounded instruction semantics");
            }
            for (var operation : operations) {
                monitor.checkCancelled();
                var nodes = new ArrayList<Varnode>(List.of(operation.getInputs()));
                if (operation.getOutput() != null) nodes.add(operation.getOutput());
                for (Varnode node : nodes) {
                    if (!node.isRegister()) continue;
                    boolean allowed = permittedCells.stream().anyMatch(cell -> node.getSize() <= cell.bytes() &&
                        node.getOffset() >= cell.offset() && node.getOffset() - cell.offset() <= cell.bytes() - node.getSize());
                    if (!allowed) throw new IllegalArgumentException("register effect is outside the audited integer profile: " + node);
                }
            }
        }
    }

    private static final List<Description> PROFILES = List.of(x86(), arm());
    private UnwindAbiProfile() { }

    /** Metadata selection is not proof of byte agreement or of a callee's behavior. */
    public static Bound select(Program program, Function function, ElfImage image, long rebaseDelta,
            TaskMonitor monitor) throws CancelledException {
        monitor.checkCancelled();
        byte[] header = image.headerBytes();
        int osAbi = Byte.toUnsignedInt(header[7]);
        if (!image.is64Bit() || image.byteOrder() != ByteOrder.LITTLE_ENDIAN ||
                (image.type() != 2 && image.type() != 3) || image.flags() != 0 ||
                (osAbi != 0 && osAbi != 3) || header[8] != 0 ||
                program.getDefaultPointerSize() != 8 || program.getLanguage().isBigEndian()) {
            throw new IllegalArgumentException("ELF or program is outside the selected ordinary unwind ABIs");
        }
        Description selected = PROFILES.stream().filter(profile -> profile.machine() == image.machine() &&
            profile.language().equals(program.getLanguageID().getIdAsString()) &&
            profile.compiler().equals(program.getCompilerSpec().getCompilerSpecID().getIdAsString())).findFirst()
            .orElseThrow(() -> new IllegalArgumentException("no audited unwind language/compiler profile"));
        long entry = ByteBuffer.wrap(header).order(image.byteOrder()).getLong(24);
        if (entry != 0 && AddressNormalizer.toElfAddress(function.getEntryPoint().getOffset(), rebaseDelta) == entry) {
            throw new IllegalArgumentException("ELF process entry is not an ordinary called frame");
        }
        var fallback = program.getCompilerSpec().getDefaultCallingConvention();
        var convention = function.getCallingConvention();
        if (convention == null && function.hasUnknownCallingConventionName()) convention = fallback;
        if (function.isExternal() || function.isThunk() || function.hasCustomVariableStorage() ||
                function.getCallFixup() != null || convention == null || convention.isErrorPlaceholder() ||
                !selected.convention().equals(convention.getName()) || fallback == null ||
                !selected.convention().equals(fallback.getName()) ||
                convention.getStackshift() != selected.entryCfaOffset() ||
                convention.getExtrapop() != selected.returnStackAdjustment() ||
                (function.isStackPurgeSizeValid() && function.getStackPurgeSize() != 0)) {
            throw new IllegalArgumentException("function convention is not the audited ordinary ABI");
        }
        var cells = new LinkedHashMap<Integer, Cell>();
        for (int number = 0; number < selected.registers().size(); number++) {
            monitor.checkCancelled();
            Register register = program.getRegister(selected.registers().get(number));
            if (register == null || register.getBitLength() != 64 || register.getMinimumByteSize() != 8) {
                throw new IllegalArgumentException("profile register width/name is unavailable");
            }
            Cell cell = GhidraUnwindInstructions.cell(new Varnode(register.getAddress(), 8));
            if (cells.containsValue(cell)) throw new IllegalArgumentException("profile registers alias unexpectedly");
            cells.put(number, cell);
        }
        Cell stackPointer = cells.get(selected.stackNumber());
        Register actualStack = program.getCompilerSpec().getStackPointer();
        if (actualStack == null || !stackPointer.equals(GhidraUnwindInstructions.cell(
                new Varnode(actualStack.getAddress(), actualStack.getMinimumByteSize())))) {
            throw new IllegalArgumentException("compiler stack register differs from the audited ABI");
        }
        var allowed = new ArrayList<>(cells.values());
        for (String name : selected.flags()) {
            monitor.checkCancelled();
            Register register = program.getRegister(name);
            if (register != null) allowed.add(GhidraUnwindInstructions.cell(
                new Varnode(register.getAddress(), register.getMinimumByteSize())));
        }
        var values = new LinkedHashMap<Cell, Value>();
        for (var item : cells.entrySet()) {
            if (item.getKey() != selected.stackNumber() && item.getKey() != selected.counterNumber()) {
                values.put(item.getValue(), new Incoming(item.getKey(), 8));
            }
        }
        values.put(stackPointer, new StackAddress(0, 8));
        Map<Slot, Value> memory = Map.of();
        if (selected.stackReturn()) memory = Map.of(new Slot(0, 8), new ReturnAddress(8));
        else values.put(cells.get(selected.returnNumber()), new ReturnAddress(8));
        monitor.checkCancelled();
        return new Bound(selected, cells, allowed, stackPointer, cells.get(selected.counterNumber()), new State(values, memory));
    }

    private static Set<String> words(String words) { return Set.of(words.split(" ")); }
    private static Description x86() {
        return new Description("x86-64-sysv-integer", 62, "x86:LE:64:default", "gcc", "__stdcall", 7, 16, 16,
            8, 8, true, List.of("RAX", "RDX", "RCX", "RBX", "RSI", "RDI", "RBP", "RSP",
                "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RIP"),
            Set.of(3, 6, 12, 13, 14, 15), List.of("CF", "PF", "AF", "ZF", "SF", "OF", "DF", "rflags"),
            words("push pop mov movsx movsxd movzx lea add sub cmp test and or xor inc dec neg not imul mul div idiv shl shr sal sar rol ror nop call ret leave jmp jz jnz jg jge jl jle ja jae jb jbe jo jno js jns jp jnp"),
            "longMode", BigInteger.ONE, "AMD64 psABI e1ce098331da5dbd66e1ffc74162380bcc213236");
    }
    private static Description arm() {
        var registers = new ArrayList<String>();
        for (int number = 0; number <= 30; number++) registers.add("x" + number);
        registers.add("sp"); registers.add("pc");
        var saved = new LinkedHashSet<Integer>();
        for (int number = 19; number <= 29; number++) saved.add(number);
        return new Description("aarch64-aapcs64-integer", 183, "AARCH64:LE:64:v8A", "default", "__cdecl", 31, 30, 32,
            0, 0, false, List.copyOf(registers), Set.copyOf(saved),
            List.of("NG", "ZR", "CY", "OV", "shift_carry", "tmpCY", "tmpOV", "tmpNG", "tmpZR"),
            words("add adds sub subs mov movk movn movz stp ldp str ldr stur ldur strb ldrb strh ldrh ldrsw cmp cmn tst and ands orr eor bic bics orn eon lsl lsr asr ror ubfx sbfx uxtb uxth sxtb sxth sxtw adr adrp cbz cbnz tbz tbnz b bl blr br ret nop b.eq b.ne b.cs b.hs b.cc b.lo b.mi b.pl b.vs b.vc b.hi b.ls b.ge b.lt b.gt b.le b.al b.nv"),
            "", BigInteger.ZERO, "AAPCS64/AADWARF64 2025Q4 daa7a94ca55973736c0e434a67a6e4bbcd35d7fa");
    }
}
