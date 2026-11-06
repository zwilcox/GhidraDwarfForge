package ghidradwarfforge.unwind;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.unwind.CallFramePlan.*;

/** Test-only native byte/range importer. Production original-byte agreement is separate. */
public final class UnwindFrameRecoveryProbe {
    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        ElfImage image = ElfImage.read(Path.of(args[1]));
        boolean arm = image.machine() == 183;
        if (!arm && image.machine() != 62) throw new IllegalArgumentException("unsupported probe target");
        long rebase = Long.decode(args[4]);
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(arm ? "AARCH64:LE:64:v8A" : "x86:LE:64:default"));
        Object owner = new Object();
        var program = new ProgramDB("recovered-frame-probe", language,
            language.getCompilerSpecByID(new CompilerSpecID(arm ? "default" : "gcc")), owner);
        try {
            int transaction = program.startTransaction("original fixture bytes");
            try {
                var functions = new LinkedHashMap<String, Function>();
                var records = Files.readAllLines(Path.of(args[2]));
                for (String line : records) {
                    String[] fields = line.split(" ");
                    byte[] bytes = HexFormat.of().parseHex(fields[2]);
                    var address = language.getDefaultSpace().getAddress(Long.parseUnsignedLong(fields[1], 16));
                    program.getMemory().createInitializedBlock(fields[0], address, bytes.length,
                        (byte) 0, TaskMonitor.DUMMY, false).setExecute(true);
                    program.getMemory().setBytes(address, bytes);
                }
                for (String line : records) {
                    String[] fields = line.split(" ");
                    var entry = language.getDefaultSpace().getAddress(Long.parseUnsignedLong(fields[1], 16));
                    var body = new AddressSet(entry, entry.add(fields[2].length() / 2 - 1));
                    if (!new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY)) {
                        throw new AssertionError("fixture decoding failed");
                    }
                    functions.put(fields[0], program.getFunctionManager().createFunction(fields[0], entry, body, SourceType.USER_DEFINED));
                }
                if (rebase != 0) program.setImageBase(program.getImageBase().add(rebase), true);
                var evidence = GhidraUnwindCalls.verify(program, functions.get("cf_recurse"), image, rebase, TaskMonitor.DUMMY);
                var planned = GhidraUnwindFrames.plan(evidence, rebase, TaskMonitor.DUMMY);
                if (planned.observations().stream().anyMatch(row -> !row.projection().covered())) throw new AssertionError("fixture has omitted rows");
                writePlan(Path.of(args[3]), planned.plan());
                var observations = new StringBuilder();
                evidence.captures().forEach((function, captured) -> observations.append(function).append(' ').append(captured).append('\n'));
                planned.observations().forEach(row -> observations.append(row).append('\n'));
                Files.writeString(Path.of(args[3] + ".evidence.txt"), observations.toString());
                System.out.println("recovered-frame-plan=PASS frames=" + planned.plan().frames().size() + " instructions=" + planned.observations().size());
            }
            finally { program.endTransaction(transaction, false); }
        }
        finally { program.release(owner); }
    }
    private static String rule(Rule rule) {
        return switch (rule) {
            case Undefined ignored -> "u";
            case SameValue ignored -> "s";
            case AtCfaOffset at -> "m:" + at.offset();
            case CfaValue value -> "v:" + value.offset();
            case InRegister register -> "r:" + register.register();
        };
    }
    private static String rules(java.util.Map<Integer, Rule> rules) {
        return String.join(",", rules.entrySet().stream().map(item -> item.getKey() + ":" + rule(item.getValue())).toList());
    }
    private static void writePlan(Path path, CallFramePlan plan) throws Exception {
        var out = new StringBuilder(plan.addressBytes() + " little " + plan.returnRegister() + " " +
            String.join(",", plan.registers().stream().map(String::valueOf).toList()) + "\n");
        out.append("initial ").append(rules(plan.initialRules())).append('\n');
        for (Frame frame : plan.frames()) {
            out.append("frame ").append(Long.toUnsignedString(frame.address(), 16)).append(' ')
                .append(Long.toHexString(frame.size())).append('\n');
            for (Row row : frame.rows()) out.append("row ").append(Long.toUnsignedString(row.address(), 16)).append(' ')
                .append(row.cfa().register()).append(' ').append(row.cfa().offset()).append(' ').append(rules(row.rules())).append('\n');
        }
        Files.writeString(path, out.toString());
    }
}
