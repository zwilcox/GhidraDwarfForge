package ghidradwarfforge;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.GhidraVtableBindings.Request;
import ghidradwarfforge.GhidraVtableBindings.Snapshot;
import ghidradwarfforge.GhidraVtableBindings.Status;
import ghidradwarfforge.targets.CxxAbiProfile;
import ghidradwarfforge.types.ClassScopeModel;
import ghidradwarfforge.types.InheritanceModel;

/** Real saved-option and FileBytes controls; no fabricated Program/Memory APIs. */
final class VtableInventorySmoke {
    private static final String GROUP = GhidraVtableBindings.OPTIONS_NAME;
    private static final TaskMonitor MONITOR = TaskMonitor.DUMMY;
    private static int checks;

    static int check(ProgramDB program, Request request, Snapshot expected) throws Exception {
        checks = 0;
        String target = expected.abi() == CxxAbiProfile.ITANIUM_X86_64 ? "x86_64" : "aarch64";
        var function = program.getFunctionManager().getFunctions(true).next();
        long delta = program.getImageBase().getOffset() - GhidraImageBase.originalImageBase(program);
        var functions = List.of(new ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol(
            function.getName(), function.getEntryPoint().getOffset() - delta, 4));
        var classes = GhidraTypeGraph.extract(program, functions, target, delta, MONITOR, ignored -> { }).classScopes();
        var messages = new ArrayList<String>();
        var baseline = GhidraVtableBindings.extract(program, classes, MONITOR, messages::add);
        require(baseline.size() == 1 && baseline.getFirst().classId() == request.classId() && messages.isEmpty(),
            "missing real extracted class/vtable binding");
        String key = "symbol-" + request.symbolId();
        String encoded = program.getOptions(GROUP).getString(key, null);

        var inferred = classes.bindings().stream().map(binding -> new ClassScopeModel.Binding(binding.classId(),
            binding.type(), ClassScopeModel.BindingSource.CURRENT_AUTO_THIS, binding.evidence())).toList();
        for (var restricted : List.of(ClassScopeModel.empty(),
                new ClassScopeModel(classes.scopes(), List.of(), classes.methods(), classes.inheritance()),
                new ClassScopeModel(classes.scopes(), inferred, classes.methods(), classes.inheritance()))) {
            messages.clear();
            require(GhidraVtableBindings.extract(program, restricted, MONITOR, messages::add).isEmpty() &&
                messages.stream().anyMatch(message -> message.contains("canonical class/inheritance is unavailable")),
                "unbound/inferred class admitted explicit table");
            unchanged(program, request, expected, encoded);
        }
        int[] visits = {0};
        GhidraVtableBindings.extract(program, classes, new TaskMonitorAdapter(true) {
            @Override public void checkCancelled() { visits[0]++; }
        }, ignored -> { });
        for (int stop : new int[] {1, visits[0] / 2, visits[0]}) {
            var monitor = new TaskMonitorAdapter(true) {
                private int calls;
                @Override public void checkCancelled() throws CancelledException {
                    if (++calls == stop) throw new CancelledException();
                }
            };
            try {
                GhidraVtableBindings.extract(program, classes, monitor, ignored -> { });
                throw new AssertionError("inventory ignored cancellation");
            }
            catch (CancelledException expectedCancellation) { checks++; }
            unchanged(program, request, expected, encoded);
        }

        int transaction = program.startTransaction("malformed vtable inventory keys");
        try {
            var options = program.getOptions(GROUP);
            for (String bad : List.of("foreign", "symbol-", "symbol-0", "symbol--1", "symbol-01",
                    "symbol-9223372036854775808", "symbol-1x")) options.setString(bad, "invalid");
            options.setInt("symbol-90000001", 1);
            options.setString("symbol-90000002", "invalid");
            messages.clear();
            require(GhidraVtableBindings.extract(program, classes, MONITOR, messages::add).equals(baseline) &&
                messages.size() == 9, "malformed keys hid or invented a valid table");
            require(options.getOptionNames().size() == 10 && options.getInt("symbol-90000001", 0) == 1,
                "inventory repaired malformed options");
        }
        finally { program.endTransaction(transaction, false); }
        unchanged(program, request, expected, encoded);

        for (String budget : List.of("keys", "encoded", "witness")) {
            transaction = program.startTransaction("vtable inventory budget " + budget);
            try {
                var options = program.getOptions(GROUP);
                String last = "";
                if (budget.equals("keys")) {
                    for (int i = 0; i < 4095; i++) options.setString("unknown-" + i, "x");
                }
                else if (budget.equals("encoded")) {
                    for (int i = 0; i < 16; i++) {
                        last = "symbol-" + (90000000 + i);
                        options.setString(last, "X".repeat(1024 * 1024 - (i == 15 ? encoded.length() : 0)));
                    }
                }
                else {
                    for (int i = 0; i < 64; i++) {
                        last = "symbol-" + (90000000 + i);
                        options.setString(last, claimedExtent(encoded, 90000000 + i,
                            1024 * 1024 - (i == 63 ? request.byteSize() : 0)));
                    }
                }
                messages.clear();
                require(GhidraVtableBindings.extract(program, classes, MONITOR, messages::add).equals(baseline),
                    "exact inventory budget rejected valid table: " + budget);
                require(messages.stream().noneMatch(message -> message.contains("budget exceeded") ||
                    message.contains("inventory exceeds bound")), "exact budget diagnosed as excessive");
                if (budget.equals("keys")) options.setString("unknown-overflow", "x");
                else if (budget.equals("encoded")) options.setString(last, options.getString(last, "") + "X");
                else options.setString(last, claimedExtent(encoded, 90000063, 1024 * 1024 - request.byteSize() + 8));
                messages.clear();
                require(GhidraVtableBindings.extract(program, classes, MONITOR, messages::add).isEmpty(),
                    "excessive inventory produced partial table list: " + budget);
                String reason = budget.equals("keys") ? "inventory exceeds bound" :
                    budget.equals("encoded") ? "encoded record budget exceeded" : "byte witness budget exceeded";
                require(messages.stream().anyMatch(message -> message.contains(reason)), "missing budget diagnostic: " + budget);
                require(encoded.equals(options.getString(key, null)), "budget rejection replaced original record");
            }
            finally { program.endTransaction(transaction, false); }
            unchanged(program, request, expected, encoded);
        }
        mappings(program, request, expected, encoded);
        membership(program, request, expected, encoded);
        System.out.println("vtable-inventory=PASS checks=" + checks + " target=" + target);
        return checks;
    }

    private static void membership(ProgramDB program, Request request, Snapshot expected, String encoded) throws Exception {
        for (String mode : List.of("outside", "derived", "base", "unrelated", "function-symbol")) {
            int transaction = program.startTransaction("explicit vtable membership " + mode);
            try {
                var other = program.getSymbolTable().createClass(program.getGlobalNamespace(), "Other", SourceType.USER_DEFINED);
                var layout = (Structure) program.getDataTypeManager().resolve(new StructureDataType("Other", 32),
                    DataTypeConflictHandler.DEFAULT_HANDLER);
                GhidraClassBindings.save(program, other, layout, "independent explicit class", MONITOR);
                if (mode.equals("outside") || mode.equals("function-symbol")) {
                    long symbol = mode.equals("function-symbol") ?
                        program.getFunctionManager().getFunctions(true).next().getID() : request.symbolId();
                    long owner = mode.equals("outside") ? other.getID() : request.classId();
                    var invalid = new Request(symbol, owner, request.mangledName(), request.lookupName(),
                        request.byteSize(), request.points(), request.evidence());
                    try {
                        GhidraVtableBindings.save(program, invalid, MONITOR);
                        throw new AssertionError("invalid vtable association accepted: " + mode);
                    }
                    catch (IllegalArgumentException rejected) {
                        require(rejected.getMessage().contains(mode.equals("outside") ?
                            "outside saved inheritance snapshot" : "saved memory label"), "wrong association rejection");
                    }
                    unchanged(program, request, expected, encoded);
                }
                else {
                    long derived = mode.equals("derived") ? request.classId() : other.getID();
                    long base = mode.equals("derived") ? other.getID() : request.classId();
                    if (mode.equals("unrelated")) {
                        var unrelated = program.getSymbolTable().createClass(program.getGlobalNamespace(), "Unrelated", SourceType.USER_DEFINED);
                        var unrelatedType = (Structure) program.getDataTypeManager().resolve(new StructureDataType("Unrelated", 32),
                            DataTypeConflictHandler.DEFAULT_HANDLER);
                        GhidraClassBindings.save(program, unrelated, unrelatedType, "unrelated explicit class", MONITOR);
                        base = unrelated.getID();
                    }
                    var edge = new InheritanceModel.Base(derived, base, 0, InheritanceModel.Access.PUBLIC,
                        new InheritanceModel.FixedBase(0, 16), "explicit base membership");
                    var model = new InheritanceModel(expected.abi(), List.of(edge), List.of());
                    GhidraInheritanceBindings.save(program, model, MONITOR);
                    if (mode.equals("unrelated")) {
                        try {
                            GhidraVtableBindings.save(program, request, MONITOR);
                            throw new AssertionError("unrelated base graph admitted table");
                        }
                        catch (IllegalArgumentException rejected) {
                            require(rejected.getMessage().contains("outside saved inheritance snapshot"), "wrong unrelated-graph rejection");
                        }
                        require(encoded.equals(program.getOptions(GROUP).getString("symbol-" + request.symbolId(), null)),
                            "unrelated association replaced saved evidence");
                    }
                    else {
                        GhidraVtableBindings.save(program, request, MONITOR);
                        var result = GhidraVtableBindings.read(program, request.symbolId(), MONITOR, ignored -> { });
                        require(result.status() == Status.VALID && result.snapshot().originalSha256().equals(expected.originalSha256()) &&
                            !result.snapshot().contextSha256().equals(expected.contextSha256()),
                            "base-only membership lost byte witness or ignored context change");
                    }
                }
            }
            finally { program.endTransaction(transaction, false); }
            unchanged(program, request, expected, encoded);
        }
    }

    /** Alter declared identity/extent only; malformed witnesses remain syntactically complete records. */
    private static String claimedExtent(String encoded, long id, int extent) throws Exception {
        byte[] raw = Base64.getDecoder().decode(encoded.substring("GDFVT1:".length()));
        var input = new DataInputStream(new ByteArrayInputStream(raw));
        input.readInt(); input.readLong(); input.readLong(); input.readUTF(); input.readUTF();
        int sizeOffset = raw.length - input.available();
        ByteBuffer.wrap(raw).putLong(4, id).putInt(sizeOffset, extent);
        return "GDFVT1:" + Base64.getEncoder().encodeToString(raw);
    }

    private static void mappings(ProgramDB program, Request request, Snapshot expected, String encoded) throws Exception {
        var memory = program.getMemory();
        var space = program.getAddressFactory().getDefaultAddressSpace();
        for (String mode : List.of("contiguous", "file-gap", "other-file", "original-geometry", "misaligned", "overlay")) {
            int transaction = program.startTransaction("vtable file witness " + mode);
            try {
                byte[] table = ByteBuffer.allocate(48).order(ByteOrder.LITTLE_ENDIAN)
                    .putLong(0).putLong(0).putLong(0x401100).putLong(-16).putLong(0).putLong(0x401108).array();
                byte[] raw = Arrays.copyOf(table, 80);
                int secondOffset = mode.equals("file-gap") ? 32 : 24;
                System.arraycopy(table, 24, raw, secondOffset, 24);
                if (mode.equals("original-geometry")) raw[0] = 8;
                var first = memory.createFileBytes("first-file", 0, raw.length, new ByteArrayInputStream(raw), MONITOR);
                var second = mode.equals("other-file") ?
                    memory.createFileBytes("second-file", 0, raw.length, new ByteArrayInputStream(raw), MONITOR) : first;
                var base = space.getAddress(0x710000);
                var block = memory.createInitializedBlock("table-first", base, first, 0, 24, mode.equals("overlay"));
                var start = block.getStart();
                memory.createInitializedBlock("table-second", start.add(24), second, secondOffset, 24, false);
                if (mode.equals("original-geometry")) memory.setBytes(start, table);
                var label = program.getSymbolTable().createLabel(start.add(mode.equals("misaligned") ? 1 : 0),
                    "file_table", SourceType.USER_DEFINED);
                var selected = new Request(label.getID(), request.classId(), request.mangledName(), request.lookupName(),
                    request.byteSize(), request.points(), request.evidence());
                if (mode.equals("contiguous")) {
                    GhidraVtableBindings.save(program, selected, MONITOR);
                    var snapshot = GhidraVtableBindings.read(program, label.getID(), MONITOR, ignored -> { });
                    require(snapshot.status() == Status.VALID && snapshot.snapshot().fileOffset() == 0 &&
                        snapshot.snapshot().originalSha256().equals(snapshot.snapshot().loadedSha256()),
                        "contiguous split blocks rejected or wrong byte witness");
                }
                else {
                    try {
                        GhidraVtableBindings.save(program, selected, MONITOR);
                        throw new AssertionError("invalid file witness accepted: " + mode);
                    }
                    catch (IllegalArgumentException rejected) {
                        String reason = switch (mode) {
                            case "file-gap", "other-file" -> "file mapping is not contiguous";
                            case "original-geometry" -> "offset-to-top disagrees";
                            case "misaligned" -> "unaligned vtable extent";
                            case "overlay" -> "not in the default address space";
                            default -> throw new AssertionError(mode);
                        };
                        require(rejected.getMessage().contains(reason), "wrong file witness rejection: " + rejected);
                    }
                    require(GhidraVtableBindings.read(program, label.getID(), MONITOR, ignored -> { }).status() == Status.ABSENT,
                        "rejected mapping created saved evidence");
                }
                unchanged(program, request, expected, encoded);
            }
            finally { program.endTransaction(transaction, false); }
            unchanged(program, request, expected, encoded);
        }
    }

    private static void unchanged(ProgramDB program, Request request, Snapshot expected, String encoded) throws Exception {
        require(encoded.equals(program.getOptions(GROUP).getString("symbol-" + request.symbolId(), null)), "saved record changed");
        require(GhidraVtableBindings.read(program, request.symbolId(), MONITOR, ignored -> { }).snapshot().equals(expected),
            "original table witness changed");
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
