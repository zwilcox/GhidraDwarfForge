package ghidradwarfforge;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.*;

import db.DBHandle;
import ghidra.GhidraApplicationLayout;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;
import ghidradwarfforge.GhidraVtableBindings.*;
import ghidradwarfforge.targets.CxxAbiProfile;
import ghidradwarfforge.types.InheritanceModel;
import ghidradwarfforge.types.InheritanceModel.*;

/** Saved-program controls for evidence lifetimes, separate byte witnesses and immutable reads. */
public final class VtableBindingEvidenceSmoke {
    private static int checks;
    private static final TaskMonitor MONITOR = TaskMonitor.DUMMY;
    private static final String GROUP = GhidraVtableBindings.OPTIONS_NAME;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        check("x86:LE:64:default", CxxAbiProfile.ITANIUM_X86_64);
        check("AARCH64:LE:64:v8A", CxxAbiProfile.ITANIUM_AARCH64);
        System.out.println("vtable-binding-evidence=PASS checks=" + checks);
    }

    private static void check(String languageId, CxxAbiProfile abi) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
        Object token = new Object();
        var program = new ProgramDB("vtables", language, language.getDefaultCompilerSpec(), token);
        var directory = Files.createTempDirectory("forge-vtable-binding-");
        var saved = directory.resolve("program.db");
        long symbolId;
        Request request;
        Snapshot expected;
        try {
            int transaction = program.startTransaction("vtable fixture");
            try {
                require(GhidraVtableBindings.read(program, 1, MONITOR, ignored -> { }).status() == Status.ABSENT, "absent evidence");
                GhidraVtableBindings.remove(program, 1, MONITOR);
                require(!program.getOptionsNames().contains(GROUP), "absent reads created metadata");
                program.setExecutableFormat(ElfLoader.ELF_NAME);
                program.getOptions(Program.PROGRAM_INFO).setString(ElfLoader.ELF_ORIGINAL_IMAGE_BASE_PROPERTY, "400000");
                var space = program.getAddressFactory().getDefaultAddressSpace();
                program.setImageBase(space.getAddress(0x400000), true);
                var memory = program.getMemory();
                var entry = space.getAddress(0x401100);
                memory.createInitializedBlock("text", entry, 16, (byte) 0, MONITOR, false);
                var owner = program.getSymbolTable().createClass(program.getGlobalNamespace(), "Child", SourceType.USER_DEFINED);
                var method = program.getFunctionManager().createFunction("inspect", entry, new AddressSet(entry, entry.add(3)), SourceType.USER_DEFINED);
                method.setParentNamespace(owner); method.setCallingConvention("__thiscall");
                var object = Arrays.stream(method.getParameters()).filter(p -> p.getAutoParameterType() == AutoParameterType.THIS).findFirst().orElseThrow();
                var layout = (Structure) ((Pointer) object.getFormalDataType()).getDataType();
                layout.add(new ArrayDataType(ByteDataType.dataType, 32, 1), "storage", "");
                GhidraClassBindings.save(program, owner, layout, "explicit fixture class", MONITOR);
                var model = new InheritanceModel(abi, List.of(), List.of(new VirtualMethod(method.getID(), 0, Access.PUBLIC,
                    Virtuality.VIRTUAL, "explicit virtual slot")));
                GhidraInheritanceBindings.save(program, model, MONITOR);
                var bytes = ByteBuffer.allocate(128).order(ByteOrder.LITTLE_ENDIAN);
                long[] words = {0, 0, 0x401100, -16, 0, 0x401108};
                for (int i = 0; i < words.length; i++) bytes.putLong(32 + i * 8, words[i]);
                var file = memory.createFileBytes("fixture.elf", 8, 128, new ByteArrayInputStream(bytes.array()), MONITOR);
                var address = space.getAddress(0x402000);
                var block = memory.createInitializedBlock("vtable", address, file, 32, 48, false);
                block.setRead(true);
                var symbol = program.getSymbolTable().createLabel(address, "analyst_table", SourceType.USER_DEFINED);
                symbolId = symbol.getID();
                request = new Request(symbolId, owner.getID(), "_ZTV5Child", "Child", 48,
                    List.of(new AddressPoint(16, 0, "primary"), new AddressPoint(40, 16, "secondary")), "analyst complete-object evidence");
                // Simulate relocated pointers without changing the original FileBytes.
                memory.setBytes(address.add(16), ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(0x501100).array());
                memory.setBytes(address.add(40), ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(0x501108).array());
                cancelled(() -> GhidraVtableBindings.save(program, request, cancelAt(1)));
                require(!program.getOptionsNames().contains(GROUP), "cancelled initial save wrote metadata");
                GhidraVtableBindings.save(program, request, MONITOR);
                expected = valid(program, symbolId);
                require(expected.fileOffset() == 40 && expected.originalAddress() == 0x402000, "wrong FileBytes-relative mapping or ELF address");
                require(!expected.originalSha256().equals(expected.loadedSha256()), "lost separate original/relocated byte witnesses");
                String key = "symbol-" + symbolId;
                var options = program.getOptions(GROUP);
                String encoded = options.getString(key, null);
                // No base edge and no local virtual method can establish this class's
                // table membership: use only the explicitly bound addressless method.
                var library = program.getExternalManager().addExternalLibraryName("Declarations", SourceType.USER_DEFINED);
                var externalOwner = program.getSymbolTable().createClass(library, "Child", SourceType.USER_DEFINED);
                var declaration = program.getExternalManager().addExtFunction(externalOwner, "declared", null, SourceType.USER_DEFINED).getFunction();
                declaration.setCallingConvention("__thiscall");
                declaration.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
                var association = new GhidraDeclarationBindings.Binding(declaration.getID(), owner.getID(), "explicit canonical virtual owner");
                GhidraDeclarationBindings.save(program, association, MONITOR);
                var externalModel = new InheritanceModel(abi, List.of(), List.of(new VirtualMethod(declaration.getID(), 0,
                    Access.PUBLIC, Virtuality.VIRTUAL, "addressless-only virtual membership")));
                GhidraInheritanceBindings.save(program, externalModel, MONITOR);
                rejected(program, symbolId);
                GhidraVtableBindings.save(program, request, MONITOR);
                require(valid(program, symbolId).request().classId() == owner.getID(), "explicit declaration owner admits table without base/local virtual edge");
                var selected = List.of(new ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol("inspect", 0x401100, 4));
                String target = abi == CxxAbiProfile.ITANIUM_X86_64 ? "x86_64" : "aarch64";
                var extractionMessages = new ArrayList<String>();
                var extracted = GhidraTypeGraph.extract(program, selected, target, 0, MONITOR, extractionMessages::add);
                require(extracted.classScopes().vtables().size() == 1 &&
                    extracted.classScopes().vtables().getFirst().classId() == owner.getID(), "ordinary extraction retains explicit addressless table ownership: " + extractionMessages);
                GhidraDeclarationBindings.remove(program, declaration.getID(), MONITOR);
                rejected(program, symbolId);
                rejects(() -> GhidraVtableBindings.save(program, request, MONITOR));
                require(GhidraTypeGraph.extract(program, selected, target, 0, MONITOR, ignored -> { }).classScopes().vtables().isEmpty(),
                    "missing explicit owner cannot infer a replacement table association");
                GhidraDeclarationBindings.save(program, association, MONITOR);
                require(valid(program, symbolId).request().classId() == owner.getID(), "exact association restoration recovers table witness");
                GhidraInheritanceBindings.save(program, model, MONITOR);
                GhidraDeclarationBindings.remove(program, declaration.getID(), MONITOR);
                GhidraVtableBindings.save(program, request, MONITOR);
                require(encoded.equals(options.getString(key, null)), "original local-virtual witness restored exactly");
                GhidraVtableBindings.save(program, request, MONITOR);
                require(encoded.equals(options.getString(key, null)), "nondeterministic saved record");
                int[] visits = {0};
                var counter = new TaskMonitorAdapter(true) { @Override public void checkCancelled() { visits[0]++; } };
                GhidraVtableBindings.save(program, request, counter);
                for (int stop : List.of(1, visits[0] / 2, visits[0])) {
                    cancelled(() -> GhidraVtableBindings.save(program, request, cancelAt(stop)));
                    require(encoded.equals(options.getString(key, null)), "cancelled save changed record");
                }
                visits[0] = 0;
                GhidraVtableBindings.read(program, symbolId, counter, ignored -> { });
                for (int stop : List.of(1, visits[0] / 2, visits[0])) {
                    cancelled(() -> GhidraVtableBindings.read(program, symbolId, cancelAt(stop), ignored -> { }));
                    require(encoded.equals(options.getString(key, null)), "cancelled read changed record");
                }
                byte originalLoaded = memory.getByte(address.add(17));
                memory.setByte(address.add(17), (byte) (originalLoaded ^ 1)); rejected(program, symbolId);
                memory.setByte(address.add(17), originalLoaded);
                require(valid(program, symbolId).equals(expected), "restored loaded bytes not accepted");
                memory.setByte(address.add(24), (byte) 0); rejected(program, symbolId);
                rejects(() -> GhidraVtableBindings.save(program, request, MONITOR));
                memory.setByte(address.add(24), (byte) -16);
                layout.growStructure(1); rejected(program, symbolId); layout.deleteAtOffset(32);
                require(valid(program, symbolId).equals(expected), "restored class layout not accepted");
                var points = List.of(new AddressPoint(16, 0, "primary"), new AddressPoint(40, 8, "wrong geometry"));
                rejects(() -> GhidraVtableBindings.save(program, new Request(symbolId, owner.getID(), "_ZTV5Child", "Child", 48, points, "bad offset"), MONITOR));
                rejects(() -> GhidraVtableBindings.save(program, new Request(symbolId, owner.getID(), "_ZTV5Child", "Other", 48, request.points(), "bad name"), MONITOR));
                rejects(() -> new Request(symbolId, owner.getID(), "_ZTC5Child", "Child", 48, request.points(), "construction table"));
                rejects(() -> new Request(symbolId, owner.getID(), "_ZTV5Child", "Child", 48,
                    Collections.nCopies(4096, new AddressPoint(16, 0, "x".repeat(8192))), "oversized"));
                require(encoded.equals(options.getString(key, null)), "rejected saves changed record");
                memory.moveBlock(block, address.add(0x1000), MONITOR);
                rejected(program, symbolId);
                memory.moveBlock(block, address, MONITOR);
                require(valid(program, symbolId).equals(expected), "restored file mapping not accepted");
                program.getOptions(Program.PROGRAM_INFO).setString(ElfLoader.ELF_ORIGINAL_IMAGE_BASE_PROPERTY, "500000");
                rejected(program, symbolId);
                program.getOptions(Program.PROGRAM_INFO).setString(ElfLoader.ELF_ORIGINAL_IMAGE_BASE_PROPERTY, "invalid");
                rejected(program, symbolId);
                program.getOptions(Program.PROGRAM_INFO).setString(ElfLoader.ELF_ORIGINAL_IMAGE_BASE_PROPERTY, "400000");
                require(valid(program, symbolId).equals(expected), "restored image metadata not accepted");
                var anonymousAddress = space.getAddress(0x405000);
                memory.createInitializedBlock("no-file-backing", anonymousAddress, 48, (byte) 0, MONITOR, false);
                var anonymous = program.getSymbolTable().createLabel(anonymousAddress, "unbacked_table", SourceType.USER_DEFINED);
                rejects(() -> GhidraVtableBindings.save(program, new Request(anonymous.getID(), owner.getID(),
                    "_ZTV5Child", "Child", 48, request.points(), "missing original file"), MONITOR));
                require(GhidraVtableBindings.read(program, anonymous.getID(), MONITOR, ignored -> { }).status() == Status.ABSENT,
                    "rejected unbacked table created evidence");
                symbol.setName("renamed_table", SourceType.USER_DEFINED);
                method.setName("renamed_method", SourceType.USER_DEFINED);
                program.setImageBase(space.getAddress(0x600000), true);
                require(valid(program, symbolId).equals(expected), "rename/rebase changed byte witness");
                GhidraVtableBindings.save(program, request, MONITOR);
                require(encoded.equals(options.getString(key, null)), "rename/rebase changed encoding");
                byte[] raw = Base64.getDecoder().decode(encoded.substring("GDFVT1:".length()));
                for (String bad : List.of("", "GDFVT1:!", "GDFVT2:AA==", encoded + "AAAA",
                        "GDFVT1:" + "A".repeat(1400000),
                        "GDFVT1:" + Base64.getEncoder().encodeToString(Arrays.copyOf(raw, raw.length - 1)))) {
                    options.setString(key, bad); rejected(program, symbolId);
                    require(bad.equals(options.getString(key, null)), "rejected record repaired");
                }
                options.setString(key, encoded);
                options.setString("symbol-" + method.getID(), encoded); rejected(program, method.getID());
                options.removeOption("symbol-" + method.getID());
                options.removeOption(key); options.setInt(key, 7); rejected(program, symbolId);
                rejects(() -> GhidraVtableBindings.save(program, request, MONITOR));
                require(options.getInt(key, 0) == 7, "wrong option type overwritten");
                options.removeOption(key); options.setString(key, encoded);
                GhidraInheritanceBindings.remove(program, MONITOR); rejected(program, symbolId);
                GhidraInheritanceBindings.save(program, model, MONITOR);
                require(valid(program, symbolId).equals(expected), "restored inheritance not accepted");
                GhidraVtableBindings.remove(program, symbolId, MONITOR);
                require(GhidraVtableBindings.read(program, symbolId, MONITOR, ignored -> { }).status() == Status.ABSENT, "removal failed");
                GhidraVtableBindings.save(program, request, MONITOR);
            }
            finally { program.endTransaction(transaction, true); }
            rejects(() -> GhidraVtableBindings.save(program, request, MONITOR));
            requestBoundaries(program, request, expected);
            relocationBoundaries(program, request, expected);
            checks += VtableInventorySmoke.check(program, request, expected);
            program.getDBHandle().saveAs(saved.toFile(), true, MONITOR);
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(saved));
            var timestamp = Files.getLastModifiedTime(saved);
            var handle = new DBHandle(saved.toFile());
            Object reader = new Object(); ProgramDB reopened = null;
            try {
                reopened = new ProgramDB(handle, OpenMode.IMMUTABLE, MONITOR, reader);
                require(valid(reopened, symbolId).equals(expected), "immutable reopen changed witness");
                require(valid(reopened, symbolId).equals(expected), "repeated immutable read changed witness");
            }
            finally { if (reopened != null) reopened.release(reader); else handle.close(); }
            require(Arrays.equals(hash, MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(saved))) &&
                timestamp.equals(Files.getLastModifiedTime(saved)), "immutable read changed database");
            int deletion = program.startTransaction("delete table control");
            try { program.getSymbolTable().getSymbol(symbolId).delete(); rejected(program, symbolId); }
            finally { program.endTransaction(deletion, true); }
            System.out.println("vtable-binding-target=PASS " + languageId);
        }
        finally { program.release(token); Files.deleteIfExists(saved); Files.deleteIfExists(directory); }
    }

    private static void requestBoundaries(ProgramDB program, Request request, Snapshot expected) throws Exception {
        int transaction = program.startTransaction("rejected vtable requests");
        String key = "symbol-" + request.symbolId();
        String encoded = program.getOptions(GROUP).getString(key, null);
        try {
            for (long symbol : new long[] {0, -1}) {
                rejects(() -> new Request(symbol, request.classId(), request.mangledName(), request.lookupName(),
                    request.byteSize(), request.points(), request.evidence()));
            }
            for (long owner : new long[] {0, -1}) {
                rejects(() -> new Request(request.symbolId(), owner, request.mangledName(), request.lookupName(),
                    request.byteSize(), request.points(), request.evidence()));
            }
            for (int size : new int[] {0, -1, 1024 * 1024 + 1}) {
                rejects(() -> withPoints(request, size, request.points()));
            }
            rejects(() -> withPoints(request, 48, null));
            rejects(() -> withPoints(request, 48, List.of()));
            rejects(() -> withPoints(request, 48, Arrays.asList((AddressPoint) null)));
            rejects(() -> withPoints(request, 48, Collections.nCopies(4097, request.points().getFirst())));
            for (String text : Arrays.asList(null, "", " ", "bad\0text", "x".repeat(8193))) {
                rejects(() -> new AddressPoint(16, 0, text));
            }
            rejects(() -> new AddressPoint(-1, 0, "negative table"));
            rejects(() -> new AddressPoint(16, -1, "negative subobject"));
            for (String name : List.of("_ZTV", "_ZTV5 Child", "_ZTC5Child")) {
                rejects(() -> new Request(request.symbolId(), request.classId(), name, request.lookupName(),
                    request.byteSize(), request.points(), request.evidence()));
            }
            // Each geometry is syntactically valid metadata but cannot describe
            // this saved complete object. Rejection must preserve its valid record.
            for (var points : List.of(
                    List.of(new AddressPoint(8, 0, "before header")),
                    List.of(new AddressPoint(48, 0, "past extent")),
                    List.of(new AddressPoint(17, 0, "misaligned table")),
                    List.of(new AddressPoint(16, 0, "primary"), new AddressPoint(32, 16, "overlap")),
                    List.of(new AddressPoint(16, 1, "misaligned object")),
                    List.of(new AddressPoint(16, 32, "outside object")),
                    List.of(new AddressPoint(16, 0, "primary"), new AddressPoint(40, 0, "duplicate object")),
                    List.of(new AddressPoint(16, 16, "no primary")))) {
                rejects(() -> GhidraVtableBindings.save(program, withPoints(request, 48, points), MONITOR));
                require(encoded.equals(program.getOptions(GROUP).getString(key, null)), "invalid geometry replaced saved evidence");
            }
            rejects(() -> GhidraVtableBindings.save(program, withPoints(request, 47, request.points()), MONITOR));
            rejects(() -> GhidraVtableBindings.save(program, null, MONITOR));
            require(valid(program, request.symbolId()).equals(expected), "request rejection changed byte witness");
            byte[] raw = Base64.getDecoder().decode(encoded.substring("GDFVT1:".length()));
            var input = new DataInputStream(new ByteArrayInputStream(raw));
            input.readInt(); input.readLong(); input.readLong(); input.readUTF(); input.readUTF();
            input.readInt(); input.readUTF();
            int countOffset = raw.length - input.available();
            var invalidRecords = new ArrayList<byte[]>();
            byte[] version = raw.clone(); ByteBuffer.wrap(version).putInt(2); invalidRecords.add(version);
            for (int count : new int[] {-1, 0, 4097}) {
                byte[] changed = raw.clone(); ByteBuffer.wrap(changed).putInt(countOffset, count); invalidRecords.add(changed);
            }
            invalidRecords.add(Arrays.copyOf(raw, raw.length + 1));
            // This decoded size shares the maximum permitted Base64 length with
            // the byte limit, so the decoded bound must be checked independently.
            invalidRecords.add(Arrays.copyOf(raw, 1024 * 1024 + 1));
            for (byte[] changed : invalidRecords) {
                String bad = "GDFVT1:" + Base64.getEncoder().encodeToString(changed);
                program.getOptions(GROUP).setString(key, bad);
                rejected(program, request.symbolId());
                require(bad.equals(program.getOptions(GROUP).getString(key, null)), "malformed record repaired itself");
            }
            program.getOptions(GROUP).setString(key, encoded);
            require(valid(program, request.symbolId()).equals(expected), "exact record restoration changed witness");
        }
        finally { program.endTransaction(transaction, false); }
        require(valid(program, request.symbolId()).equals(expected), "request controls changed persistent state");
    }

    private static Request withPoints(Request request, int size, List<AddressPoint> points) {
        return new Request(request.symbolId(), request.classId(), request.mangledName(), request.lookupName(),
            size, points, request.evidence());
    }

    private static void relocationBoundaries(ProgramDB program, Request request, Snapshot original) throws Exception {
        var address = program.getSymbolTable().getSymbol(request.symbolId()).getAddress();
        var table = program.getRelocationTable();
        var contexts = new HashSet<String>();
        String key = "symbol-" + request.symbolId();
        String encoded = program.getOptions(GROUP).getString(key, null);
        // Independent one-field changes must alter only the context witness,
        // not the original or loaded table byte witnesses.
        for (int variant = 0; variant < 10; variant++) {
            int transaction = program.startTransaction("vtable relocation fingerprint " + variant);
            try {
                long[] values = variant == 4 ? null : variant == 5 ? new long[0] :
                    variant == 6 ? new long[] {12, 14} : new long[] {12, 13};
                byte[] bytes = variant == 7 ? null : variant == 8 ? new byte[] {4, 6} : new byte[] {4, 5};
                var status = variant == 3 ? ghidra.program.model.reloc.Relocation.Status.APPLIED_OTHER :
                    ghidra.program.model.reloc.Relocation.Status.APPLIED;
                table.add(address.add(variant == 1 ? 17 : 16), status, variant == 2 ? 258 : 257,
                    values, bytes, variant == 9 ? "other-symbol" : "symbol");
                require(table.getSize() == 1, "fixture did not create one real relocation record");
                rejected(program, request.symbolId());
                require(encoded.equals(program.getOptions(GROUP).getString(key, null)), "stale relocation evidence refreshed itself");
                GhidraVtableBindings.save(program, request, MONITOR);
                var updated = valid(program, request.symbolId());
                require(updated.originalSha256().equals(original.originalSha256()) &&
                    updated.loadedSha256().equals(original.loadedSha256()), "metadata changed table bytes");
                require(!updated.contextSha256().equals(original.contextSha256()) && contexts.add(updated.contextSha256()),
                    "relocation field was omitted from fingerprint: " + variant);
            }
            finally { program.endTransaction(transaction, false); }
            require(table.getSize() == 0 && valid(program, request.symbolId()).equals(original), "relocation rollback changed original state");
        }
        for (String kind : List.of("outside", "values-limit", "too-many-values", "bytes-limit", "too-many-bytes", "aggregate")) {
            int transaction = program.startTransaction("vtable relocation limit " + kind);
            try {
                int count = kind.equals("aggregate") ? 129 : 1;
                for (int i = 0; i < count; i++) {
                    table.add(address.add(kind.equals("outside") ? 48 : i % 48),
                        ghidra.program.model.reloc.Relocation.Status.APPLIED, 257,
                        new long[kind.equals("too-many-values") ? 4097 : kind.equals("values-limit") ||
                            kind.equals("aggregate") ? 4096 : 0],
                        new byte[kind.equals("too-many-bytes") ? 1024 * 1024 + 1 :
                            kind.equals("bytes-limit") ? 1024 * 1024 : 0], null);
                }
                if (kind.equals("outside")) {
                    require(valid(program, request.symbolId()).equals(original), "outside relocation invalidated table witness");
                }
                else if (kind.equals("values-limit") || kind.equals("bytes-limit")) {
                    GhidraVtableBindings.save(program, request, MONITOR);
                    require(valid(program, request.symbolId()).originalSha256().equals(original.originalSha256()),
                        "supported boundary changed original bytes");
                }
                else {
                    rejects(() -> GhidraVtableBindings.save(program, request, MONITOR));
                    rejected(program, request.symbolId());
                    require(encoded.equals(program.getOptions(GROUP).getString(key, null)), "oversized relocation replaced evidence");
                }
            }
            finally { program.endTransaction(transaction, false); }
            require(table.getSize() == 0 && valid(program, request.symbolId()).equals(original), "limit control changed original state");
        }
    }

    private static Snapshot valid(Program program, long id) throws Exception {
        var messages = new ArrayList<String>();
        var result = GhidraVtableBindings.read(program, id, MONITOR, messages::add);
        require(result.status() == Status.VALID && messages.isEmpty(), "valid evidence rejected: " + messages);
        return result.snapshot();
    }
    private static void rejected(Program program, long id) throws Exception {
        var messages = new ArrayList<String>();
        var result = GhidraVtableBindings.read(program, id, MONITOR, messages::add);
        require(result.status() == Status.REJECTED && result.snapshot() == null && messages.size() == 1, "invalid evidence accepted: " + messages);
    }
    private static TaskMonitor cancelAt(int count) {
        return new TaskMonitorAdapter(true) {
            private int visits;
            @Override public void checkCancelled() throws CancelledException { if (++visits == count) throw new CancelledException(); }
        };
    }
    private interface Operation { void run() throws Exception; }
    private static void cancelled(Operation action) throws Exception {
        try { action.run(); throw new AssertionError("cancellation ignored"); }
        catch (CancelledException expected) { checks++; }
    }
    private static void rejects(Operation action) throws Exception {
        try { action.run(); throw new AssertionError("invalid save accepted"); }
        catch (IllegalArgumentException expected) { checks++; }
    }
    private static void require(boolean value, String message) { checks++; if (!value) throw new AssertionError(message); }
}
