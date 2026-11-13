package ghidradwarfforge.nativeapi;

import com.google.gson.JsonParser;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.output.FileDigests;
import ghidradwarfforge.targets.CxxAbiProfile;
import ghidradwarfforge.types.*;
import ghidradwarfforge.types.ClassScopeModel.*;
import ghidradwarfforge.types.InheritanceModel.*;
import ghidradwarfforge.types.TypeGraph.*;

/** Isolated native producer, driven by independently decoded compiler fixture evidence. */
public final class InheritanceProducerProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 5) throw new IllegalArgumentException("consumer producer input model output");
        Path input = Path.of(args[2]), output = Path.of(args[4]);
        var evidence = JsonParser.parseString(Files.readString(Path.of(args[3]))).getAsJsonObject();
        var elf = ElfImage.read(input);
        var abi = CxxAbiProfile.valueOf(evidence.get("abi").getAsString());
        abi.requireTarget(elf.machine(), elf.is64Bit() ? 8 : 4, elf.byteOrder());
        var nodes = new ArrayList<TypeNode>();
        var integer = new TypeRef("int");
        nodes.add(new BaseType("int", "int", 4, BaseEncoding.SIGNED));
        nodes.add(new VoidType("void"));
        nodes.add(new SubroutineType("vfunction", "fixture virtual function", 0, integer, List.of(), false));
        nodes.add(new IndirectionType("vfptr", "fixture function pointer", 8, IndirectionKind.POINTER, new TypeRef("vfunction")));
        nodes.add(new IndirectionType("vptr", "fixture vtable pointer", 8, IndirectionKind.POINTER, new TypeRef("vfptr")));
        var scopes = new ArrayList<Scope>();
        var bindings = new ArrayList<Binding>();
        var classIds = new HashMap<String, Long>();
        for (var value : evidence.getAsJsonArray("classes")) {
            var row = value.getAsJsonObject();
            String name = row.get("name").getAsString();
            long id = row.get("id").getAsLong();
            classIds.put(name, id);
            var members = new ArrayList<Member>();
            for (var item : row.getAsJsonArray("members")) {
                var member = item.getAsJsonObject();
                members.add(new Member(member.get("name").getAsString(),
                    new TypeRef(member.get("vptr").getAsBoolean() ? "vptr" : "int"), member.get("offset").getAsLong()));
            }
            nodes.add(new AggregateType(name, name, row.get("size").getAsLong(), AggregateKind.STRUCTURE, members));
            nodes.add(new IndirectionType(name + "*", name + " *", 8, IndirectionKind.POINTER, new TypeRef(name)));
            scopes.add(new Scope(id, 0, name, Kind.CLASS));
            bindings.add(new Binding(id, new TypeRef(name), BindingSource.EXPLICIT_SAVED, "compiler reference fixture identity"));
        }
        var bases = new ArrayList<Base>();
        for (var item : evidence.getAsJsonArray("bases")) {
            var row = item.getAsJsonObject();
            BaseLocation location = row.get("virtual").getAsBoolean()
                ? new VirtualBase(0, row.get("slotOffset").getAsLong())
                : new FixedBase(row.get("offset").getAsLong(), row.get("occupiedBytes").getAsLong());
            bases.add(new Base(classIds.get(row.get("derived").getAsString()), classIds.get(row.get("base").getAsString()),
                row.get("order").getAsInt(), Access.PUBLIC, location, "compiler reference direct base"));
        }
        var methods = new ArrayList<Method>();
        var virtuals = new ArrayList<VirtualMethod>();
        var signatures = new ArrayList<ProgramTypeModel.FunctionSignature>();
        var functions = new ArrayList<FunctionSymbol>();
        var declarations = new ArrayList<ProgramTypeModel.FunctionDeclaration>();
        for (var item : evidence.getAsJsonArray("methods")) {
            var row = item.getAsJsonObject();
            String owner = row.get("owner").getAsString(), leaf = row.get("name").getAsString();
            String name = owner + "::" + leaf;
            long id = row.get("id").getAsLong();
            long address = row.has("address") ? row.get("address").getAsLong() : -1;
            var reference = address >= 0 ? FunctionReference.definition(name, address) :
                FunctionReference.declaration(name, "compiler-method:" + id);
            methods.add(new Method(id, classIds.get(owner), leaf, reference));
            virtuals.add(new VirtualMethod(id, row.get("slot").getAsInt(), Access.PUBLIC, Virtuality.VIRTUAL,
                "compiler reference vtable slot"));
            var parameters = List.of(new Parameter("this", new TypeRef(owner + "*"), true, false, true));
            if (address >= 0) {
                functions.add(new FunctionSymbol(name, address, row.get("size").getAsLong()));
                signatures.add(new ProgramTypeModel.FunctionSignature(name, address, integer,
                    parameters, List.of(), false, false, "default", "USER_DEFINED"));
            }
            else declarations.add(new ProgramTypeModel.FunctionDeclaration(reference.declarationKey(), name, integer,
                parameters, false, false, "default", "USER_DEFINED"));
        }
        var checkpoint = evidence.getAsJsonObject("checkpoint");
        long entry = checkpoint.get("address").getAsLong();
        functions.add(new FunctionSymbol("inheritance_checkpoint", entry, checkpoint.get("size").getAsLong()));
        signatures.add(new ProgramTypeModel.FunctionSignature("inheritance_checkpoint", entry, new TypeRef("void"),
            List.of(), List.of(), false, false, "default", "USER_DEFINED"));
        var globals = new ArrayList<ProgramTypeModel.GlobalVariable>();
        for (var item : evidence.getAsJsonArray("globals")) {
            var row = item.getAsJsonObject();
            globals.add(new ProgramTypeModel.GlobalVariable(row.get("name").getAsString(), row.get("address").getAsLong(),
                8, new TypeRef(row.get("type").getAsString() + "*"), false, "USER_DEFINED"));
        }
        var classes = new ClassScopeModel(scopes, bindings, methods, new InheritanceModel(abi, bases, virtuals));
        var model = new ProgramTypeModel(new TypeGraph(nodes), signatures, globals, new VariableStorageModel(List.of()),
            List.of(), declarations, List.of(), classes);
        String original = FileDigests.read(input).sha256();
        var exporter = new MinimalDwarfSidecarExporter();
        if (Files.exists(output)) throw new IllegalArgumentException("output must be new");
        byte[] first = null;
        for (int iteration = 0; iteration < 2; iteration++) {
            exporter.export(input, output, Path.of(args[0]), Path.of(args[1]), functions, null, model);
            byte[] current = Files.readAllBytes(output);
            if ((first != null && !java.util.Arrays.equals(first, current)) ||
                    !original.equals(FileDigests.read(input).sha256())) {
                throw new AssertionError("native inheritance emission changed input or repeated output");
            }
            first = current;
        }
        var visits = new java.util.concurrent.atomic.AtomicInteger();
        exporter.export(input, output, Path.of(args[0]), Path.of(args[1]), functions, null, model,
            output.getFileName() + ".c", () -> { visits.incrementAndGet(); return false; });
        for (boolean existing : List.of(false, true)) {
            Path destination = existing ? output : output.resolveSibling("cancelled.dbg");
            if (!existing && Files.exists(destination)) throw new IllegalArgumentException("cancel destination must be new");
            for (int stop : List.of(1, visits.get() / 2, visits.get() - 5)) {
                var counter = new java.util.concurrent.atomic.AtomicInteger();
                try {
                    exporter.export(input, destination, Path.of(args[0]), Path.of(args[1]), functions, null, model,
                        output.getFileName() + ".c", () -> counter.incrementAndGet() >= stop);
                    throw new AssertionError("native export ignored cancellation");
                }
                catch (java.util.concurrent.CancellationException expected) {
                    if (existing ? !java.util.Arrays.equals(first, Files.readAllBytes(output)) : Files.exists(destination)) {
                        throw new AssertionError("cancelled native export published output");
                    }
                }
            }
        }
        var wrongClasses = new ClassScopeModel(scopes, bindings, methods, new InheritanceModel(
            abi == CxxAbiProfile.ITANIUM_X86_64 ? CxxAbiProfile.ITANIUM_AARCH64 : CxxAbiProfile.ITANIUM_X86_64,
            bases, virtuals));
        var wrongModel = new ProgramTypeModel(model.types(), signatures, globals, model.variableStorage(),
            List.of(), declarations, List.of(), wrongClasses);
        try {
            exporter.export(input, output, Path.of(args[0]), Path.of(args[1]), functions, null, wrongModel);
            throw new AssertionError("wrong C++ target profile accepted");
        }
        catch (IllegalArgumentException expected) {
            if (!expected.getMessage().contains("C++ ABI profile") || !java.util.Arrays.equals(first, Files.readAllBytes(output))) {
                throw new AssertionError("wrong target failure changed output", expected);
            }
        }
        if (!original.equals(FileDigests.read(input).sha256())) throw new AssertionError("failure control changed original");
        System.out.println("inheritance-producer=PASS bases=" + bases.size() + " virtualMethods=" + virtuals.size());
    }
}
