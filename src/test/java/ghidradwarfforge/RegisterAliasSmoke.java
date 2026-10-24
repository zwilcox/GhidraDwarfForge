package ghidradwarfforge;

import java.io.File;
import java.lang.reflect.Proxy;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.DefaultLanguageService;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;

/** Exercises real pinned Ghidra register hierarchies without importing a program. */
public final class RegisterAliasSmoke {
    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        check("x86:LE:64:default", "x86_64", "XMM0", 4, "XMM0", 17, 0);
        check("x86:LE:64:default", "x86_64", "XMM1", 8, "XMM1", 18, 0);
        check("x86:LE:64:default", "x86_64", "EDI", 4, "RDI", 5, 0);
        check("x86:LE:64:default", "x86_64", "AH", 1, "RAX", 0, 8);
        check("AARCH64:LE:64:v8A", "aarch64", "s0", 4, "q0", 64, 0);
        check("AARCH64:LE:64:v8A", "aarch64", "d1", 8, "q1", 65, 0);
        check("ARM:LE:32:v8", "arm", "s0", 4, "d0", 256, 0);
        check("ARM:LE:32:v8", "arm", "s1", 4, "d0", 256, 32);
        check("ARM:LE:32:v8", "arm", "s3", 4, "d1", 257, 32);
        check("ARM:LE:32:v8", "arm", "d1", 8, "d1", 257, 0);
        unavailable("x86:LE:64:default", "x86_64", "YMM0", 32);
        unavailable("AARCH64:LE:64:v8A", "aarch64", "z0", 32);
        unavailable("ARM:LE:32:v8", "arm", "q0", 16);
        for (String endian : new String[] { "BE", "LE" }) {
            String id = "MIPS:" + endian + ":32:default";
            String target = endian.equals("BE") ? "mips" : "mipsel";
            check(id, target, "f12", 4, "f12", 44, 0);
            var language = language(id);
            if (!(GhidraVariableStorage.mappedRegister(language.getRegister("f12_13"), 8,
                    TargetRegisterMap.forTarget(target), "parameter") instanceof
                    UnavailableStorage)) {
                throw new AssertionError("unproven paired floating register was mapped");
            }
        }
        System.out.println("register-alias-smoke=PASS");
    }

    private static Language language(String id) throws Exception {
        return DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(id));
    }

    private static void unavailable(String id, String target, String name, int bytes)
            throws Exception {
        if (!(GhidraVariableStorage.mappedRegister(language(id).getRegister(name), bytes,
                TargetRegisterMap.forTarget(target), "parameter") instanceof UnavailableStorage)) {
            throw new AssertionError("unproven broad register was mapped: " + id + " " + name);
        }
    }

    private static void check(String id, String target, String name, int bytes,
            String mappedName, int number, int offset) throws Exception {
        var language = language(id);
        var register = language.getRegister(name);
        var storage = GhidraVariableStorage.mappedRegister(register, bytes,
            TargetRegisterMap.forTarget(target), "parameter");
        if (!(storage instanceof RegisterStorage mapped) ||
                !mapped.register().ghidraName().equals(mappedName) ||
                mapped.register().dwarfNumber() != number || mapped.valueBitOffset() != offset ||
                mapped.bitSize() != bytes * 8) {
            throw new AssertionError(id + " " + name + " mapped incorrectly: " + storage);
        }
        var write = new PcodeOp(language.getDefaultSpace().getAddress(0x1000), 0,
            PcodeOp.COPY, new Varnode[0],
            new Varnode(register.getAddress(), register.getMinimumByteSize()));
        var instruction = (Instruction) Proxy.newProxyInstance(Instruction.class.getClassLoader(),
            new Class<?>[] { Instruction.class }, (proxy, method, arguments) ->
                switch (method.getName()) {
                    case "getResultObjects" -> new Object[0];
                    case "getPcode" -> new PcodeOp[] { write };
                    default -> throw new AssertionError("unexpected API " + method);
                });
        if (!GhidraVariableStorage.writesRegister(instruction, register.getBaseRegister())) {
            throw new AssertionError("mapped alias bypassed conservative write detection");
        }
        System.out.printf("register-alias=%s %s -> %s offset=%d PASS%n", id, name,
            mappedName, offset);
    }
}
