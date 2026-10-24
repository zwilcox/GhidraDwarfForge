package ghidradwarfforge;

import java.lang.reflect.Proxy;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidradwarfforge.elf.ElfImage;

/** Checks metadata agreement through the pinned Program/Language APIs, without native code. */
public final class GhidraTargetAgreementSmoke {
    private record Profile(int machine, int bytes, boolean little, String processor,
            String language, String compiler) {
    }

    private GhidraTargetAgreementSmoke() {
    }

    public static void main(String[] arguments) throws Exception {
        Path input = Files.createTempFile("forge-target-agreement-", ".elf");
        try {
            for (Profile profile : List.of(
                    new Profile(62, 8, true, "x86", "x86:LE:64:default", "gcc"),
                    new Profile(183, 8, true, "AARCH64", "AARCH64:LE:64:v8A", "default"),
                    new Profile(40, 4, true, "ARM", "ARM:LE:32:v8", "default"),
                    new Profile(8, 4, true, "MIPS", "MIPS:LE:32:default", "default"),
                    new Profile(8, 4, false, "MIPS", "MIPS:BE:32:default", "default"))) {
                byte[] original = image(profile.machine(), profile.bytes(), profile.little());
                Files.write(input, original);
                ElfImage elf = ElfImage.read(input);
                var target = GhidraTargetAgreement.requireAgreement(program(profile), elf);
                if (!profile.processor().equals(target.ghidraProcessor())) {
                    throw new AssertionError("wrong processor in target table: " + target);
                }
                expectMismatch(elf, new Profile(profile.machine(), profile.bytes(),
                    profile.little(), profile.bytes() == 8 ?
                        (profile.processor().equals("x86") ? "AARCH64" : "x86") :
                        (profile.processor().equals("ARM") ? "MIPS" : "ARM"),
                    "forced:other:language", "analyst-compiler"), profile.processor());
                expectMismatch(elf, new Profile(profile.machine(), profile.bytes() == 8 ? 4 : 8,
                    profile.little(), profile.processor(), profile.language(), profile.compiler()),
                    profile.processor());
                expectMismatch(elf, new Profile(profile.machine(), profile.bytes(),
                    !profile.little(), profile.processor(), profile.language(), profile.compiler()),
                    profile.processor());
                // Variant/compiler choices alone do not establish an ELF contradiction.
                // In particular, an ISA/register width is not a data-pointer width.
                GhidraTargetAgreement.requireAgreement(program(new Profile(profile.machine(),
                    profile.bytes(), profile.little(), profile.processor(),
                    "analyst:custom:64-registers:32-addresses", "nondefault-compiler")), elf);
                if (!Arrays.equals(original, Files.readAllBytes(input))) {
                    throw new AssertionError("agreement check changed the original ELF");
                }
            }
            Files.write(input, image(0xffff, 8, true));
            try {
                GhidraTargetAgreement.requireAgreement(program(new Profile(0xffff, 8, true,
                    "unknown", "unknown:LE:64:default", "default")), ElfImage.read(input));
                throw new AssertionError("unsupported ELF machine was accepted");
            }
            catch (IllegalArgumentException expected) {
                if (!expected.getMessage().contains("unsupported ELF machine")) {
                    throw expected;
                }
            }
        }
        finally {
            Files.delete(input);
        }
        System.out.println("ghidra-target-agreement-smoke=PASS");
    }

    private static void expectMismatch(ElfImage elf, Profile actual, String expectedProcessor) {
        try {
            GhidraTargetAgreement.requireAgreement(program(actual), elf);
            throw new AssertionError("contradictory Program metadata was accepted: " + actual);
        }
        catch (IllegalStateException expected) {
            for (String text : List.of("ELF/Ghidra target mismatch", "machine=" + elf.machine(),
                    "class=ELF" + (elf.is64Bit() ? 64 : 32), "flags=0x1234",
                    "expected-processor=" + expectedProcessor,
                    "Ghidra processor=" + actual.processor(),
                    "pointer-bits=" + (actual.bytes() * 8), "language=" + actual.language(),
                    "compiler=" + actual.compiler(), "before extraction and native production")) {
                if (!expected.getMessage().contains(text)) {
                    throw new AssertionError("missing diagnostic identity " + text, expected);
                }
            }
        }
    }

    private static Program program(Profile profile) {
        Language language = (Language) Proxy.newProxyInstance(Language.class.getClassLoader(),
            new Class<?>[] { Language.class }, (proxy, method, arguments) -> switch (method.getName()) {
                case "getProcessor" -> Processor.findOrPossiblyCreateProcessor(profile.processor());
                case "getLanguageID" -> new LanguageID(profile.language());
                case "isBigEndian" -> !profile.little();
                default -> throw new AssertionError("unexpected Language API: " + method.getName());
            });
        CompilerSpec compiler = (CompilerSpec) Proxy.newProxyInstance(
            CompilerSpec.class.getClassLoader(), new Class<?>[] { CompilerSpec.class },
            (proxy, method, arguments) -> {
                if (method.getName().equals("getCompilerSpecID")) {
                    return new CompilerSpecID(profile.compiler());
                }
                throw new AssertionError("unexpected CompilerSpec API: " + method.getName());
            });
        return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
            new Class<?>[] { Program.class }, (proxy, method, arguments) -> switch (method.getName()) {
                case "getLanguage" -> language;
                case "getDefaultPointerSize" -> profile.bytes();
                case "getCompilerSpec" -> compiler;
                default -> throw new AssertionError("unexpected Program API: " + method.getName());
            });
    }

    private static byte[] image(int machine, int addressBytes, boolean little) {
        boolean elf64 = addressBytes == 8;
        int headerSize = elf64 ? 64 : 52;
        ByteBuffer result = ByteBuffer.allocate(headerSize).order(
            little ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
        result.put(new byte[] { 0x7f, 'E', 'L', 'F', (byte) (elf64 ? 2 : 1),
            (byte) (little ? 1 : 2), 1 });
        result.putShort(16, (short) 2).putShort(18, (short) machine).putInt(20, 1);
        result.putInt(elf64 ? 48 : 36, 0x1234);
        result.putShort(elf64 ? 52 : 40, (short) headerSize);
        return result.array();
    }
}
