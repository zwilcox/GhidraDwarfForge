package ghidradwarfforge;

import java.lang.reflect.Proxy;

import ghidra.app.util.opinion.ElfLoader;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.Program;

/** Verifies the actual pinned loader property API and its use during rebasing. */
public final class GhidraImageBaseSmoke {
    private GhidraImageBaseSmoke() {
    }

    public static void main(String[] arguments) {
        check("0x400000", 0x400000, 0x401234, 0x401234);
        check("0x401000", 0x401000, 0x401020, 0x401020);
        check("0x401000", 0x2401000, 0x2401020, 0x401020);
        check("0x401000", 0x301000, 0x301020, 0x401020);
        check("0x0", 0x100000, 0x101234, 0x1234);
        // All PT_LOAD headers can be beyond Ghidra's bounded base scan while
        // loaded functions retain their original 0x400000-based ELF addresses.
        check("0x0", 0, 0x400630, 0x400630);
        check("0x0", 0x2000000, 0x2400630, 0x400630);
        expectFailure(null, "missing");
        expectFailure("not-a-base", "invalid");
        System.out.println("ghidra-image-base-smoke=PASS");
    }

    private static void check(String recorded, long currentBase, long ghidraAddress,
            long expectedElfAddress) {
        long originalBase = GhidraImageBase.originalImageBase(program(recorded));
        long delta = AddressNormalizer.rebaseDelta(currentBase, originalBase);
        if (AddressNormalizer.toElfAddress(ghidraAddress, delta) != expectedElfAddress) {
            throw new AssertionError("wrong address using recorded base " + recorded);
        }
    }

    private static void expectFailure(String recorded, String message) {
        try {
            GhidraImageBase.originalImageBase(program(recorded));
            throw new AssertionError("invalid/missing loader metadata was accepted");
        }
        catch (IllegalStateException expected) {
            if (!expected.getMessage().contains(message) ||
                    !expected.getMessage().contains("cannot establish address translation")) {
                throw expected;
            }
        }
    }

    private static Program program(String recorded) {
        ToolOptions options = new ToolOptions(Program.PROGRAM_INFO);
        if (recorded != null) {
            options.setString(ElfLoader.ELF_ORIGINAL_IMAGE_BASE_PROPERTY, recorded);
        }
        return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
            new Class<?>[] { Program.class }, (proxy, method, arguments) -> {
                if (method.getName().equals("getOptions") && arguments.length == 1 &&
                        Program.PROGRAM_INFO.equals(arguments[0])) {
                    return options;
                }
                throw new AssertionError("unexpected Program API: " + method.getName());
            });
    }
}
