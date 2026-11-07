import java.nio.file.Path;
import ghidra.app.script.GhidraScript;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.elf.ElfImage;

/** Save and verify one analyst name using the actual ELF/Ghidra image bases. */
public class PreparePerfBuildId extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 5 || !(args[0].equals("initial") ||
                args[0].equals("edit") || args[0].equals("verify"))) {
            throw new IllegalArgumentException("supply initial|edit|verify link-address original sha256 expected-name");
        }
        Path original = Path.of(args[2]);
        String path = FileSystemService.getInstance().getLocalFSRL(original.toFile()).getPath();
        if (!currentProgram.getExecutablePath().equals(path) ||
                !currentProgram.getExecutableSHA256().equalsIgnoreCase(args[3])) {
            throw new IllegalStateException("import identity differs from owned fixture");
        }
        long link = Long.parseUnsignedLong(args[1], 16);
        long offset = link - ElfImage.read(original).preferredImageBase();
        var function = getFunctionAt(currentProgram.getImageBase().add(offset));
        if (function == null) throw new IllegalStateException("missing hot function");
        if (!args[0].equals("verify")) {
            if (args[0].equals("edit") && !function.getName().equals("forge_profile_initial")) {
                throw new IllegalStateException("saved initial name is missing");
            }
            function.setName(args[4], SourceType.USER_DEFINED);
        }
        if (!function.getName().equals(args[4])) throw new IllegalStateException("saved name differs");
        println("perf-build-id-program=PASS mode=" + args[0] + " name=" + args[4]);
    }
}
