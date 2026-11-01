// Exercise the installed exporter twice before closing the analyzed program.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public class RepeatLiveAbiExport extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (getScriptArgs().length != 1) throw new IllegalArgumentException("output");
        Path output = Path.of(getScriptArgs()[0]);
        Path source = Path.of(output + ".c");
        String[] arguments = {"--packaged-natives", "--output=" + output};
        runScript("GhidraDwarfForge.java", arguments);
        byte[] first = Files.readAllBytes(output);
        byte[] firstSource = Files.readAllBytes(source);
        runScript("GhidraDwarfForge.java", arguments);
        if (!Arrays.equals(first, Files.readAllBytes(output)) ||
                !Arrays.equals(firstSource, Files.readAllBytes(source))) {
            throw new AssertionError("repeated live export changed artifacts");
        }
        println("live-abi-export-repeat=PASS");
    }
}
