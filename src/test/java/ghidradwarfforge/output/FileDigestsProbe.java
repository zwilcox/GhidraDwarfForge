package ghidradwarfforge.output;

import java.nio.file.Path;

/** CLI oracle adapter: load the production helper from the installed extension JAR. */
public final class FileDigestsProbe {
    private FileDigestsProbe() {
    }

    public static void main(String[] arguments) throws Exception {
        if (arguments.length == 0) {
            throw new IllegalArgumentException("supply at least one input file");
        }
        System.out.println("digest-class-source=" + FileDigests.class.getProtectionDomain()
            .getCodeSource().getLocation().toURI());
        System.out.println("java-version=" + System.getProperty("java.version"));
        System.out.println("max-heap=" + Runtime.getRuntime().maxMemory());
        for (int index = 0; index < arguments.length; index++) {
            var result = FileDigests.read(Path.of(arguments[index]));
            System.out.printf("digest=%d sha256=%s crc32=%08x bytes=%d%n", index,
                result.sha256(), result.gnuDebuglinkCrc32(), result.byteCount());
        }
    }
}
