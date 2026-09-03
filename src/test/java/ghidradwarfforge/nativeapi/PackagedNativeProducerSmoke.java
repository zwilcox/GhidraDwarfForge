package ghidradwarfforge.nativeapi;

import java.nio.file.Path;

/** Resolves and loads an installed release's native pair in an isolated JVM. */
public final class PackagedNativeProducerSmoke {
    private PackagedNativeProducerSmoke() {
    }

    public static void main(String[] arguments) throws Exception {
        if (arguments.length != 3) {
            throw new IllegalArgumentException(
                "usage: PackagedNativeProducerSmoke <module-root> <platform> <target-profile>");
        }
        Path moduleRoot = Path.of(arguments[0]).toAbsolutePath().normalize();
        PackagedNativeLibraries.Pair pair =
            PackagedNativeLibraries.resolve(moduleRoot, arguments[1]);
        System.out.println("packaged-native-directory=" + pair.directory());
        DwarfProducerSmoke.main(new String[] {
            pair.consumer().toString(), pair.producer().toString(), arguments[2]
        });
        System.out.println("packaged-native-producer-smoke=PASS");
    }
}
