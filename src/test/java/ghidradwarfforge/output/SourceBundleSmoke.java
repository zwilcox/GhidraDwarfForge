package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.source.SyntheticSourceFile.FunctionText;

/** Exercises inventory identity, strict consumption, source correlation and cancellation. */
public final class SourceBundleSmoke {
    private static int checks;
    private static final String INPUT = "a".repeat(64);

    public static void main(String[] args) throws Exception {
        SyntheticSourceFile source = fixture();
        SourceBundle.Plan first = SourceBundle.prepare(INPUT, "sample.dbg.c", source, 3, () -> false);
        SourceBundle.Plan again = SourceBundle.prepare(INPUT, "sample.dbg.c", source, 3, () -> false);
        require(Arrays.equals(first.manifestBytes(), again.manifestBytes()), "manifest determinism");
        require(Arrays.equals(first.indexBytes(() -> false), again.indexBytes(() -> false)), "index determinism");
        require(first.manifest().equals(SourceBundle.read(first.manifestBytes(), () -> false)), "round trip");
        require(first.manifest().parts().size() > 2, "multiple partitions");
        require(first.manifest().functions().stream().map(SourceBundle.Function::disposition).toList()
            .equals(List.of("decompiled", "decompiled", "failed", "omitted")), "all dispositions");
        StringBuilder restored = new StringBuilder();
        for (var part : first.manifest().parts()) {
            byte[] bytes = first.bytes(part.fileName());
            require(SourceBundle.sha256(bytes).equals(part.sha256()), "content identity");
            require(bytes.length == part.bytes(), "byte count");
            String[] lines = new String(bytes, StandardCharsets.UTF_8).split("\n", -1);
            require(lines.length - 3 == part.last() - part.first() + 1, "local line population");
            for (int line = 2; line < lines.length - 1; line++) restored.append(lines[line]).append('\n');
        }
        require(Arrays.equals(restored.toString().getBytes(StandardCharsets.UTF_8), source.utf8()), "lossless source");
        for (int index = 0; index < source.functions().size(); index++) {
            var logical = source.functions().get(index);
            var recorded = first.manifest().functions().get(index);
            var position = first.fileLayout().locate(logical.startLine());
            require(position.file() == recorded.file() && position.line() == recorded.first(), "DIE/manifest coordinates");
            require(recorded.name().equals(logical.name()) && recorded.address() == logical.address(), "function identity");
        }
        String index = new String(first.indexBytes(() -> false), StandardCharsets.UTF_8);
        require(index.startsWith(SourceBundle.INDEX_PREFIX), "recognizable synthetic index");
        require(!index.contains("*/ hostile"), "analyst text is not interpolated in index");
        require(index.contains(first.manifestName()), "manifest discovery");
        var regrouped = SourceBundle.prepare(INPUT, "sample.dbg.c", source, 200, () -> false);
        require(!first.manifestName().equals(regrouped.manifestName()), "policy identity");
        var renamed = SourceBundle.prepare(INPUT, "another.dbg.c", source, 3, () -> false);
        require(!first.manifestName().equals(renamed.manifestName()), "index binding");
        require(first.manifest().parts().equals(renamed.manifest().parts()), "identical parts reusable across indices");
        var reinput = SourceBundle.prepare("b".repeat(64), "sample.dbg.c", source, 3, () -> false);
        require(!first.manifestName().equals(reinput.manifestName()), "input binding");
        byte[] returned = first.bytes(first.manifest().parts().getFirst().fileName());
        returned[0] = 0;
        require(first.bytes(first.manifest().parts().getFirst().fileName())[0] == '/', "part defensive copy");
        byte[] manifest = first.manifestBytes(); manifest[0] = 0;
        require(first.manifestBytes()[0] == '{', "manifest defensive copy");

        String valid = new String(first.manifestBytes(), StandardCharsets.UTF_8);
        for (String invalid : List.of(
                valid.replaceFirst("\\{", "{\"schema\":1,"),
                valid.replace("\"schema\":1", "\"schema\":2"),
                valid.replace("\"schema\":1", "\"schema\":1,\"unknown\":0"),
                valid.replace("\"targetLines\":3", "\"targetLines\":0"),
                valid.replace("\"targetLines\":3", "\"targetLines\":2147483648"),
                valid.replace("\"targetLines\":3", "\"targetLines\":3.0"),
                valid.replace("\"targetLines\":3", "\"targetLines\":null"),
                valid.replace("\"targetLines\":3", "\"targetLines\":true"),
                valid.replace("sample.dbg.c", "../sample.dbg.c"),
                valid.replace("\"disposition\":\"failed\"", "\"disposition\":\"guessed\""),
                valid.replace("\"file\":1", "\"file\":2"),
                valid.replaceFirst("\"first\":1", "\"first\":2"),
                valid.replaceFirst("\"last\":[0-9]+", "\"last\":2147483647"),
                valid.replaceFirst("\"name\":\"forge-src-", "\"name\":\"../forge-src-"),
                valid.replace("\"first\":3", "\"first\":2147483647"),
                " " + valid, valid + "{}", valid.stripTrailing(), valid.replace("{", "{ "))) {
            reject(invalid.getBytes(StandardCharsets.UTF_8));
        }
        reject(new byte[] { (byte) 0xc0, (byte) 0xaf });
        SourceBundle.Plan empty = SourceBundle.prepare(INPUT, "empty.dbg.c",
            SyntheticSourceFile.build("empty", "test", List.of()), 3, () -> false);
        require(empty.manifest().functions().isEmpty() && empty.manifest().parts().size() == 1, "preamble only");

        AtomicInteger calls = new AtomicInteger();
        SourceBundle.prepare(INPUT, "sample.dbg.c", source, 3, () -> { calls.incrementAndGet(); return false; });
        for (int stop = 1; stop <= calls.get(); stop++) {
            int limit = stop;
            AtomicInteger count = new AtomicInteger();
            try {
                SourceBundle.prepare(INPUT, "sample.dbg.c", source, 3, () -> count.incrementAndGet() >= limit);
                throw new AssertionError("preparation ignored cancellation at " + stop);
            }
            catch (CancellationException expected) { checks++; }
        }
        try {
            first.indexBytes(() -> true);
            throw new AssertionError("index ignored cancellation");
        }
        catch (CancellationException expected) { checks++; }
        System.out.println("source-bundle-smoke: PASS checks=" + checks + " preparationCancellationPoints=" + calls.get());
    }

    static SyntheticSourceFile fixture() {
        return SyntheticSourceFile.build("firmware", "test", List.of(
            new FunctionText("duplicate", 0x1000, "int duplicate(void) {\n    return 5;\n}\n", null),
            new FunctionText("duplicate", 0x2000, "int duplicate(void) {\n    return 9;\n}\n", null),
            new FunctionText("*/ hostile \"λ\"", 0x3000, null, "unavailable"),
            FunctionText.omitted("omitted", 0x4000, "selection")));
    }

    private static void reject(byte[] bytes) throws Exception {
        try {
            SourceBundle.read(bytes, () -> false);
            throw new AssertionError("accepted malformed manifest: " + new String(bytes, StandardCharsets.UTF_8));
        }
        catch (IOException expected) { checks++; }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
