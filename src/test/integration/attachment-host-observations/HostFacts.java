import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.DosFileAttributes;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;

/** Research only: read-only host facts, never an attachment or preservation decision. */
public final class HostFacts {
    private static final LinkOption[] NOFOLLOW = {LinkOption.NOFOLLOW_LINKS};
    private static final LinkOption[] FOLLOW = {};
    private static final long CONTENT_LIMIT = 16L * 1024 * 1024;
    private record Selection(String id, String spelling, String policy) {}
    private record Pair(String left, String right) {}
    @FunctionalInterface private interface Query { Object run() throws Exception; }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("Expected explicit manifest path");
        byte[] bytes;
        try (var input = Files.newInputStream(Path.of(args[0]))) {
            bytes = input.readNBytes(65537);
        }
        if (bytes.length > 65536) throw new IOException("Manifest exceeds 65536 bytes");
        String text = utf8(bytes);
        if (text.indexOf('\r') >= 0 || !text.endsWith("\n")) {
            throw new IOException("Manifest requires LF-terminated records");
        }
        String[] lines = text.split("\n", -1);
        if (!lines[0].equals("FORGE_HOST_FACTS\t1")) throw new IOException("Manifest version");
        Map<String, Selection> selections = new LinkedHashMap<>();
        List<Pair> pairs = new ArrayList<>();
        for (int i = 1; i < lines.length - 1; i++) {
            String[] fields = lines[i].split("\t", -1);
            if (fields.length == 4 && fields[0].equals("FILE")) {
                if (!fields[1].matches("[a-z][a-z0-9_-]{0,63}")) throw new IOException("File ID");
                if (!fields[3].equals("READ") && !fields[3].equals("METADATA")) {
                    throw new IOException("File policy");
                }
                byte[] decoded = Base64.getDecoder().decode(fields[2]);
                if (!Base64.getEncoder().encodeToString(decoded).equals(fields[2])) {
                    throw new IOException("Noncanonical base64");
                }
                String spelling = utf8(decoded);
                if (spelling.isEmpty() || spelling.length() > 16384 || spelling.indexOf('\0') >= 0) {
                    throw new IOException("Path spelling bounds");
                }
                if (selections.putIfAbsent(fields[1], new Selection(fields[1], spelling, fields[3])) != null
                        || selections.size() > 64) throw new IOException("Duplicate/excess file ID");
            } else if (fields.length == 3 && fields[0].equals("PAIR")) {
                pairs.add(new Pair(fields[1], fields[2]));
                if (pairs.size() > 128) throw new IOException("Excess pairs");
            } else throw new IOException("Invalid manifest record " + i);
        }
        if (selections.isEmpty()) throw new IOException("Empty file selection");
        for (Pair pair : pairs) {
            if (!selections.containsKey(pair.left()) || !selections.containsKey(pair.right())) {
                throw new IOException("Unknown pair ID");
            }
        }
        Map<String, Object> files = new LinkedHashMap<>();
        for (Selection selected : selections.values()) files.put(selected.id(), inspect(selected));
        List<Object> comparisons = new ArrayList<>();
        for (Pair pair : pairs) {
            comparisons.add(map("left", pair.left(), "right", pair.right(), "isSameFile", query(() ->
                Files.isSameFile(path(selections.get(pair.left())), path(selections.get(pair.right()))))));
        }
        Map<String, Object> host = map("javaVersion", System.getProperty("java.version"),
            "javaRuntimeVersion", System.getProperty("java.runtime.version"),
            "javaVendor", System.getProperty("java.vendor"), "javaHome", System.getProperty("java.home"),
            "osName", System.getProperty("os.name"), "osVersion", System.getProperty("os.version"),
            "osArch", System.getProperty("os.arch"), "maxHeap", Runtime.getRuntime().maxMemory(),
            "fileSystemProvider", Path.of(args[0]).getFileSystem().provider().getClass().getName());
        Object result = map("schemaVersion", 1, "scope", "INSPECTION_ONLY", "host", host,
            "manifestSHA256", sha(bytes), "files", files, "pairs", comparisons,
            "limits", map("manifestBytes", 65536, "files", 64, "pairs", 128,
                "contentBytesPerRead", CONTENT_LIMIT, "userAttributes", 64,
                "attributeBytes", 65536, "totalAttributeBytesPerView", 1048576),
            "limitations", List.of("No attachment, preservation, atomicity or durability decision",
                "Path observations and sequential reads are not an immutable snapshot",
                "Java public channel identity is UNKNOWN; native oracle must inspect opened handles",
                "User-attribute enumeration is not complete native security metadata",
                "Read access can change atime; no access-time preservation claim",
                "Provider list allocations precede research output bounds; no universal heap claim"));
        System.out.write((json(result) + "\n").getBytes(StandardCharsets.UTF_8));
    }

    private static Path path(Selection selected) throws IOException {
        Path path = Path.of(selected.spelling());
        if (!path.isAbsolute()) throw new IOException("Path is not absolute");
        return path;
    }

    private static Object inspect(Selection selected) {
        Map<String, Object> facts = map("path", selected.spelling(), "pathUtf8Base64",
            Base64.getEncoder().encodeToString(selected.spelling().getBytes(StandardCharsets.UTF_8)),
            "policy", selected.policy());
        facts.put("pathConstruction", query(() -> path(selected).toString()));
        facts.put("nofollow", query(() -> basic(path(selected), NOFOLLOW)));
        facts.put("follow", query(() -> basic(path(selected), FOLLOW)));
        facts.put("symbolicLinkTarget", query(() -> Files.readSymbolicLink(path(selected)).toString()));
        facts.put("fileStore", query(() -> {
            var store = Files.getFileStore(path(selected));
            return map("name", store.name(), "type", store.type(), "readOnly", store.isReadOnly());
        }));
        for (boolean follow : List.of(false, true)) {
            LinkOption[] options = follow ? FOLLOW : NOFOLLOW;
            String suffix = follow ? "Follow" : "NoFollow";
            facts.put("unix" + suffix, query(() -> new TreeMap<>(Files.readAttributes(path(selected),
                "unix:dev,ino,nlink,uid,gid,mode", options))));
            facts.put("posix" + suffix, query(() -> {
                PosixFileAttributes attrs = Files.readAttributes(path(selected), PosixFileAttributes.class, options);
                return map("owner", attrs.owner().getName(), "group", attrs.group().getName(),
                    "permissions", attrs.permissions().stream().map(Enum::name).sorted().toList());
            }));
            facts.put("dos" + suffix, query(() -> {
                requireOrdinaryMetadataEntry(path(selected), options);
                DosFileAttributes attrs = Files.readAttributes(path(selected), DosFileAttributes.class, options);
                return map("archive", attrs.isArchive(), "hidden", attrs.isHidden(),
                    "readOnly", attrs.isReadOnly(), "system", attrs.isSystem());
            }));
            facts.put("acl" + suffix, query(() -> {
                requireOrdinaryMetadataEntry(path(selected), options);
                AclFileAttributeView view = Files.getFileAttributeView(path(selected), AclFileAttributeView.class, options);
                if (view == null) throw new UnsupportedOperationException("ACL view unavailable");
                var entries = view.getAcl();
                if (entries.size() > 256) throw new IOException("ACL entry bound");
                List<Object> acl = new ArrayList<>();
                for (var entry : entries) acl.add(map("type", entry.type().name(),
                    "principal", entry.principal().getName(), "flags",
                    entry.flags().stream().map(Enum::name).sorted().toList(), "permissions",
                    entry.permissions().stream().map(Enum::name).sorted().toList()));
                return map("owner", view.getOwner().getName(), "entries", acl,
                    "completeNativeSecurityMetadata", "UNKNOWN");
            }));
            facts.put("user" + suffix, query(() -> user(path(selected), options)));
        }
        facts.put("reads", selected.policy().equals("READ") ? query(() -> readTwice(path(selected)))
            : map("status", "NOT_REQUESTED"));
        facts.put("nofollowReadOpen", selected.policy().equals("READ") ? query(() -> {
            var attrs = Files.readAttributes(path(selected), BasicFileAttributes.class, NOFOLLOW);
            if (!attrs.isRegularFile() && !attrs.isSymbolicLink()) {
                throw new IOException("Not a regular file or symlink control; open not attempted");
            }
            try (var ignored = FileChannel.open(path(selected), StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
                return "OPENED_READ_ONLY";
            }
        }) : map("status", "NOT_REQUESTED"));
        return facts;
    }

    private static Object basic(Path path, LinkOption[] options) throws IOException {
        BasicFileAttributes attrs = Files.readAttributes(path, BasicFileAttributes.class, options);
        return map("regular", attrs.isRegularFile(), "directory", attrs.isDirectory(),
            "symbolicLink", attrs.isSymbolicLink(), "other", attrs.isOther(), "size", attrs.size(),
            "modifiedNanos", attrs.lastModifiedTime().to(TimeUnit.NANOSECONDS),
            "accessNanos", attrs.lastAccessTime().to(TimeUnit.NANOSECONDS),
            "creationNanos", attrs.creationTime().to(TimeUnit.NANOSECONDS),
            "fileKey", attrs.fileKey() == null ? null : attrs.fileKey().toString(),
            "fileKeyScope", "PATH_OBSERVATION_NOT_OPEN_CHANNEL_IDENTITY");
    }

    private static Object user(Path path, LinkOption[] options) throws Exception {
        requireOrdinaryMetadataEntry(path, options);
        var view = Files.getFileAttributeView(path, UserDefinedFileAttributeView.class, options);
        if (view == null) throw new UnsupportedOperationException("User attribute view unavailable");
        var names = view.list();
        if (names.size() > 64) throw new IOException("User attribute count bound");
        Map<String, Object> attributes = new TreeMap<>();
        int total = 0;
        for (String name : names) {
            int size = view.size(name);
            if (size < 0 || size > 65536 || (total += size) > 1048576) throw new IOException("Attribute byte bound");
            ByteBuffer buffer = ByteBuffer.allocate(size);
            if (view.read(name, buffer) != size) throw new IOException("Attribute changed size");
            attributes.put(name, map("bytes", size, "sha256", sha(buffer.array())));
        }
        return map("attributes", attributes, "completeNativeNamespaceEnumeration", "UNKNOWN");
    }

    private static void requireOrdinaryMetadataEntry(Path path, LinkOption[] options) throws IOException {
        // Provider metadata implementations can open a data descriptor. In particular,
        // opening a known FIFO for user/DOS attributes can block even without reading it.
        // Basic/unix/posix observations still describe such entries. This precondition
        // does not protect against a concurrent replacement; fixtures are trusted/owned.
        BasicFileAttributes attrs = Files.readAttributes(path, BasicFileAttributes.class, options);
        if (!attrs.isRegularFile() && !attrs.isDirectory()) {
            throw new IOException("Optional provider view not queried for nonregular/nondirectory entry");
        }
    }

    private static Object readTwice(Path path) throws Exception {
        if (!Files.isRegularFile(path)) throw new IOException("Not an observed regular file; read not attempted");
        try (FileChannel first = FileChannel.open(path, StandardOpenOption.READ);
                FileChannel second = FileChannel.open(path, StandardOpenOption.READ)) {
            return map("first", digest(first), "second", digest(second),
                "openedChannelIdentity", "UNKNOWN_PUBLIC_JAVA_API",
                "openOptions", List.of("READ"));
        }
    }

    private static Object digest(FileChannel channel) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        ByteBuffer buffer = ByteBuffer.allocate(65536);
        long count = 0;
        while (true) {
            int n = channel.read(buffer);
            if (n < 0) break;
            if (n == 0) throw new IOException("No read progress");
            count += n;
            if (count > CONTENT_LIMIT) throw new IOException("Research content bound exceeded");
            digest.update(buffer.array(), 0, n);
            buffer.clear();
        }
        return map("bytes", count, "sha256", HexFormat.of().formatHex(digest.digest()));
    }

    private static Object query(Query query) {
        try { return map("status", "OBSERVED", "value", query.run()); }
        catch (Exception failure) {
            String message = failure.getMessage();
            if (message != null && message.length() > 2048) message = message.substring(0, 2048);
            return map("status", "UNAVAILABLE", "exception", failure.getClass().getName(), "message", message);
        }
    }

    private static String utf8(byte[] bytes) throws CharacterCodingException {
        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
    }

    private static String sha(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static Map<String, Object> map(Object... entries) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int i = 0; i < entries.length; i += 2) result.put((String) entries[i], entries[i + 1]);
        return result;
    }

    private static String json(Object value) {
        if (value == null) return "null";
        if (value instanceof Number || value instanceof Boolean) return value.toString();
        if (value instanceof Map<?, ?> map) {
            List<String> fields = new ArrayList<>();
            map.forEach((key, item) -> fields.add(json(key.toString()) + ":" + json(item)));
            return "{" + String.join(",", fields) + "}";
        }
        if (value instanceof Iterable<?> list) {
            List<String> fields = new ArrayList<>();
            list.forEach(item -> fields.add(json(item)));
            return "[" + String.join(",", fields) + "]";
        }
        String string = value.toString();
        if (string.length() > 32768) throw new IllegalArgumentException("Research output string bound");
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < string.length(); i++) {
            char c = string.charAt(i);
            if (c == '"' || c == '\\') out.append('\\').append(c);
            else if (c < 32 || c > 126) out.append(String.format("\\u%04x", (int) c));
            else out.append(c);
        }
        return out.append('"').toString();
    }
}
