package ghidradwarfforge.formatters;

import com.google.gson.Gson;
import ghidradwarfforge.output.FileDigests;
import ghidradwarfforge.output.FormatterSelection;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/** Generation-bound presentation choices, with synthetic aliases to real canonical DIEs. */
public record FormatterPlan(Map<String, String> aliases, List<Rule> rules) {
    public record Flag(String name, String bits) { }
    public record Rule(String key, String alias, String name, String mode, long size,
            boolean signed, List<Flag> flags, List<String> peers) { }

    public FormatterPlan {
        aliases = Collections.unmodifiableMap(new TreeMap<>(aliases));
        rules = List.copyOf(rules);
    }

    /** LLDB imports by Python module basename: target filenames may contain dots or quotes. */
    public static Path outputPath(Path sidecar) {
        String name = "forge_formatters_" + digest(sidecar.getFileName().toString()
            .getBytes(StandardCharsets.UTF_8)) + ".py";
        return sidecar.resolveSibling(name);
    }

    public static FormatterPlan prepare(ProgramTypeModel model, FormatterSelection selection,
            BooleanSupplier cancelled) {
        var graph = model.types().byKey();
        var aliases = new TreeMap<String, String>();
        var rules = new ArrayList<Rule>();
        long textUnits = 0;
        var reserved = new java.util.HashSet<String>();
        for (var node : graph.values()) { check(cancelled); reserved.add(node.name()); }
        model.globals().forEach(value -> reserved.add(value.name()));
        model.functions().forEach(value -> reserved.add(value.name()));
        for (var choice : selection.modes().entrySet()) {
            check(cancelled);
            var node = graph.get(choice.getKey());
            boolean flags = choice.getValue().equals("flags");
            if (node == null || (flags ? !(node instanceof TypeGraph.EnumType) :
                    !(node instanceof TypeGraph.AggregateType))) {
                throw new IllegalArgumentException("formatter selection requires an emitted " +
                    (flags ? "enum" : "aggregate") + " canonical key: " + choice.getKey());
            }
            if (node.byteSize() == 0 || flags && node.byteSize() > 8 ||
                    node instanceof TypeGraph.AggregateType aggregate && aggregate.members().size() > 256) {
                throw new IllegalArgumentException("formatter type exceeds supported size/field bounds: " + node.key());
            }
            var peers = new ArrayList<String>();
            textUnits += node.key().length() + node.name().length();
            // GDB type equality can equate distinct DIEs. Retain same-name candidates
            // so both consumers can refuse a selection if canonical identity collapses.
            for (var candidate : model.types().nodes()) {
                check(cancelled);
                if (candidate.getClass() == node.getClass() && candidate.name().equals(node.name())) {
                    String alias = "__forge_formatter_" + digest(candidate.key().getBytes(StandardCharsets.UTF_8));
                    if (reserved.contains(alias)) throw new IllegalArgumentException("formatter alias collides with a program name");
                    aliases.put(candidate.key(), alias);
                    if (!candidate.key().equals(node.key())) peers.add(alias);
                }
            }
            if (aliases.size() > 4096) throw new IllegalArgumentException("too many ambiguous formatter type candidates");
            var values = new ArrayList<Flag>();
            if (node instanceof TypeGraph.EnumType enumeration) {
                if (enumeration.values().size() > 256) throw new IllegalArgumentException("formatter enum exceeds 256 names");
                long mask = enumeration.byteSize() == 8 ? -1L : (1L << (enumeration.byteSize() * 8)) - 1;
                for (var value : enumeration.values()) {
                    check(cancelled);
                    textUnits += value.name().length();
                    if (value.name().length() > 4096 || textUnits > 262144) {
                        throw new IllegalArgumentException("formatter labels exceed the text budget");
                    }
                    values.add(new Flag(value.name(), Long.toUnsignedString(value.value() & mask, 16)));
                }
                values.sort(java.util.Comparator.comparing(Flag::bits).thenComparing(Flag::name));
            }
            peers.sort(String::compareTo);
            if (textUnits > 262144) throw new IllegalArgumentException("formatter labels exceed the text budget");
            rules.add(new Rule(node.key(), aliases.get(node.key()), node.name(), choice.getValue(),
                node.byteSize(), node instanceof TypeGraph.EnumType enumeration && enumeration.signed(),
                List.copyOf(values), List.copyOf(peers)));
        }
        return new FormatterPlan(aliases, rules);
    }

    public String render(Path original, Path stagedSidecar, Path finalSidecar,
            BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        var manifest = new LinkedHashMap<String, Object>();
        manifest.put("schema", 1);
        manifest.put("original", artifact(original, original, cancelled));
        manifest.put("sidecar", artifact(stagedSidecar, finalSidecar, cancelled));
        manifest.put("rules", rules);
        byte[] runtime;
        try (var input = FormatterPlan.class.getResourceAsStream("/ghidradwarfforge/formatters/runtime.py")) {
            if (input == null) throw new IOException("packaged formatter runtime is missing");
            runtime = input.readAllBytes();
        }
        String data = Base64.getEncoder().encodeToString(new Gson().toJson(manifest).getBytes(StandardCharsets.UTF_8));
        check(cancelled);
        return """
            # GhidraDwarfForge optional formatters. Analyst text is JSON data, never Python.
            # GDB: source this file after loading symbols. LLDB: command script import this file.
            import base64 as _base64
            import json as _json
            import sys as _sys
            import types as _types
            _manifest = _json.loads(_base64.b64decode('%s'))
            _name = '_forge_formatters_' + _manifest['sidecar']['sha256']
            _previous = _sys.modules.get(_name)
            if _previous is not None:
                _previous.unload()
            _runtime = _types.ModuleType(_name)
            _sys.modules[_name] = _runtime
            exec(compile(_base64.b64decode('%s'), '<Forge formatter runtime>', 'exec'), _runtime.__dict__)
            _runtime.MANIFEST = _manifest
            def __lldb_init_module(debugger, internal_dict):
                internal_dict[_name] = _runtime
                _runtime.register_lldb(debugger)
            def unload():
                _runtime.unload()
            try:
                import gdb as _gdb
            except ImportError:
                pass
            else:
                _runtime.register_gdb()
            """.formatted(data, Base64.getEncoder().encodeToString(runtime));
    }

    private static Map<String, String> artifact(Path bytes, Path destination, BooleanSupplier cancelled)
            throws IOException {
        var result = new LinkedHashMap<String, String>();
        result.put("path", destination.toAbsolutePath().toString());
        result.put("sha256", FileDigests.read(bytes, cancelled).sha256());
        return result;
    }

    private static String digest(byte[] value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)); }
        catch (NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("formatter generation cancelled");
    }
}
