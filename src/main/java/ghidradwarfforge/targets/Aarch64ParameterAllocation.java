package ghidradwarfforge.targets;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.XmlEncode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.xml.XmlPullParserFactory;
import ghidradwarfforge.GhidraParameterAllocation;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.nativeapi.DwarfTarget;
import org.xml.sax.helpers.DefaultHandler;

/** AAPCS64 C.12-C.15: a composite that does not fit in registers goes wholly to the stack. */
public final class Aarch64ParameterAllocation {
    private static final String BASELINE =
        "6ad78c7504e89518ca8205c4b78b99177bd49726c966d46074888b31e50afa25";
    private static final String JOIN = "<join align=\"true\" stackspill=\"true\" backfill=\"false\"/>";

    private Aarch64ParameterAllocation() {
    }

    /** Uses an isolated prototype. Neither the program nor its compiler specification is modified. */
    public static GhidraParameterAllocation forProgram(Program program, ElfImage image,
            TaskMonitor monitor, Consumer<String> diagnostic) throws CancelledException, IOException {
        monitor.checkCancelled();
        var target = DwarfTarget.fromElf(image);
        var spec = program.getCompilerSpec();
        if (!target.name().equals("aarch64") ||
                !target.compilerSpecCallRestriction(program.getLanguageID().toString(),
                    spec.getCompilerSpecID().toString()).isEmpty() ||
                !target.elfAbiCallRestriction(image).isEmpty()) {
            return GhidraParameterAllocation.UNCHANGED;
        }
        var original = spec.getDefaultCallingConvention();
        var encoder = new XmlEncode(false);
        original.encode(encoder, spec.getPcodeInjectLibrary());
        String xml = encoder.toString();
        PrototypeModel corrected = new PrototypeModel();
        try {
            String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(xml.getBytes(StandardCharsets.UTF_8)));
            if (!hash.equals(BASELINE)) {
                diagnostic.accept("Computed parameter allocation correction unavailable: selected prototype differs from the audited baseline");
                return GhidraParameterAllocation.UNCHANGED;
            }
            String revised = xml.replace(JOIN,
                "<join align=\"true\" stackspill=\"false\" backfill=\"false\"/>")
                .replace("</input>", "<rule><datatype name=\"any\"/><goto_stack/>" +
                    "<consume_remaining storage=\"general\"/></rule></input>");
            var parser = XmlPullParserFactory.create(revised, "audited-AAPCS64-allocation", new DefaultHandler(), false);
            try {
                corrected.restoreXml(parser, spec);
            }
            finally {
                parser.dispose();
            }
        }
        catch (java.security.NoSuchAlgorithmException | org.xml.sax.SAXException |
                ghidra.xml.XmlParseException error) {
            throw new IOException("Cannot construct audited parameter allocation", error);
        }
        monitor.checkCancelled();
        return (function, task, report) -> {
            task.checkCancelled();
            if (function.getProgram() != program || function.hasCustomVariableStorage() ||
                    function.getCallingConvention() != original) {
                return Map.of();
            }
            var parameters = function.getParameters();
            if (parameters.length > 4096) return Map.of();
            boolean split = false;
            for (var parameter : parameters) {
                task.checkCancelled();
                var storage = parameter.getVariableStorage();
                boolean register = false, stack = false;
                for (var node : storage.getVarnodes()) {
                    register |= node.isRegister();
                    stack |= node.getAddress().isStackAddress();
                }
                if (register && stack) {
                    DataType type = parameter.getFormalDataType();
                    var seen = java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<DataType, Boolean>());
                    while (type instanceof TypeDef alias && seen.add(type) && seen.size() <= 64) {
                        type = alias.getBaseDataType();
                    }
                    if (!(type instanceof Composite) || type.getLength() < 9 || type.getLength() > 16) {
                        report.accept("Computed split parameter storage has no audited composite classification for " +
                            function.getName() + "::" + parameter.getName() + "; retaining the selected model");
                        return Map.of();
                    }
                    split = true;
                }
            }
            if (!split) return Map.of();
            var types = new ArrayList<DataType>();
            types.add(function.getReturn().getFormalDataType());
            for (var parameter : parameters) {
                if (!parameter.isAutoParameter()) types.add(parameter.getFormalDataType());
            }
            var signature = types.toArray(DataType[]::new);
            var expected = original.getStorageLocations(program, signature, true);
            var adjusted = corrected.getStorageLocations(program, signature, true);
            if (expected.length != parameters.length + 1 || adjusted.length != expected.length ||
                    !adjusted[0].equals(expected[0])) {
                throw new IllegalStateException("Audited parameter allocation changed the return or automatic parameters");
            }
            var changes = new LinkedHashMap<Integer, VariableStorage>();
            for (int index = 0; index < parameters.length; index++) {
                task.checkCancelled();
                var actual = parameters[index].getVariableStorage();
                var prior = expected[index + 1];
                var replacement = adjusted[index + 1];
                if (!prior.equals(actual) || prior.isForcedIndirect() != actual.isForcedIndirect() ||
                        prior.isAutoStorage() != actual.isAutoStorage()) {
                    throw new IllegalStateException("Saved dynamic storage disagrees with its selected prototype");
                }
                if (prior.equals(replacement)) continue;
                if (!replacement.isValid() || !replacement.isStackStorage() ||
                        replacement.size() != actual.size() ||
                        replacement.isForcedIndirect() != actual.isForcedIndirect() ||
                        replacement.isAutoStorage() != actual.isAutoStorage()) {
                    throw new IllegalStateException("Parameter allocation correction escaped the audited stack boundary");
                }
                changes.put(parameters[index].getOrdinal(), replacement);
                report.accept("Corrected computed parameter storage for " + function.getName() + "::" +
                    parameters[index].getName() + " from " + actual + " to " + replacement +
                    " using audited AAPCS64 allocation; saved program and decompiler output remain unchanged");
            }
            return Map.copyOf(changes);
        };
    }
}
