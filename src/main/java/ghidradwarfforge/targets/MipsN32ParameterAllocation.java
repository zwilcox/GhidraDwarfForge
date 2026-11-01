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
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.XmlEncode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.xml.XmlPullParserFactory;
import ghidradwarfforge.GhidraParameterAllocation;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.elf.MipsAbiFlags;
import org.xml.sax.helpers.DefaultHandler;

/** N32 positional argument slots and by-value aggregate allocation, without program mutation. */
public final class MipsN32ParameterAllocation {
    private static final String BASELINE =
        "7779b39a220a4ef8fc5da8c838311138a0cec39e6724ed3afeb076b0652bd9a2";

    private MipsN32ParameterAllocation() {
    }

    public static GhidraParameterAllocation forProgram(Program program, ElfImage image,
            TaskMonitor monitor, Consumer<String> diagnostic) throws CancelledException, IOException {
        monitor.checkCancelled();
        boolean big = image.byteOrder() == java.nio.ByteOrder.BIG_ENDIAN;
        var spec = program.getCompilerSpec();
        byte[] header = image.headerBytes();
        int osAbi = Byte.toUnsignedInt(header[7]);
        if (image.machine() != 8 || image.is64Bit() || (image.type() != 2 && image.type() != 3) ||
                (image.flags() & ~7L) != 0x80000020L || (osAbi != 0 && osAbi != 3) ||
                Byte.toUnsignedInt(header[8]) > 1 || program.getDefaultPointerSize() != 4 ||
                !program.getLanguageID().toString().equals("MIPS:" + (big ? "BE" : "LE") + ":64:64-32addr") ||
                !spec.getCompilerSpecID().toString().equals("n32")) {
            return GhidraParameterAllocation.UNCHANGED;
        }
        var observation = MipsAbiFlags.observe(image, monitor::isCancelled);
        if (observation.status() != MipsAbiFlags.Status.AVAILABLE) return GhidraParameterAllocation.UNCHANGED;
        var fields = observation.fields().orElseThrow();
        if (fields.version() != 0 || fields.isaLevel() != 64 || fields.isaRevision() != 2 ||
                fields.gprSize() != 2 || fields.cpr1Size() != 2 || fields.cpr2Size() != 0 ||
                fields.fpAbi() != 1 || fields.isaExtension() != 0 || fields.ases() != 0 ||
                (fields.flags1() & ~1L) != 0 || fields.flags2() != 0) {
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
            if (!BASELINE.equals(hash)) {
                diagnostic.accept("Computed N32 allocation correction unavailable: selected prototype differs from the audited baseline");
                return GhidraParameterAllocation.UNCHANGED;
            }
            String revised = xml.substring(0, xml.indexOf("<input")) + input(big) +
                xml.substring(xml.indexOf("</input>") + "</input>".length());
            var parser = XmlPullParserFactory.create(revised, "audited-N32-allocation", new DefaultHandler(), false);
            try {
                corrected.restoreXml(parser, spec);
            }
            finally {
                parser.dispose();
            }
        }
        catch (java.security.NoSuchAlgorithmException | org.xml.sax.SAXException |
                ghidra.xml.XmlParseException error) {
            throw new IOException("Cannot construct audited N32 parameter allocation", error);
        }
        return (function, task, report) -> {
            task.checkCancelled();
            if (function.getProgram() != program || function.hasCustomVariableStorage() ||
                    function.getCallingConvention() != original) return Map.of();
            var parameters = function.getParameters();
            if (parameters.length > 4096) return Map.of();
            var types = new ArrayList<DataType>();
            types.add(function.getReturn().getFormalDataType());
            for (var parameter : parameters) {
                task.checkCancelled();
                if (!parameter.isAutoParameter()) types.add(parameter.getFormalDataType());
            }
            var signature = types.toArray(DataType[]::new);
            var expected = original.getStorageLocations(program, signature, true);
            var adjusted = corrected.getStorageLocations(program, signature, true);
            if (expected.length != parameters.length + 1 || adjusted.length != expected.length ||
                    !adjusted[0].equals(expected[0])) {
                throw new IllegalStateException("Audited N32 input allocation changed return or automatic parameter count");
            }
            var changes = new LinkedHashMap<Integer, VariableStorage>();
            for (int index = 0; index < parameters.length; index++) {
                task.checkCancelled();
                var actual = parameters[index].getVariableStorage();
                var prior = expected[index + 1];
                var replacement = adjusted[index + 1];
                if (!prior.equals(actual) || prior.isForcedIndirect() != actual.isForcedIndirect() ||
                        prior.isAutoStorage() != actual.isAutoStorage()) {
                    throw new IllegalStateException("Saved N32 dynamic storage disagrees with its selected prototype");
                }
                if (prior.equals(replacement)) continue;
                if (!replacement.isValid() || replacement.size() != actual.size() ||
                        replacement.isForcedIndirect() != actual.isForcedIndirect() ||
                        replacement.isAutoStorage() != actual.isAutoStorage()) {
                    throw new IllegalStateException("N32 allocation correction changed parameter representation");
                }
                changes.put(parameters[index].getOrdinal(), replacement);
                report.accept("Corrected computed parameter storage for " + function.getName() + "::" +
                    parameters[index].getName() + " from " + actual + " to " + replacement +
                    " using audited N32 allocation; saved program and decompiler output remain unchanged");
            }
            return Map.copyOf(changes);
        };
    }

    /** Ghidra 12.0.3 N64 input rules also describe N32 slots; pointer types remain four bytes. */
    private static String input(boolean big) {
        var xml = new StringBuilder("<input killedbycall=\"true\">");
        String[] general = { "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3" };
        for (int index = 0; index < general.length; index++) {
            xml.append("<group><pentry minsize=\"1\" maxsize=\"8\" metatype=\"float\"><register name=\"f")
                .append(12 + index).append("\"/></pentry><pentry minsize=\"1\" maxsize=\"8\"><register name=\"")
                .append(general[index]).append("\"/></pentry></group>");
        }
        xml.append("<pentry minsize=\"1\" maxsize=\"500\" align=\"8\"><addr offset=\"0\" space=\"stack\"/></pentry>");
        String justify = big ? " reversejustify=\"true\"" : "";
        xml.append("<rule><datatype name=\"float\"/><varargs first=\"0\"/>")
            .append(big ? "<join reversejustify=\"true\"/>" : "<consume storage=\"general\"/>").append("</rule>")
            .append("<rule><datatype name=\"struct\"/><varargs first=\"0\"/><join").append(justify).append("/></rule>")
            .append("<rule><datatype name=\"float\"/><consume storage=\"float\"/></rule>");
        if (big) xml.append("<rule><datatype name=\"float\"/><join reversejustify=\"true\"/></rule>");
        xml.append("<rule><datatype name=\"struct\"/><join_dual_class stackspill=\"true\" fillalternate=\"true\"")
            .append(justify).append("/></rule>");
        if (big) xml.append("<rule><datatype name=\"union\"/><join reversejustify=\"true\"/></rule>");
        return xml.append("<rule><datatype name=\"any\"/><join/></rule></input>").toString();
    }
}
