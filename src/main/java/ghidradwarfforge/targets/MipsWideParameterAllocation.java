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
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.Integer16DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
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

/** Audited N32/N64 positional argument slots, without program mutation. */
public final class MipsWideParameterAllocation {
    private static final String N32_BASELINE =
        "7779b39a220a4ef8fc5da8c838311138a0cec39e6724ed3afeb076b0652bd9a2";

    private MipsWideParameterAllocation() {
    }

    public static GhidraParameterAllocation forProgram(Program program, ElfImage image,
            TaskMonitor monitor, Consumer<String> diagnostic) throws CancelledException, IOException {
        monitor.checkCancelled();
        boolean big = image.byteOrder() == java.nio.ByteOrder.BIG_ENDIAN;
        boolean n64 = image.is64Bit();
        String profile = n64 ? "N64" : "N32";
        String baseline = n64 ? (big
            ? "b8f0d07f076f2c193e61b0ff69312bdea213f144d22a9f3acf0ed5c617f2f713"
            : "d210c0b368233a5370593154af3abec36c52ff3cb2a399e1afca2ba7542620a5") : N32_BASELINE;
        var spec = program.getCompilerSpec();
        byte[] header = image.headerBytes();
        int osAbi = Byte.toUnsignedInt(header[7]);
        if (image.machine() != 8 || (image.type() != 2 && image.type() != 3) ||
                (image.flags() & ~7L) != (n64 ? 0x80000000L : 0x80000020L) || (osAbi != 0 && osAbi != 3) ||
                Byte.toUnsignedInt(header[8]) > 1 || program.getDefaultPointerSize() != (n64 ? 8 : 4) ||
                !program.getLanguageID().toString().equals("MIPS:" + (big ? "BE" : "LE") + (n64 ? ":64:default" : ":64:64-32addr")) ||
                !spec.getCompilerSpecID().toString().equals(n64 ? "default" : "n32")) {
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
            // PrototypeModel.getKilledByCallList() lazily turns null into an
            // empty array. Analysis can therefore add this empty XML element
            // without changing allocation; reopening removes it again. Keep
            // all nonempty register lists and every other audited byte strict.
            String fingerprintXml = xml.replace("<killedbycall/>", "");
            String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(fingerprintXml.getBytes(StandardCharsets.UTF_8)));
            if (!baseline.equals(hash)) {
                diagnostic.accept("Computed " + profile + " allocation correction unavailable: selected prototype differs from the audited baseline");
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
            // The pinned dual-class aggregate rule aligns stack storage but
            // does not skip odd register slots. An allocation-only placeholder
            // consumes that ABI hole; it is never exported as a parameter.
            var allocationTypes = new ArrayList<DataType>();
            allocationTypes.add(signature[0]);
            int[] allocationIndices = new int[parameters.length];
            long slots = 0;
            int padding = 0;
            for (int index = 0; index < parameters.length; index++) {
                task.checkCancelled();
                var parameter = parameters[index];
                if (parameter.isAutoParameter()) {
                    slots += (parameter.getVariableStorage().size() + 7L) / 8;
                }
                else {
                    DataType input = inputType(parameter.getFormalDataType());
                    if (input.getLength() <= 0) return Map.of();
                    boolean aligned = input.getAlignment() >= 16;
                    if (aligned && (slots & 1) != 0) {
                        if (input instanceof Composite && slots < 8) {
                            allocationTypes.add(new UnsignedLongLongDataType(program.getDataTypeManager()));
                            padding++;
                        }
                        slots++;
                    }
                    allocationTypes.add(input);
                    slots += (input.getLength() + 7L) / 8;
                }
                allocationIndices[index] = index + 1 + padding;
            }
            var adjusted = corrected.getStorageLocations(program, allocationTypes.toArray(DataType[]::new), true);
            if (expected.length != parameters.length + 1 || adjusted.length != expected.length + padding ||
                    !adjusted[0].equals(expected[0])) {
                throw new IllegalStateException("Audited MIPS input allocation changed return or automatic parameter count");
            }
            var changes = new LinkedHashMap<Integer, VariableStorage>();
            for (int index = 0; index < parameters.length; index++) {
                task.checkCancelled();
                var actual = parameters[index].getVariableStorage();
                var prior = expected[index + 1];
                var replacement = adjusted[allocationIndices[index]];
                if (!prior.equals(actual) || prior.isForcedIndirect() != actual.isForcedIndirect() ||
                        prior.isAutoStorage() != actual.isAutoStorage()) {
                    throw new IllegalStateException("Saved MIPS dynamic storage disagrees with its selected prototype");
                }
                if (prior.equals(replacement)) continue;
                if (!replacement.isValid() || replacement.size() != actual.size() ||
                        replacement.isForcedIndirect() != actual.isForcedIndirect() ||
                        replacement.isAutoStorage() != actual.isAutoStorage()) {
                    throw new IllegalStateException("MIPS allocation correction changed parameter representation");
                }
                changes.put(parameters[index].getOrdinal(), replacement);
                report.accept("Corrected computed parameter storage for " + function.getName() + "::" +
                    parameters[index].getName() + " from " + actual + " to " + replacement +
                    " using audited " + profile + " allocation; saved program and decompiler output remain unchanged");
            }
            return Map.copyOf(changes);
        };
    }

    /**
     * Allocation-only shape: GCC's N32/N64 classifier considers direct, aligned
     * double fields, not floating primitives nested in an array, union or struct.
     * The original types are retained for DWARF and in the saved program.
     */
    private static DataType inputType(DataType original) {
        DataType type = original;
        var seen = java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<DataType, Boolean>());
        while (type instanceof TypeDef alias && seen.add(type) && seen.size() <= 64) {
            type = alias.getBaseDataType();
        }
        if (type.getLength() != original.getLength()) return original;
        var manager = type.getDataTypeManager();
        if (type instanceof AbstractIntegerDataType && type.getLength() == 16) {
            // The pinned Ghidra data organization reports eight-byte alignment;
            // the selected GCC ABI aligns its native 128-bit integer to 16.
            return new Integer16DataType(manager) {
                @Override
                public int getAlignment() { return 16; }
            };
        }
        if (!(type instanceof Structure structure) || type.getLength() <= 0 || type.getLength() > 4096) {
            return original;
        }
        int alignment = Math.min(16, original.getAlignment());
        var shape = new StructureDataType("__forge_allocation_shape", 0, manager) {
            @Override
            public int getAlignment() { return alignment; }
        };
        for (int offset = 0; offset < type.getLength();) {
            int size = Math.min(8, type.getLength() - offset);
            DataType slot = size == 8 ? new UnsignedLongLongDataType(manager)
                : new ArrayDataType(new UnsignedCharDataType(manager), size, 1, manager);
            var component = structure.getComponentAt(offset);
            if (size == 8 && component != null && component.getOffset() == offset &&
                    component.getLength() == 8 && !component.isBitFieldComponent()) {
                DataType field = component.getDataType();
                var aliases = java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<DataType, Boolean>());
                while (field instanceof TypeDef alias && aliases.add(field) && aliases.size() <= 64) {
                    field = alias.getBaseDataType();
                }
                if (field instanceof AbstractFloatDataType && field.getLength() == 8) slot = field;
            }
            shape.add(slot, size, "slot_" + offset, null);
            offset += size;
        }
        return shape;
    }

    /** Eight positional slots, with the original return model and pointer width retained. */
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
        return xml.append("<rule><datatype name=\"any\"/><join align=\"true\"/></rule></input>").toString();
    }
}
