package ghidradwarfforge.nativeapi;

import static ghidradwarfforge.nativeapi.DwarfConstants.DW_AT_DATA_BIT_OFFSET;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_AT_HIGH_PC;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_AT_LANGUAGE;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_AT_LOCATION;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_AT_LOW_PC;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_OFFSET32;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_POINTER32;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_POINTER64;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_SYMBOLIC_RELOCATIONS;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_TARGET_BIGENDIAN;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_TARGET_LITTLEENDIAN;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLV_ERROR;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLV_OK;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_LANG_C11;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_TAG_COMPILE_UNIT;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_TAG_FORMAL_PARAMETER;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_TAG_SUBPROGRAM;
import static ghidradwarfforge.nativeapi.DwarfConstants.DWARF_DRD_BUFFER_VERSION;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.LongByReference;
import com.sun.jna.ptr.PointerByReference;

import ghidradwarfforge.nativeapi.DwarfNativeTypes.Debug;
import ghidradwarfforge.nativeapi.DwarfNativeTypes.Die;
import ghidradwarfforge.nativeapi.DwarfNativeTypes.Error;
import ghidradwarfforge.nativeapi.DwarfNativeTypes.Expr;
import ghidradwarfforge.elf.MatchedElfSidecarWriter;

/**
 * Standalone libdwarf producer ABI test.
 *
 * <p>The Gradle task launches this class in a child JVM. Native crashes are
 * therefore reported as a non-zero task result without loading libdwarfp into
 * the Gradle daemon or Ghidra.</p>
 */
public final class DwarfProducerSmoke {
    private static final String EXPECTED_VERSION = "2.3.2";
    private static final long TEXT_SYMBOL_INDEX = 0x1001L;
    private static final long FUNCTION_SIZE = 0x40L;

    private enum TargetProfile {
        X86_64("x86_64", 8, true, 0x1_0000_1234L),
        ARM64("arm64", 8, true, 0x1_0000_1234L),
        MIPS32BE("mips", 4, false, 0x0040_1234L),
        MIPS32LE("mips", 4, true, 0x0040_1234L);

        private final String isaName;
        private final int addressBytes;
        private final boolean littleEndian;
        private final long functionAddress;

        TargetProfile(String isaName, int addressBytes, boolean littleEndian,
                long functionAddress) {
            this.isaName = isaName;
            this.addressBytes = addressBytes;
            this.littleEndian = littleEndian;
            this.functionAddress = functionAddress;
        }

        private static TargetProfile parse(String value) {
            return switch (value.toLowerCase(java.util.Locale.ROOT)) {
                case "x86_64" -> X86_64;
                case "arm64", "aarch64" -> ARM64;
                case "mips", "mips32be" -> MIPS32BE;
                case "mipsel", "mips32le" -> MIPS32LE;
                default -> throw new IllegalArgumentException(
                    "unknown target profile " + value +
                        " (expected x86_64, arm64, mips32be, or mips32le)");
            };
        }

        private long producerFlags() {
            long pointerFlag = addressBytes == 8 ? DW_DLC_POINTER64 : DW_DLC_POINTER32;
            long byteOrderFlag =
                littleEndian ? DW_DLC_TARGET_LITTLEENDIAN : DW_DLC_TARGET_BIGENDIAN;
            return pointerFlag | DW_DLC_OFFSET32 | DW_DLC_SYMBOLIC_RELOCATIONS |
                byteOrderFlag;
        }
    }

    @Structure.FieldOrder({ "type", "length", "offset", "symbolIndex" })
    public static final class RelocationData extends Structure {
        public byte type;
        public byte length;
        public long offset;
        public long symbolIndex;

        public RelocationData() {
        }

        public RelocationData(Pointer pointer) {
            super(pointer);
            read();
        }
    }

    private record SectionRecord(String name, long symbolIndex) {
    }

    private record SidecarRequest(Path input, Path output, long functionAddress) {
    }

    private DwarfProducerSmoke() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 3 && args.length != 6) {
            throw new IllegalArgumentException(
                "usage: DwarfProducerSmoke <absolute-libdwarf> <absolute-libdwarfp> " +
                    "<x86_64|arm64|mips32be|mips32le> [<input-elf> <output-dbg> " +
                    "<function-address>]");
        }

        Path consumerPath = requireNative(args[0]);
        Path producerPath = requireNative(args[1]);
        TargetProfile target = TargetProfile.parse(args[2]);
        SidecarRequest sidecar = args.length == 6
                ? new SidecarRequest(requireFile(args[3]),
                    Path.of(args[4]).toAbsolutePath().normalize(), parseAddress(args[5]))
                : null;
        System.out.printf("java=%s os=%s arch=%s%n", System.getProperty("java.version"),
            System.getProperty("os.name"), System.getProperty("os.arch"));
        System.out.printf("libdwarf=%s sha256=%s%n", consumerPath, sha256(consumerPath));
        System.out.printf("libdwarfp=%s sha256=%s%n", producerPath, sha256(producerPath));
        System.out.printf("target=%s isa=%s address-size=%d endian=%s%n", target.name(),
            target.isaName, target.addressBytes,
            target.littleEndian ? "little" : "big");

        // Load the dependency first and never through a static interface field.
        LibDwarfConsumer consumer = Native.load(consumerPath.toString(), LibDwarfConsumer.class);
        LibDwarfProducer producer = Native.load(producerPath.toString(), LibDwarfProducer.class);
        String packageVersion = consumer.dwarf_package_version();
        if (!EXPECTED_VERSION.equals(packageVersion)) {
            throw new IllegalStateException(
                "expected libdwarf " + EXPECTED_VERSION + ", found " + packageVersion);
        }
        System.out.println("libdwarf-package-version=" + packageVersion);

        runProducer(producer, consumer, target, sidecar);
        System.out.println("native-producer-smoke=PASS");
    }

    private static void runProducer(LibDwarfProducer producer, LibDwarfConsumer consumer,
            TargetProfile target, SidecarRequest sidecar) throws IOException {
        Map<Long, SectionRecord> sections = new LinkedHashMap<>();
        long[] nextSectionIndex = { 1L };
        long[] nextSectionSymbolIndex = { 1L };

        // Strongly referenced until dwarf_producer_finish_a returns.
        LibDwarfProducer.SectionCallback sectionCallback = (name, size, type, flags, link,
                info, sectionNameSymbolIndex, userData, callbackError) -> {
            long elfSectionIndex = nextSectionIndex[0]++;
            long elfSectionSymbolIndex = nextSectionSymbolIndex[0]++;
            sectionNameSymbolIndex.setValue(elfSectionSymbolIndex);
            sections.put(elfSectionIndex,
                new SectionRecord(Objects.requireNonNull(name), elfSectionSymbolIndex));
            System.out.printf(
                "callback section=%d symbol=%d name=%s align=%d type=%d flags=%d link=%d info=%d%n",
                elfSectionIndex, elfSectionSymbolIndex, name, size, type, flags, link, info);
            return Math.toIntExact(elfSectionIndex);
        };

        PointerByReference errorOut = new PointerByReference();
        PointerByReference debugOut = new PointerByReference();
        int initResult = producer.dwarf_producer_init(target.producerFlags(), sectionCallback,
            null, null, null, target.isaName, "V5", "", debugOut, errorOut);
        check(initResult, "dwarf_producer_init", errorOut, consumer);
        Debug debug = new Debug(requirePointer(debugOut, "producer debug"));
        boolean finished = false;
        try {
            long functionAddress = sidecar == null
                    ? target.functionAddress : sidecar.functionAddress();
            Die compileUnit = newDie(producer, consumer, debug, DW_TAG_COMPILE_UNIT, errorOut);
            addName(producer, consumer, compileUnit, "ghidra-dwarf-forge-smoke.c", errorOut);
            addProducer(producer, consumer, compileUnit, errorOut);
            addUnsigned(producer, consumer, debug, compileUnit, DW_AT_LANGUAGE, DW_LANG_C11,
                errorOut);
            addAddress(producer, consumer, debug, compileUnit, functionAddress,
                TEXT_SYMBOL_INDEX, errorOut);

            Die function = newDie(producer, consumer, debug, DW_TAG_SUBPROGRAM, errorOut);
            checkCall(producer.dwarf_die_link_a(function, compileUnit, null, null, null,
                errorOut), "dwarf_die_link_a(subprogram)", errorOut, consumer);
            addName(producer, consumer, function, "smoke_function", errorOut);
            addAddress(producer, consumer, debug, function, functionAddress,
                TEXT_SYMBOL_INDEX, errorOut);
            addUnsigned(producer, consumer, debug, function, DW_AT_HIGH_PC, FUNCTION_SIZE,
                errorOut);
            verifyProducerErrorDecoding(producer, consumer, debug, function, errorOut);
            Die parameter = newDie(producer, consumer, debug, DW_TAG_FORMAL_PARAMETER,
                errorOut);
            checkCall(producer.dwarf_die_link_a(parameter, function, null, null, null,
                errorOut), "dwarf_die_link_a(parameter)", errorOut, consumer);
            addName(producer, consumer, parameter, "register_parameter", errorOut);
            addRegisterLocation(producer, consumer, debug, parameter, 0, errorOut);

            checkCall(producer.dwarf_add_die_to_debug_a(debug, compileUnit, errorOut),
                "dwarf_add_die_to_debug_a", errorOut, consumer);

            LongByReference bufferCountOut = new LongByReference();
            checkCall(producer.dwarf_transform_to_disk_form_a(debug, bufferCountOut, errorOut),
                "dwarf_transform_to_disk_form_a", errorOut, consumer);
            long bufferCount = bufferCountOut.getValue();
            if (bufferCount <= 0 || bufferCount > 100_000) {
                throw new IllegalStateException("implausible section buffer count: " + bufferCount);
            }

            Map<Long, ByteArrayOutputStream> sectionData = collectSectionData(producer, consumer,
                debug, errorOut, bufferCount, sections);
            requireSectionWithData(".debug_info", sections, sectionData);
            requireSectionWithData(".debug_abbrev", sections, sectionData);
            validateRelocations(producer, consumer, debug, errorOut, sections, sectionData,
                target.addressBytes);
            if (sidecar != null) {
                Map<String, byte[]> debugSections = materializeDebugSections(sections,
                    sectionData);
                new MatchedElfSidecarWriter().write(sidecar.input(), sidecar.output(),
                    debugSections);
                System.out.printf("sidecar=%s function-address=0x%x sections=%s%n",
                    sidecar.output(), functionAddress, debugSections.keySet());
            }

            checkCall(producer.dwarf_producer_finish_a(debug, errorOut),
                "dwarf_producer_finish_a", errorOut, consumer);
            finished = true;
            System.out.printf("buffers=%d sections=%d%n", bufferCount, sections.size());
        }
        finally {
            // All producer allocations, including returned error objects, belong to
            // the producer debug handle and are released by finish.
            if (!finished) {
                PointerByReference finishError = new PointerByReference();
                int result = producer.dwarf_producer_finish_a(debug, finishError);
                if (result != DW_DLV_OK) {
                    System.err.println(describeError("cleanup dwarf_producer_finish_a",
                        finishError, consumer));
                }
            }
        }
    }

    private static Map<String, byte[]> materializeDebugSections(
            Map<Long, SectionRecord> sections,
            Map<Long, ByteArrayOutputStream> sectionData) {
        Map<String, byte[]> result = new LinkedHashMap<>();
        sections.forEach((index, section) -> {
            ByteArrayOutputStream data = sectionData.get(index);
            if (section.name().startsWith(".debug_") && data != null && data.size() != 0) {
                byte[] previous = result.put(section.name(), data.toByteArray());
                if (previous != null) {
                    throw new IllegalStateException(
                        "duplicate producer section " + section.name());
                }
            }
        });
        if (!result.containsKey(".debug_info") || !result.containsKey(".debug_abbrev")) {
            throw new IllegalStateException("producer output lacks required DWARF sections");
        }
        return result;
    }

    private static Die newDie(LibDwarfProducer producer, LibDwarfConsumer consumer,
            Debug debug, long tag, PointerByReference errorOut) {
        PointerByReference dieOut = new PointerByReference();
        checkCall(producer.dwarf_new_die_a(debug, tag, null, null, null, null, dieOut,
            errorOut), "dwarf_new_die_a(tag=0x" + Long.toHexString(tag) + ")", errorOut,
            consumer);
        return new Die(requirePointer(dieOut, "producer DIE"));
    }

    private static void addName(LibDwarfProducer producer, LibDwarfConsumer consumer,
            Die die, String name, PointerByReference errorOut) {
        PointerByReference attributeOut = new PointerByReference();
        checkCall(producer.dwarf_add_AT_name_a(die, name, attributeOut, errorOut),
            "dwarf_add_AT_name_a", errorOut, consumer);
        requirePointer(attributeOut, "name attribute");
    }

    private static void addProducer(LibDwarfProducer producer, LibDwarfConsumer consumer,
            Die die, PointerByReference errorOut) {
        PointerByReference attributeOut = new PointerByReference();
        checkCall(producer.dwarf_add_AT_producer_a(die,
            "GhidraDwarfForge native ABI smoke", attributeOut, errorOut),
            "dwarf_add_AT_producer_a", errorOut, consumer);
        requirePointer(attributeOut, "producer attribute");
    }

    private static void addUnsigned(LibDwarfProducer producer, LibDwarfConsumer consumer,
            Debug debug, Die die, short attribute, long value, PointerByReference errorOut) {
        PointerByReference attributeOut = new PointerByReference();
        checkCall(producer.dwarf_add_AT_unsigned_const_a(debug, die, attribute, value,
            attributeOut, errorOut), "dwarf_add_AT_unsigned_const_a", errorOut, consumer);
        requirePointer(attributeOut, "unsigned attribute");
    }

    private static void verifyProducerErrorDecoding(LibDwarfProducer producer,
            LibDwarfConsumer consumer, Debug debug, Die die,
            PointerByReference errorOut) {
        PointerByReference attributeOut = new PointerByReference();
        int result = producer.dwarf_add_AT_unsigned_const_a(debug, die,
            DW_AT_DATA_BIT_OFFSET, 0, attributeOut, errorOut);
        if (result != DW_DLV_ERROR) {
            throw new IllegalStateException("invalid producer attribute was not rejected");
        }
        String detail = describeError("controlled invalid producer attribute", errorOut,
            consumer);
        if (!detail.contains("error=") || !detail.contains("message=")) {
            throw new IllegalStateException("producer error was not decoded: " + detail);
        }
        System.out.println(detail);
        errorOut.setValue(null);
    }

    private static void addAddress(LibDwarfProducer producer, LibDwarfConsumer consumer,
            Debug debug, Die die, long address, long symbolIndex,
            PointerByReference errorOut) {
        PointerByReference attributeOut = new PointerByReference();
        checkCall(producer.dwarf_add_AT_targ_address_c(debug, die, DW_AT_LOW_PC, address,
            symbolIndex, attributeOut, errorOut), "dwarf_add_AT_targ_address_c", errorOut,
            consumer);
        requirePointer(attributeOut, "target-address attribute");
    }

    private static void addRegisterLocation(LibDwarfProducer producer,
            LibDwarfConsumer consumer, Debug debug, Die die, long dwarfRegister,
            PointerByReference errorOut) {
        PointerByReference expressionOut = new PointerByReference();
        checkCall(producer.dwarf_new_expr_a(debug, expressionOut, errorOut),
            "dwarf_new_expr_a", errorOut, consumer);
        Expr expression = new Expr(requirePointer(expressionOut, "location expression"));
        LongByReference nextOffset = new LongByReference();
        checkCall(producer.dwarf_add_expr_gen_a(expression, (byte) 0x90, dwarfRegister,
            0, nextOffset, errorOut), "dwarf_add_expr_gen_a", errorOut, consumer);
        if (nextOffset.getValue() <= 0) {
            throw new IllegalStateException("empty register location expression");
        }
        PointerByReference attributeOut = new PointerByReference();
        checkCall(producer.dwarf_add_AT_location_expr_a(debug, die, DW_AT_LOCATION,
            expression, attributeOut, errorOut), "dwarf_add_AT_location_expr_a", errorOut,
            consumer);
        requirePointer(attributeOut, "location attribute");
    }

    private static Map<Long, ByteArrayOutputStream> collectSectionData(
            LibDwarfProducer producer, LibDwarfConsumer consumer, Debug debug,
            PointerByReference errorOut, long bufferCount, Map<Long, SectionRecord> sections) {
        Map<Long, ByteArrayOutputStream> dataBySection = new HashMap<>();
        for (long buffer = 0; buffer < bufferCount; buffer++) {
            LongByReference sectionIndexOut = new LongByReference();
            LongByReference lengthOut = new LongByReference();
            PointerByReference bytesOut = new PointerByReference();
            checkCall(producer.dwarf_get_section_bytes_a(debug, buffer, sectionIndexOut,
                lengthOut, bytesOut, errorOut), "dwarf_get_section_bytes_a", errorOut,
                consumer);
            long sectionIndex = sectionIndexOut.getValue();
            long length = lengthOut.getValue();
            if (!sections.containsKey(sectionIndex)) {
                throw new IllegalStateException(
                    "buffer refers to unknown ELF section " + sectionIndex);
            }
            if (length < 0 || length > Integer.MAX_VALUE) {
                throw new IllegalStateException("unsupported section chunk length " + length);
            }
            Pointer bytes = requirePointer(bytesOut, "section data");
            ByteArrayOutputStream accumulated =
                dataBySection.computeIfAbsent(sectionIndex, ignored -> new ByteArrayOutputStream());
            try {
                accumulated.write(bytes.getByteArray(0, Math.toIntExact(length)));
            }
            catch (IOException impossible) {
                throw new AssertionError(impossible);
            }
        }
        return dataBySection;
    }

    private static void validateRelocations(LibDwarfProducer producer,
            LibDwarfConsumer consumer, Debug debug, PointerByReference errorOut,
            Map<Long, SectionRecord> sections,
            Map<Long, ByteArrayOutputStream> sectionData, int expectedAddressWidth) {
        LongByReference relocationSectionCountOut = new LongByReference();
        IntByReference versionOut = new IntByReference();
        checkCall(producer.dwarf_get_relocation_info_count(debug,
            relocationSectionCountOut, versionOut, errorOut),
            "dwarf_get_relocation_info_count", errorOut, consumer);
        long sectionCount = relocationSectionCountOut.getValue();
        if (sectionCount <= 0 || sectionCount > sections.size()) {
            throw new IllegalStateException("invalid relocation section count " + sectionCount);
        }
        if (versionOut.getValue() != DWARF_DRD_BUFFER_VERSION) {
            throw new IllegalStateException("unexpected relocation buffer version " +
                versionOut.getValue());
        }
        int recordSize = new RelocationData().size();
        if (recordSize != 24) {
            throw new IllegalStateException("unexpected relocation record size " + recordSize);
        }

        long totalRelocations = 0;
        long addressRelocations = 0;
        List<Long> sectionSymbolIndices =
            sections.values().stream().map(SectionRecord::symbolIndex).toList();
        for (long group = 0; group < sectionCount; group++) {
            LongByReference relocationSectionOut = new LongByReference();
            LongByReference targetSectionOut = new LongByReference();
            LongByReference relocationCountOut = new LongByReference();
            PointerByReference relocationDataOut = new PointerByReference();
            checkCall(producer.dwarf_get_relocation_info(debug, relocationSectionOut,
                targetSectionOut, relocationCountOut, relocationDataOut, errorOut),
                "dwarf_get_relocation_info", errorOut, consumer);
            long relocationSection = relocationSectionOut.getValue();
            long targetSection = targetSectionOut.getValue();
            long relocationCount = relocationCountOut.getValue();
            if (!sections.containsKey(relocationSection) || !sections.containsKey(targetSection)) {
                throw new IllegalStateException("relocations reference unknown sections: " +
                    relocationSection + " -> " + targetSection);
            }
            ByteArrayOutputStream targetData = sectionData.get(targetSection);
            if (targetData == null || relocationCount <= 0 || relocationCount > 100_000) {
                throw new IllegalStateException("invalid relocation target/count");
            }
            Pointer relocationBase = requirePointer(relocationDataOut, "relocation data");
            for (long index = 0; index < relocationCount; index++) {
                RelocationData relocation =
                    new RelocationData(relocationBase.share(Math.multiplyExact(index, recordSize)));
                int length = Byte.toUnsignedInt(relocation.length);
                if (length != 4 && length != 8) {
                    throw new IllegalStateException("invalid relocation width " + length);
                }
                if (relocation.offset < 0 ||
                        relocation.offset + length > targetData.size()) {
                    throw new IllegalStateException("relocation outside target section");
                }
                if (relocation.symbolIndex == TEXT_SYMBOL_INDEX) {
                    if (length != expectedAddressWidth) {
                        throw new IllegalStateException("target address relocation width " +
                            length + " does not match address size " + expectedAddressWidth);
                    }
                    addressRelocations++;
                }
                else if (!sectionSymbolIndices.contains(relocation.symbolIndex)) {
                    throw new IllegalStateException("unexpected relocation symbol " +
                        relocation.symbolIndex);
                }
                totalRelocations++;
            }
        }
        if (addressRelocations < 2) {
            throw new IllegalStateException(
                "expected relocations for CU and function addresses, found " +
                    addressRelocations);
        }
        System.out.printf(
            "relocation-groups=%d relocations=%d address-relocations=%d record-size=%d%n",
            sectionCount, totalRelocations, addressRelocations, recordSize);
    }

    private static void requireSectionWithData(String name, Map<Long, SectionRecord> sections,
            Map<Long, ByteArrayOutputStream> sectionData) {
        List<Long> matching = new ArrayList<>();
        sections.forEach((index, section) -> {
            if (name.equals(section.name())) {
                matching.add(index);
            }
        });
        if (matching.size() != 1 || !sectionData.containsKey(matching.get(0)) ||
                sectionData.get(matching.get(0)).size() == 0) {
            throw new IllegalStateException("missing or empty producer section " + name);
        }
    }

    private static void checkCall(int result, String operation, PointerByReference errorOut,
            LibDwarfConsumer consumer) {
        check(result, operation, errorOut, consumer);
        errorOut.setValue(null);
    }

    private static void check(int result, String operation, PointerByReference errorOut,
            LibDwarfConsumer consumer) {
        if (result != DW_DLV_OK) {
            throw new IllegalStateException(describeError(operation, errorOut, consumer) +
                " status=" + result);
        }
    }

    private static String describeError(String operation, PointerByReference errorOut,
            LibDwarfConsumer consumer) {
        Pointer pointer = errorOut.getValue();
        if (pointer == null) {
            return operation + " failed without Dwarf_Error";
        }
        Error error = new Error(pointer);
        long number = consumer.dwarf_errno(error);
        return operation + " failed: error=" + number + " message=" +
            consumer.dwarf_errmsg_by_number(number);
    }

    private static Pointer requirePointer(PointerByReference reference, String description) {
        Pointer pointer = reference.getValue();
        if (pointer == null) {
            throw new IllegalStateException(description + " was null");
        }
        return pointer;
    }

    private static Path requireNative(String value) {
        Path path = requireFile(value);
        return path;
    }

    private static Path requireFile(String value) {
        Path path = Path.of(value).toAbsolutePath().normalize();
        if (!Files.isRegularFile(path)) {
            throw new IllegalArgumentException("file does not exist: " + path);
        }
        return path;
    }

    private static long parseAddress(String value) {
        try {
            return Long.decode(value);
        }
        catch (NumberFormatException invalid) {
            throw new IllegalArgumentException("invalid function address " + value, invalid);
        }
    }

    private static String sha256(Path path) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (var input = Files.newInputStream(path)) {
            byte[] buffer = new byte[64 * 1024];
            for (int count; (count = input.read(buffer)) != -1;) {
                digest.update(buffer, 0, count);
            }
        }
        return java.util.HexFormat.of().formatHex(digest.digest());
    }
}
