package ghidradwarfforge.nativeapi;

import static ghidradwarfforge.nativeapi.DwarfConstants.*;

import java.io.ByteArrayOutputStream;
import java.lang.ref.Reference;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.LongByReference;
import com.sun.jna.ptr.PointerByReference;

import ghidradwarfforge.nativeapi.DwarfNativeTypes.Debug;
import ghidradwarfforge.nativeapi.DwarfNativeTypes.Die;
import ghidradwarfforge.calls.CallValue;

/** Isolated ABI/serialization test; these synthetic calls are not runtime evidence. */
public final class CallSiteProducerSmoke {
    private record Profile(String isa, int width, boolean littleEndian) {
        static Profile parse(String name) {
            return switch (name) {
                case "x86_64" -> new Profile("x86_64", 8, true);
                case "aarch64", "arm64" -> new Profile("arm64", 8, true);
                case "arm32" -> new Profile("arm", 4, true);
                case "mips32be" -> new Profile("mips", 4, false);
                case "mips32le" -> new Profile("mips", 4, true);
                default -> throw new IllegalArgumentException("unknown probe profile: " + name);
            };
        }

        long flags() {
            return DW_DLC_OFFSET32 | DW_DLC_SYMBOLIC_RELOCATIONS |
                (width == 8 ? DW_DLC_POINTER64 : DW_DLC_POINTER32) |
                (littleEndian ? DW_DLC_TARGET_LITTLEENDIAN : DW_DLC_TARGET_BIGENDIAN);
        }

        long address() {
            return width == 8 ? 0x1_0000_1000L : 0x0040_1000L;
        }
    }

    private CallSiteProducerSmoke() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            throw new IllegalArgumentException("expected consumer, producer, profile, empty output directory");
        }
        LibDwarfConsumer consumer = Native.load(Path.of(args[0]).toRealPath().toString(), LibDwarfConsumer.class);
        LibDwarfProducer producer = Native.load(Path.of(args[1]).toRealPath().toString(), LibDwarfProducer.class);
        if (!"2.3.2".equals(consumer.dwarf_package_version())) {
            throw new IllegalStateException("unexpected native version");
        }
        Profile profile = Profile.parse(args[2]);
        Path output = Path.of(args[3]);
        Files.createDirectories(output);
        try (var files = Files.list(output)) {
            if (files.findAny().isPresent()) throw new IllegalArgumentException("output must be empty");
        }
        Map<String, byte[]> baseline = null;
        for (int iteration = 0; iteration < 8; iteration++) {
            // Exercise native error handling and cleanup before every successful lifetime.
            try (Session session = new Session(producer, consumer, profile)) {
                session.checkRejectedNullOwner();
            }
            Map<String, byte[]> sections;
            try (Session session = new Session(producer, consumer, profile)) {
                sections = session.produce(profile);
            }
            if (baseline == null) baseline = sections;
            else if (!baseline.keySet().equals(sections.keySet()) ||
                    baseline.entrySet().stream().anyMatch(entry ->
                        !Arrays.equals(entry.getValue(), sections.get(entry.getKey())))) {
                throw new IllegalStateException("producer bytes changed across lifetimes");
            }
        }
        for (var entry : baseline.entrySet()) {
            Files.write(output.resolve(entry.getKey()), entry.getValue(), StandardOpenOption.CREATE_NEW);
        }
        System.out.println("call-site-jna=PASS profile=" + args[2] +
            " successful-lifetimes=8 error-lifetimes=8 input-buffer-mutated=true deterministic=true");
    }

    private static final class Session implements AutoCloseable {
        private final LibDwarfProducer producer;
        private final LibDwarfConsumer consumer;
        private final Debug debug;
        private final Map<Long, String> sectionNames = new LinkedHashMap<>();
        private final LibDwarfProducer.SectionCallback callback;

        Session(LibDwarfProducer producer, LibDwarfConsumer consumer, Profile profile) {
            this.producer = producer;
            this.consumer = consumer;
            callback = (name, size, type, flags, link, info, symbol, user, error) -> {
                int index = sectionNames.size() + 1;
                sectionNames.put((long) index, name);
                symbol.setValue(100L + index);
                return index;
            };
            PointerByReference result = new PointerByReference();
            PointerByReference error = new PointerByReference();
            check(producer.dwarf_producer_init(profile.flags(), callback, null, null,
                null, profile.isa(), "V5", "", result, error), error);
            debug = new Debug(pointer(result));
        }

        void checkRejectedNullOwner() {
            PointerByReference error = new PointerByReference();
            int result = producer.dwarf_add_AT_block_a(debug, null, DW_AT_CALL_VALUE,
                new byte[] {0x35}, 1L, new PointerByReference(), error);
            if (result != DW_DLV_ERROR || error.getValue() == null ||
                    consumer.dwarf_errno(new DwarfNativeTypes.Error(error.getValue())) == 0) {
                throw new IllegalStateException("null-owner block did not report a native error");
            }
        }

        Map<String, byte[]> produce(Profile profile) {
            Die unit = die(DW_TAG_COMPILE_UNIT, null);
            name(unit, "call-site-jna.c");
            Die caller = die(DW_TAG_SUBPROGRAM, unit);
            name(caller, "synthetic_caller");
            address(caller, DW_AT_LOW_PC, profile.address());
            PointerByReference error = new PointerByReference();
            check(producer.dwarf_add_AT_flag_a(debug, caller, DW_AT_CALL_ALL_CALLS,
                (byte) 1, new PointerByReference(), error), error);
            Die callee = die(DW_TAG_SUBPROGRAM, unit);
            name(callee, "synthetic_callee");
            address(callee, DW_AT_LOW_PC, profile.address() + 0x100);
            Die formal = die(DW_TAG_FORMAL_PARAMETER, callee);
            name(formal, "synthetic_parameter");
            Die site = die(DW_TAG_CALL_SITE, caller);
            address(site, DW_AT_CALL_PC, profile.address() + 4);
            address(site, DW_AT_CALL_RETURN_PC, profile.address() + 8);
            reference(site, DW_AT_CALL_ORIGIN, callee);
            Die parameter = die(DW_TAG_CALL_SITE_PARAMETER, site);
            reference(parameter, DW_AT_CALL_PARAMETER, formal);
            block(parameter, DW_AT_LOCATION, new byte[] {0x50});
            byte[] value = {(byte) 0xa3, 1, 0x50};
            block(parameter, DW_AT_CALL_VALUE, value);
            // libdwarf must own a copy after return, not a borrowed Java buffer.
            Arrays.fill(value, (byte) 0);
            Die generated = die(DW_TAG_CALL_SITE_PARAMETER, site);
            block(generated, DW_AT_LOCATION, new byte[] {0x51});
            var first = new CallValue.Incoming(5, profile.width());
            var second = new CallValue.Incoming(6, profile.width());
            var condition = CallValue.binary(CallValue.Op.EQUAL, second, new CallValue.Literal(0, profile.width()), 1);
            var signedByte = CallValue.extend(CallValue.slice(first, 0, 1), true, profile.width());
            var computed = CallValue.select(condition,
                CallValue.binary(CallValue.Op.ADD, signedByte, new CallValue.Literal(1, profile.width()), profile.width()),
                CallValue.binary(CallValue.Op.ADD, first, second, profile.width()));
            byte[] generatedValue = computed.dwarf(profile.width(), profile.littleEndian() ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
            block(generated, DW_AT_CALL_VALUE, generatedValue);
            Arrays.fill(generatedValue, (byte) 0);
            check(producer.dwarf_add_die_to_debug_a(debug, unit, error), error);
            LongByReference count = new LongByReference();
            check(producer.dwarf_transform_to_disk_form_a(debug, count, error), error);
            if (count.getValue() <= 0 || count.getValue() > 1024) {
                throw new IllegalStateException("invalid native section count");
            }
            Map<String, ByteArrayOutputStream> buffers = new LinkedHashMap<>();
            for (long index = 0; index < count.getValue(); index++) {
                LongByReference section = new LongByReference();
                LongByReference length = new LongByReference();
                PointerByReference data = new PointerByReference();
                check(producer.dwarf_get_section_bytes_a(debug, index, section, length, data, error), error);
                String name = sectionNames.get(section.getValue());
                if (name == null || length.getValue() <= 0 || length.getValue() > 1024 * 1024) {
                    throw new IllegalStateException("invalid native section buffer");
                }
                if (name.startsWith(".debug_") && !name.contains("/") && !name.contains("\\")) {
                    buffers.computeIfAbsent(name, ignored -> new ByteArrayOutputStream()).writeBytes(
                        pointer(data).getByteArray(0, Math.toIntExact(length.getValue())));
                }
            }
            Map<String, byte[]> result = new LinkedHashMap<>();
            buffers.forEach((name, data) -> result.put(name, data.toByteArray()));
            if (!result.containsKey(".debug_info") || !result.containsKey(".debug_abbrev")) {
                throw new IllegalStateException("missing core DWARF sections");
            }
            return result;
        }

        private Die die(long tag, Die parent) {
            PointerByReference result = new PointerByReference();
            PointerByReference error = new PointerByReference();
            check(producer.dwarf_new_die_a(debug, tag, parent, null, null, null, result, error), error);
            return new Die(pointer(result));
        }

        private void name(Die die, String name) {
            PointerByReference error = new PointerByReference();
            check(producer.dwarf_add_AT_name_a(die, name, new PointerByReference(), error), error);
        }

        private void address(Die die, short attribute, long value) {
            PointerByReference error = new PointerByReference();
            check(producer.dwarf_add_AT_targ_address_c(debug, die, attribute, value, 1,
                new PointerByReference(), error), error);
        }

        private void reference(Die die, short attribute, Die target) {
            PointerByReference error = new PointerByReference();
            check(producer.dwarf_add_AT_reference_c(debug, die, attribute, target,
                new PointerByReference(), error), error);
        }

        private void block(Die die, short attribute, byte[] bytes) {
            PointerByReference error = new PointerByReference();
            check(producer.dwarf_add_AT_block_a(debug, die, attribute, bytes, (long) bytes.length,
                new PointerByReference(), error), error);
        }

        private void check(int result, PointerByReference error) {
            if (result != DW_DLV_OK || error.getValue() != null) {
                String message = error.getValue() == null ? "no error object" :
                    consumer.dwarf_errmsg_by_number(consumer.dwarf_errno(
                        new DwarfNativeTypes.Error(error.getValue())));
                throw new IllegalStateException("native call failed: " + result + ": " + message);
            }
        }

        @Override
        public void close() {
            try {
                PointerByReference error = new PointerByReference();
                int result = producer.dwarf_producer_finish_a(debug, error);
                if (result != DW_DLV_OK || error.getValue() != null) {
                    throw new IllegalStateException("native finish failed: " + result);
                }
            }
            finally {
                Reference.reachabilityFence(callback);
            }
        }
    }

    private static Pointer pointer(PointerByReference reference) {
        if (reference.getValue() == null) throw new IllegalStateException("null native output");
        return reference.getValue();
    }
}
