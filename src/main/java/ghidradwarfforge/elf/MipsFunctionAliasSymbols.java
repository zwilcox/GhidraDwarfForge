package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** Direct-address aliases for the explicitly observed classic MIPS32r2 O32 profile. */
public final class MipsFunctionAliasSymbols {
    private MipsFunctionAliasSymbols() {
    }

    public static List<ElfLocalFunctionSymbol> plan(ElfImage image, List<ElfFunctionAlias> aliases,
            List<FunctionSymbol> functions, List<ElfLocalFunctionSymbol> reserved,
            BooleanSupplier cancelled, Consumer<String> diagnostic) throws IOException {
        checkCancelled(cancelled);
        String restriction = restriction(image, cancelled);
        if (restriction != null) {
            diagnostic.accept("Omitted function aliases: MIPS symbol-value policy: " + restriction);
            return List.of();
        }
        var aligned = new java.util.ArrayList<ElfFunctionAlias>();
        for (ElfFunctionAlias alias : aliases) {
            checkCancelled(cancelled);
            boolean alignedRanges = true;
            for (var range : alias.ranges()) {
                checkCancelled(cancelled);
                alignedRanges &= (range.address() & 3) == 0 && (range.size() & 3) == 0;
            }
            if ((alias.address() & 3) != 0 || !alignedRanges) {
                diagnostic.accept("Omitted function alias " + alias.name() +
                    ": classic MIPS body is not word aligned");
            }
            else {
                aligned.add(alias);
            }
        }
        return FunctionAliasSymbols.plan(image, aligned, functions, reserved, cancelled, diagnostic);
    }

    private static String restriction(ElfImage image, BooleanSupplier cancelled) throws IOException {
        // Admit NOREORDER/PIC/CPIC only in the observed O32 MIPS32r2 envelope.
        // MIPS16/microMIPS header flags and other ABI/ISA profiles stay excluded.
        if (image.machine() != 8 || image.is64Bit() || (image.type() != 2 && image.type() != 3) ||
                (image.flags() & ~7L) != 0x70001000L) {
            return "requires the observed O32 MIPS32r2 ELF header profile";
        }
        var observation = MipsAbiFlags.observe(image, cancelled);
        if (observation.status() != MipsAbiFlags.Status.AVAILABLE) {
            return "requires an unambiguous typed ABI record: " + observation.detail();
        }
        var fields = observation.fields().orElseThrow();
        if (fields.isaLevel() != 32 || fields.isaRevision() != 2 || fields.gprSize() != 1 ||
                fields.cpr1Size() != 1 || fields.cpr2Size() != 0 ||
                (fields.fpAbi() != 1 && fields.fpAbi() != 5) || fields.isaExtension() != 0 ||
                fields.ases() != 0 || (fields.flags1() & ~1L) != 0 || fields.flags2() != 0) {
            return "ABI record is outside the classic O32 FP32/FPXX profile";
        }
        // Even inconsistent inputs must not lose a symbol's ISA/mode bits.
        // Only ordinary visibility bits are permitted on defined code symbols;
        // no processor-specific st_other value is copied into a new local alias.
        if (image.sections().isEmpty()) {
            try {
                var inventory = DynamicSymbolMirror.read(image, cancelled);
                if (inventory != null) {
                    ByteBuffer symbols = ByteBuffer.wrap(inventory.records()).order(image.byteOrder());
                    for (int offset = 0; offset < symbols.limit(); offset += 16) {
                        checkCancelled(cancelled);
                        int type = Byte.toUnsignedInt(symbols.get(offset + 12)) & 15;
                        if ((type == 2 || type == 10) && symbols.getShort(offset + 14) != 0 &&
                                ((Byte.toUnsignedInt(symbols.get(offset + 13)) & ~3) != 0 ||
                                (symbols.getInt(offset + 4) & 3) != 0)) {
                            return "defined PT_DYNAMIC code symbol has an unverified mode or tagged address";
                        }
                    }
                }
            }
            catch (IllegalArgumentException unsupported) {
                return unsupported.getMessage();
            }
        }
        long rows = 0;
        for (var section : image.sections()) {
            checkCancelled(cancelled);
            if (section.type != 2 && section.type != 11) {
                continue;
            }
            if (section.entrySize != 16 || section.size < 16 || section.size % 16 != 0 ||
                    (rows += section.size / 16) > 262144) {
                return "unsupported or oversized symbol inventory";
            }
            ByteBuffer symbols = ByteBuffer.wrap(image.sectionData(section)).order(image.byteOrder());
            for (int offset = 0; offset < symbols.limit(); offset += 16) {
                checkCancelled(cancelled);
                int type = Byte.toUnsignedInt(symbols.get(offset + 12)) & 15;
                if ((type == 2 || type == 10) && symbols.getShort(offset + 14) != 0 &&
                        ((Byte.toUnsignedInt(symbols.get(offset + 13)) & ~3) != 0 ||
                        (symbols.getInt(offset + 4) & 3) != 0)) {
                    return "defined code symbol has an unverified mode or tagged address";
                }
            }
        }
        return null;
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) {
            throw new CancellationException("MIPS alias planning cancelled");
        }
    }
}
