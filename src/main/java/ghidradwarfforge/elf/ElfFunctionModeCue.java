package ghidradwarfforge.elf;

import java.util.Locale;

/** Recovered code evidence; encoded symbol values are supplied by an isolated target extractor. */
public record ElfFunctionModeCue(String displayName, long address, long size,
        long symbolValue, String codeSha256) {
    public ElfFunctionModeCue {
        if (displayName == null || displayName.isBlank() || displayName.length() > 65536 ||
                address < 0 || size <= 0 || size > Long.MAX_VALUE - address ||
                symbolValue < 0 || codeSha256 == null ||
                !codeSha256.matches("[0-9a-fA-F]{64}")) {
            throw new IllegalArgumentException("invalid ELF function-mode evidence");
        }
        codeSha256 = codeSha256.toLowerCase(Locale.ROOT);
    }
}
