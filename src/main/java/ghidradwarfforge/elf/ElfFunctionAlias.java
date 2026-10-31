package ghidradwarfforge.elf;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

/** An explicit analyst label and its selected primary definition's original-code evidence. */
public record ElfFunctionAlias(String name, String owner, long address, long size,
        String codeSha256) {
    public ElfFunctionAlias {
        if (name == null || name.isBlank() || name.indexOf('\0') >= 0 ||
                name.length() > 65536 || !StandardCharsets.UTF_8.newEncoder().canEncode(name) ||
                name.getBytes(StandardCharsets.UTF_8).length > 65536 ||
                owner == null || owner.isBlank() || name.equals(owner) ||
                address < 0 || size <= 0 || size > Long.MAX_VALUE - address ||
                codeSha256 == null || !codeSha256.matches("[0-9a-fA-F]{64}")) {
            throw new IllegalArgumentException("invalid recovered function alias");
        }
        codeSha256 = codeSha256.toLowerCase(Locale.ROOT);
    }
}
