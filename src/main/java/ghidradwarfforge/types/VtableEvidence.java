package ghidradwarfforge.types;

import ghidradwarfforge.targets.CxxAbiProfile;

/** A current saved-program witness; original ELF and consumer-name admission remain separate. */
public record VtableEvidence(long symbolId, long classId, CxxAbiProfile abi, String mangledName,
        String lookupName, long address, int byteSize, long fileOffset, String originalSha256,
        String provenance) {
    public VtableEvidence {
        if (symbolId <= 0 || classId <= 0 || abi == null || abi == CxxAbiProfile.UNSPECIFIED ||
                address < 0 || byteSize <= 0 || byteSize > 1024 * 1024 || fileOffset < 0 ||
                mangledName == null || !mangledName.startsWith("_ZTV") || mangledName.length() > 8192 ||
                lookupName == null || lookupName.isBlank() || lookupName.length() > 8192 ||
                originalSha256 == null || !originalSha256.matches("[0-9a-f]{64}") ||
                provenance == null || provenance.isBlank() || provenance.length() > 8192 ||
                mangledName.indexOf('\0') >= 0 || lookupName.indexOf('\0') >= 0) {
            throw new IllegalArgumentException("invalid saved vtable evidence");
        }
        Math.addExact(address, byteSize);
        Math.addExact(fileOffset, byteSize);
    }
}
