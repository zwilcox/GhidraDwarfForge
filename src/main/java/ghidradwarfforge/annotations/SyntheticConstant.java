package ghidradwarfforge.annotations;

/** A synthetic lookup value, never an addressable recovered program variable. */
public record SyntheticConstant(String name, int bits, boolean signed, long value) {
    public SyntheticConstant {
        if (name == null || !name.matches("[A-Za-z][A-Za-z0-9_]*")) {
            throw new IllegalArgumentException("invalid synthetic constant name");
        }
        if (bits < 1 || bits > 64) throw new IllegalArgumentException("invalid constant width");
        if (bits < 64) {
            boolean fits = signed ? value >= -(1L << (bits - 1)) && value < (1L << (bits - 1))
                : value >= 0 && value <= (-1L >>> (64 - bits));
            if (!fits) throw new IllegalArgumentException("constant does not fit its evidence width");
        }
    }
}
