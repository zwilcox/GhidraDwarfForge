package ghidradwarfforge.nativeapi;

import com.sun.jna.Pointer;
import com.sun.jna.PointerType;

/** Opaque native handles declared by the pinned libdwarf 2.3.2 headers. */
public final class DwarfNativeTypes {
    private DwarfNativeTypes() {
    }

    public static final class Debug extends PointerType {
        public Debug() {
        }

        public Debug(Pointer pointer) {
            super(pointer);
        }
    }

    public static final class Die extends PointerType {
        public Die() {
        }

        public Die(Pointer pointer) {
            super(pointer);
        }
    }

    public static final class Error extends PointerType {
        public Error() {
        }

        public Error(Pointer pointer) {
            super(pointer);
        }
    }

    public static final class Expr extends PointerType {
        public Expr() {
        }

        public Expr(Pointer pointer) {
            super(pointer);
        }
    }
}
