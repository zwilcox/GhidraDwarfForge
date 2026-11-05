package ghidradwarfforge.coverage;

/** Canonical type populations, not DIE counts or a probability of correctness. */
public record TypeCoverage(long recoveredRoots, long emittedRoots,
        long opaqueFreeEmittedRoots, long recoveredNodes, long resolvedEmittedNodes,
        long opaqueEmittedNodes, long notEmittedNodes, long implicitVoidNodes,
        long emittedImplicitVoidNodes) {
    public TypeCoverage {
        if (recoveredRoots < 0 || emittedRoots < 0 || opaqueFreeEmittedRoots < 0 ||
                recoveredNodes < 0 || resolvedEmittedNodes < 0 || opaqueEmittedNodes < 0 ||
                notEmittedNodes < 0 || implicitVoidNodes < 0 || emittedImplicitVoidNodes < 0 ||
                emittedRoots > recoveredRoots || opaqueFreeEmittedRoots > emittedRoots ||
                emittedImplicitVoidNodes > implicitVoidNodes ||
                resolvedEmittedNodes > recoveredNodes ||
                opaqueEmittedNodes > recoveredNodes - resolvedEmittedNodes ||
                notEmittedNodes != recoveredNodes - resolvedEmittedNodes - opaqueEmittedNodes) {
            throw new IllegalArgumentException("inconsistent type coverage populations");
        }
    }

    public long emittedNodes() {
        return resolvedEmittedNodes + opaqueEmittedNodes;
    }

    /** Void-only and empty populations have no DIE-required node denominator. */
    public boolean applicable() {
        return recoveredNodes != 0;
    }
}
