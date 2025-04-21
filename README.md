# GhidraDwarfForge

hammering debug sections straight into your ELF.

to build add:
export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.3_PUBLIC

./gradlew :DwarfForge:buildExtension && cp DwarfForge/build/dist/DwarfForge.zip $GHIDRA_INSTALL_DIR/Ghidra/Extensions/