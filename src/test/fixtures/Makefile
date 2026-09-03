SHELL := /bin/bash

BUILD_DIR ?= ../../../build/fixtures
SOURCE := semantic.c
SOURCE_DATE_EPOCH ?= 1750550400
export SOURCE_DATE_EPOCH

COMMON_CFLAGS := -O0 -g3 -gdwarf-5 -fno-omit-frame-pointer \
	-ffile-prefix-map=$(CURDIR)=/ghidra-dwarf-forge-fixture \
	-fdebug-prefix-map=$(CURDIR)=/ghidra-dwarf-forge-fixture
NON_PIE_FLAGS := -fno-pie -no-pie -Wl,--build-id=sha1
NO_BUILD_ID_FLAGS := -fno-pie -no-pie -Wl,--build-id=none
PIE_FLAGS := -fPIE -pie -Wl,--build-id=sha1
SHARED_FLAGS := -fPIC -shared -Wl,--build-id=sha1,-soname,libsemantic.so.stripped
SHARED_DRIVER_FLAGS := -fno-pie -no-pie -Wl,--build-id=sha1 \
	-Wl,-rpath,'$$ORIGIN'

TARGETS := x86_64 aarch64 mips32be mips32le
x86_64_CC := gcc
x86_64_STRIP := strip
x86_64_OBJCOPY := objcopy
aarch64_CC := aarch64-linux-gnu-gcc
aarch64_STRIP := aarch64-linux-gnu-strip
aarch64_OBJCOPY := aarch64-linux-gnu-objcopy
mips32be_CC := mips-linux-gnu-gcc
mips32be_STRIP := mips-linux-gnu-strip
mips32be_OBJCOPY := mips-linux-gnu-objcopy
mips32le_CC := mipsel-linux-gnu-gcc
mips32le_STRIP := mipsel-linux-gnu-strip
mips32le_OBJCOPY := mipsel-linux-gnu-objcopy

.PHONY: all $(TARGETS)

all: $(TARGETS)

$(TARGETS): %: \
	$(BUILD_DIR)/%/semantic.exec.reference \
	$(BUILD_DIR)/%/semantic.exec.stripped \
	$(BUILD_DIR)/%/semantic.exec.no-build-id.reference \
	$(BUILD_DIR)/%/semantic.exec.no-build-id.stripped \
	$(BUILD_DIR)/%/semantic.exec.no-sections.stripped \
	$(BUILD_DIR)/%/semantic.pie.reference \
	$(BUILD_DIR)/%/semantic.pie.stripped \
	$(BUILD_DIR)/%/libsemantic.so.reference \
	$(BUILD_DIR)/%/libsemantic.so.stripped \
	$(BUILD_DIR)/%/semantic.shared-driver.reference \
	$(BUILD_DIR)/%/semantic.shared-driver.stripped

$(BUILD_DIR)/%/semantic.exec.reference: $(SOURCE) Makefile
	@mkdir -p "$(@D)"
	$($*_CC) $(COMMON_CFLAGS) $(NON_PIE_FLAGS) "$<" -o "$@"

$(BUILD_DIR)/%/semantic.exec.stripped: $(BUILD_DIR)/%/semantic.exec.reference
	cp "$<" "$@"
	$($*_STRIP) --strip-all "$@"

$(BUILD_DIR)/%/semantic.exec.no-build-id.reference: $(SOURCE) Makefile
	@mkdir -p "$(@D)"
	$($*_CC) $(COMMON_CFLAGS) $(NO_BUILD_ID_FLAGS) "$<" -o "$@"

$(BUILD_DIR)/%/semantic.exec.no-build-id.stripped: \
		$(BUILD_DIR)/%/semantic.exec.no-build-id.reference
	cp "$<" "$@"
	$($*_STRIP) --strip-all "$@"

$(BUILD_DIR)/%/semantic.exec.no-sections.stripped: $(BUILD_DIR)/%/semantic.exec.stripped
	$($*_OBJCOPY) --strip-section-headers "$<" "$@"

$(BUILD_DIR)/%/semantic.pie.reference: $(SOURCE) Makefile
	@mkdir -p "$(@D)"
	$($*_CC) $(COMMON_CFLAGS) $(PIE_FLAGS) "$<" -o "$@"

$(BUILD_DIR)/%/semantic.pie.stripped: $(BUILD_DIR)/%/semantic.pie.reference
	cp "$<" "$@"
	$($*_STRIP) --strip-all "$@"

$(BUILD_DIR)/%/libsemantic.so.reference: $(SOURCE) Makefile
	@mkdir -p "$(@D)"
	$($*_CC) $(COMMON_CFLAGS) $(SHARED_FLAGS) "$<" -o "$@"

$(BUILD_DIR)/%/libsemantic.so.stripped: $(BUILD_DIR)/%/libsemantic.so.reference
	cp "$<" "$@"
	$($*_STRIP) --strip-all "$@"

$(BUILD_DIR)/%/semantic.shared-driver.reference: shared_driver.c \
		$(BUILD_DIR)/%/libsemantic.so.stripped Makefile
	$($*_CC) $(COMMON_CFLAGS) $(SHARED_DRIVER_FLAGS) "$<" \
		-L"$(@D)" -Wl,-l:libsemantic.so.stripped -o "$@"

$(BUILD_DIR)/%/semantic.shared-driver.stripped: \
		$(BUILD_DIR)/%/semantic.shared-driver.reference
	cp "$<" "$@"
	$($*_STRIP) --strip-all "$@"
