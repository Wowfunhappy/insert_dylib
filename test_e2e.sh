#!/bin/bash
# End-to-end test: build a test program and dylib, insert the dylib,
# then confirm the program actually runs and loads code from the dylib.
# Also verifies that image-base fixups (export trie, __program_vars.mh,
# nlist) are correct after header expansion.
set -e

TESTDIR=$(mktemp -d -t insert_dylib_e2e)
cleanup() { rm -rf "$TESTDIR"; }
trap cleanup EXIT

TOOL="./insert_dylib_new"
if [ ! -f "$TOOL" ]; then
    echo "Building insert_dylib..."
    cc -o "$TOOL" insert_dylib/main.c -O2 -Wall
fi

echo "=== Building test dylib ==="
cat > "$TESTDIR/testlib.c" << 'DYLIB_SRC'
#include <stdio.h>

__attribute__((constructor))
void dylib_init(void) {
    printf("DYLIB_LOADED_OK\n");
}
DYLIB_SRC
cc -dynamiclib -o "$TESTDIR/testlib.dylib" "$TESTDIR/testlib.c"

echo "=== Building test program ==="
cat > "$TESTDIR/testprog.c" << 'PROG_SRC'
#include <stdio.h>
#include <crt_externs.h>
#include <mach-o/loader.h>

extern struct mach_header _mh_execute_header;

int main(void) {
    // Test 1: direct RIP-relative reference to _mh_execute_header
    // This broke before the header shadow fix.
    if (_mh_execute_header.magic == MH_MAGIC_64 || _mh_execute_header.magic == MH_MAGIC) {
        printf("DIRECT_MH_VALID\n");
    } else {
        printf("DIRECT_MH_INVALID magic=0x%x\n", _mh_execute_header.magic);
    }

    // Test 2: _NSGetMachExecuteHeader (uses __program_vars.mh)
    // This broke before the __program_vars.mh fixup.
    const struct mach_header *mh = _NSGetMachExecuteHeader();
    if (mh && (mh->magic == MH_MAGIC_64 || mh->magic == MH_MAGIC)) {
        printf("INDIRECT_MH_VALID\n");
    } else {
        printf("INDIRECT_MH_INVALID magic=0x%x\n", mh ? mh->magic : 0);
    }

    printf("MAIN_RUNNING\n");
    return 0;
}
PROG_SRC
cc -o "$TESTDIR/testprog" "$TESTDIR/testprog.c" -Wl,-headerpad,0x0

echo ""
echo "=== Test A: Basic insertion (no expansion) ==="
cp "$TESTDIR/testprog" "$TESTDIR/testprog_basic"
DYLIB_REAL="$TESTDIR/testlib.dylib"
OUTPUT=$($TOOL --all-yes --inplace "$DYLIB_REAL" "$TESTDIR/testprog_basic" 2>&1)
echo "$OUTPUT"

echo ""
echo "=== Test B: Insertion after exhausting header space (forces expansion) ==="
cp "$TESTDIR/testprog" "$TESTDIR/testprog_patched"

# Consume all free header space with dummy weak dylibs until expansion triggers
EXPANSION_TRIGGERED=no
for i in $(seq 1 50); do
    PAD_OUT=$($TOOL --all-yes --inplace --weak \
        "/fake/padding/lib_number_${i}_aaaaaaaaaaaaaaaaaaa.dylib" \
        "$TESTDIR/testprog_patched" 2>&1) || true
    if echo "$PAD_OUT" | grep -q "WARNING"; then
        echo "  Expansion triggered on padding insertion #$i"
        EXPANSION_TRIGGERED=yes
    fi
done

echo "After padding: $(otool -l "$TESTDIR/testprog_patched" | grep -c '^Load command') load commands"
echo "Expansion was triggered during padding: $EXPANSION_TRIGGERED"

# Now insert the REAL dylib
OUTPUT=$($TOOL --all-yes --inplace "$DYLIB_REAL" "$TESTDIR/testprog_patched" 2>&1)
echo "$OUTPUT"
if echo "$OUTPUT" | grep -q "WARNING"; then
    EXPANSION_TRIGGERED=yes
fi

if [ "$EXPANSION_TRIGGERED" = "no" ]; then
    echo "  ERROR: Expansion was never triggered!"
fi

echo ""
echo "=== Running programs ==="
ORIG_OUTPUT=$("$TESTDIR/testprog" 2>&1)
echo "Original:           $ORIG_OUTPUT"
BASIC_OUTPUT=$("$TESTDIR/testprog_basic" 2>&1)
echo "Basic patched:      $BASIC_OUTPUT"
EXPANDED_OUTPUT=$("$TESTDIR/testprog_patched" 2>&1)
echo "Expansion patched:  $EXPANDED_OUTPUT"

echo ""
echo "=== Verifying results ==="
PASS=0
FAIL=0

check() {
    local desc="$1" output="$2" pattern="$3" expect="$4"
    if echo "$output" | grep -q "$pattern"; then
        found=yes
    else
        found=no
    fi
    if [ "$found" = "$expect" ]; then
        PASS=$((PASS + 1))
        echo "  PASS: $desc"
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL: $desc"
    fi
}

check "Original runs"                                 "$ORIG_OUTPUT"     "MAIN_RUNNING"       yes
check "Original has no dylib"                         "$ORIG_OUTPUT"     "DYLIB_LOADED"       no
check "Original direct mh valid"                      "$ORIG_OUTPUT"     "DIRECT_MH_VALID"    yes
check "Original indirect mh valid"                    "$ORIG_OUTPUT"     "INDIRECT_MH_VALID"  yes
check "Basic patch runs"                              "$BASIC_OUTPUT"    "MAIN_RUNNING"       yes
check "Basic patch loads dylib"                       "$BASIC_OUTPUT"    "DYLIB_LOADED"       yes
check "Expanded patch runs"                           "$EXPANDED_OUTPUT" "MAIN_RUNNING"       yes
check "Expanded patch loads dylib"                    "$EXPANDED_OUTPUT" "DYLIB_LOADED"       yes
check "Expanded direct _mh_execute_header valid"      "$EXPANDED_OUTPUT" "DIRECT_MH_VALID"    yes
check "Expanded indirect _NSGetMachExecuteHeader valid" "$EXPANDED_OUTPUT" "INDIRECT_MH_VALID"  yes
check "Expanded no invalid headers"                   "$EXPANDED_OUTPUT" "MH_INVALID"         no

TOTAL=$((PASS + FAIL))
echo ""
echo "================================"
echo "Results: $PASS/$TOTAL passed, $FAIL failed"
echo "================================"

[ $FAIL -eq 0 ] && exit 0 || exit 1
