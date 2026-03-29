#!/bin/bash
# Tests for fixes 5-9:
#   5: Large export trie (>4096 nodes)
#   6: Missing LC handlers (LC_DYLIB_CODE_SIGN_DRS etc)
#   7: Shadow header ncmds/sizeofcmds zeroed
#   8: Fall-through bug in check_load_commands
#   9: False positive pointer scan eliminated
TOOL="./insert_dylib_new"
TESTDIR=$(mktemp -d -t test_fixes)
PASS=0
FAIL=0
TOTAL=0

cleanup() { rm -rf "$TESTDIR"; }
trap cleanup EXIT

check() {
    TOTAL=$((TOTAL + 1))
    local desc="$1" ok="$2"
    if [ "$ok" = "1" ]; then
        PASS=$((PASS + 1))
        echo "  PASS: $desc"
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL: $desc"
    fi
}

if [ ! -f "$TOOL" ]; then
    cc -o "$TOOL" insert_dylib/main.c -O2 -Wall
fi

# ==========================================================================
echo ""
echo "=== Fix 5: Large export trie (many exported symbols) ==="
# Build a binary that exports thousands of symbols (would overflow old 4096 limit)
echo '#include <stdio.h>' > "$TESTDIR/big_exports.c"
# Generate many exports via a single compilation unit with macros
python3 -c "
for i in range(1, 5001):
    print(f'int exported_func_{i}(void) {{ return {i}; }}')
" >> "$TESTDIR/big_exports.c"
echo 'int main(void) { printf("BIG_EXPORTS_OK\n"); return exported_func_1(); }' >> "$TESTDIR/big_exports.c"

# Build with minimal headerpad and export all symbols
cc -o "$TESTDIR/big_exports" "$TESTDIR/big_exports.c" \
    -Wl,-headerpad,0x0 -Wl,-export_dynamic 2>&1 || true

ORIG_EXPORTS=$(nm -gU "$TESTDIR/big_exports" 2>/dev/null | wc -l | tr -d ' ')
echo "Original has $ORIG_EXPORTS exported symbols"

# Exhaust header space then insert
cp "$TESTDIR/big_exports" "$TESTDIR/big_exports_patched"
for i in $(seq 1 60); do
    $TOOL --all-yes --inplace --weak \
        "/fake/pad_${i}_aaaaaaaaaaaaaaaaaaaaa.dylib" \
        "$TESTDIR/big_exports_patched" 2>&1 > /dev/null || true
done
$TOOL --all-yes --inplace /usr/lib/libz.dylib "$TESTDIR/big_exports_patched" 2>&1 > /dev/null

# Verify the patched binary runs
OUTPUT=$("$TESTDIR/big_exports_patched" 2>&1) || true
check "Binary with $ORIG_EXPORTS exports runs after expansion" "$(echo "$OUTPUT" | grep -c 'BIG_EXPORTS_OK')"

# Verify export count is preserved (original + our additions)
PATCHED_EXPORTS=$(nm -gU "$TESTDIR/big_exports_patched" 2>/dev/null | wc -l | tr -d ' ')
check "Export count preserved ($ORIG_EXPORTS original)" "$([ "$PATCHED_EXPORTS" -ge "$ORIG_EXPORTS" ] && echo 1 || echo 0)"

# Verify export trie is valid by checking dyld can resolve symbols
OUTPUT2=$(DYLD_PRINT_BINDINGS=1 "$TESTDIR/big_exports_patched" 2>&1) || true
check "Patched binary runs with DYLD_PRINT_BINDINGS" "$(echo "$OUTPUT2" | grep -c 'BIG_EXPORTS_OK')"

# ==========================================================================
echo ""
echo "=== Fix 7: Shadow header has ncmds=0 ==="
# Build a test binary that reads _mh_execute_header and checks ncmds
cat > "$TESTDIR/shadow_test.c" << 'EOF'
#include <stdio.h>
#include <mach-o/loader.h>
#include <mach-o/getsect.h>
extern struct mach_header _mh_execute_header;

int main(void) {
    // Direct reference (uses shadow after expansion)
    if (_mh_execute_header.magic == MH_MAGIC_64 || _mh_execute_header.magic == MH_MAGIC) {
        printf("MAGIC_OK\n");
    } else {
        printf("MAGIC_BAD=0x%x\n", _mh_execute_header.magic);
    }
    // Shadow should have ncmds=0 so code won't walk garbage LCs
    if (_mh_execute_header.ncmds == 0) {
        printf("NCMDS_ZERO\n");
    } else {
        printf("NCMDS=%d\n", _mh_execute_header.ncmds);
    }
    printf("SHADOW_TEST_OK\n");
    return 0;
}
EOF
cc -o "$TESTDIR/shadow_test" "$TESTDIR/shadow_test.c" -Wl,-headerpad,0x0

# Exhaust space and trigger expansion
cp "$TESTDIR/shadow_test" "$TESTDIR/shadow_patched"
for i in $(seq 1 60); do
    $TOOL --all-yes --inplace --weak \
        "/fake/pad_${i}_aaaaaaaaaaaaaaaaaaaaa.dylib" \
        "$TESTDIR/shadow_patched" 2>&1 > /dev/null || true
done

OUTPUT=$("$TESTDIR/shadow_patched" 2>&1) || true
echo "Output: $OUTPUT"
check "Shadow has valid magic" "$(echo "$OUTPUT" | grep -c 'MAGIC_OK')"
check "Shadow has ncmds=0 (safe for LC walkers)" "$(echo "$OUTPUT" | grep -c 'NCMDS_ZERO')"
check "Shadow test runs to completion" "$(echo "$OUTPUT" | grep -c 'SHADOW_TEST_OK')"

# ==========================================================================
echo ""
echo "=== Fix 8: Fall-through bug (codesig stripping with segments) ==="
# The fall-through made symtab_pos point to the last segment instead of LC_SYMTAB.
# This corrupted code signature stripping. We test by creating a binary with a
# code signature, stripping it during insertion, and verifying the binary works.
cat > "$TESTDIR/codesig_test.c" << 'EOF'
#include <stdio.h>
int main(void) { printf("CODESIG_TEST_OK\n"); return 0; }
EOF
cc -o "$TESTDIR/codesig_test" "$TESTDIR/codesig_test.c"

# Ad-hoc sign it to add LC_CODE_SIGNATURE
codesign -s - "$TESTDIR/codesig_test" 2>/dev/null || true

# Verify it has a code signature
HAS_CODESIG=$(otool -l "$TESTDIR/codesig_test" 2>/dev/null | grep -c "LC_CODE_SIGNATURE")
check "Test binary has code signature" "$([ "$HAS_CODESIG" -gt 0 ] && echo 1 || echo 0)"

# Insert a dylib (which should strip the code signature)
cp "$TESTDIR/codesig_test" "$TESTDIR/codesig_patched"
$TOOL --all-yes --strip-codesig --inplace /usr/lib/libz.dylib "$TESTDIR/codesig_patched" 2>&1 > /dev/null

# Verify code signature was stripped
NO_CODESIG=$(otool -l "$TESTDIR/codesig_patched" 2>/dev/null | grep -c "LC_CODE_SIGNATURE")
check "Code signature stripped" "$([ "$NO_CODESIG" -eq 0 ] && echo 1 || echo 0)"

# Verify the binary still runs
OUTPUT=$("$TESTDIR/codesig_patched" 2>&1) || true
check "Binary runs after codesig strip (fall-through fix)" "$(echo "$OUTPUT" | grep -c 'CODESIG_TEST_OK')"

# Verify the symtab is valid (nm should work without errors)
NM_OUTPUT=$(nm "$TESTDIR/codesig_patched" 2>&1)
NM_OK=$(echo "$NM_OUTPUT" | grep -c "_main")
check "Symbol table intact after codesig strip" "$([ "$NM_OK" -gt 0 ] && echo 1 || echo 0)"

# ==========================================================================
echo ""
echo "=== Fix 9: No false positive pointer corruption ==="
# Build a binary that has 0x100000000 (4GB) as a data constant in __DATA,
# and verify it's NOT corrupted after expansion.
cat > "$TESTDIR/false_positive.c" << 'EOF'
#include <stdio.h>
#include <stdint.h>
#include <crt_externs.h>
#include <mach-o/loader.h>

// This constant happens to equal the typical __TEXT vmaddr (0x100000000)
volatile uint64_t four_gb = 0x100000000ULL;

int main(void) {
    // Verify our 4GB constant was NOT corrupted
    if (four_gb == 0x100000000ULL) {
        printf("CONSTANT_INTACT\n");
    } else {
        printf("CONSTANT_CORRUPTED=0x%llx\n", four_gb);
    }

    // Verify _NSGetMachExecuteHeader still works
    const struct mach_header *mh = _NSGetMachExecuteHeader();
    if (mh && (mh->magic == MH_MAGIC_64 || mh->magic == MH_MAGIC)) {
        printf("MH_VALID\n");
    } else {
        printf("MH_INVALID\n");
    }

    printf("FALSE_POS_OK\n");
    return 0;
}
EOF
cc -o "$TESTDIR/false_positive" "$TESTDIR/false_positive.c" -Wl,-headerpad,0x0

# Verify original works
ORIG_OUT=$("$TESTDIR/false_positive" 2>&1)
check "Original: constant intact" "$(echo "$ORIG_OUT" | grep -c 'CONSTANT_INTACT')"

# Exhaust space and trigger expansion
cp "$TESTDIR/false_positive" "$TESTDIR/fp_patched"
for i in $(seq 1 60); do
    $TOOL --all-yes --inplace --weak \
        "/fake/pad_${i}_aaaaaaaaaaaaaaaaaaaaa.dylib" \
        "$TESTDIR/fp_patched" 2>&1 > /dev/null || true
done

OUTPUT=$("$TESTDIR/fp_patched" 2>&1) || true
echo "Output: $OUTPUT"
check "4GB constant NOT corrupted after expansion" "$(echo "$OUTPUT" | grep -c 'CONSTANT_INTACT')"
check "_NSGetMachExecuteHeader still valid" "$(echo "$OUTPUT" | grep -c 'MH_VALID')"
check "False positive test runs to completion" "$(echo "$OUTPUT" | grep -c 'FALSE_POS_OK')"

# ==========================================================================
echo ""
echo "================================"
echo "Results: $PASS/$TOTAL passed, $FAIL failed"
echo "================================"

[ $FAIL -eq 0 ] && exit 0 || exit 1
