#!/bin/bash
# Test script for insert_dylib header expansion
set -e

BINARY="./insert_dylib_new"
TESTDIR=$(mktemp -d -t insert_dylib_test)
PASS=0
FAIL=0
TOTAL=0

cleanup() { rm -rf "$TESTDIR"; }
trap cleanup EXIT

assert_ok() {
    TOTAL=$((TOTAL + 1))
    if [ $? -eq 0 ]; then
        PASS=$((PASS + 1))
        echo "  PASS: $1"
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL: $1"
    fi
}

assert_contains() {
    TOTAL=$((TOTAL + 1))
    if echo "$2" | grep -q "$3"; then
        PASS=$((PASS + 1))
        echo "  PASS: $1"
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL: $1 (expected to find '$3')"
    fi
}

assert_eq() {
    TOTAL=$((TOTAL + 1))
    if [ "$2" = "$3" ]; then
        PASS=$((PASS + 1))
        echo "  PASS: $1"
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL: $1 (got '$2', expected '$3')"
    fi
}

# Build the tool if needed
if [ ! -f "$BINARY" ]; then
    echo "Building insert_dylib..."
    cc -o "$BINARY" insert_dylib/main.c -O2 -Wall
fi

SRC="/Applications/Momiji.app/Contents/MacOS/firefox"
if [ ! -f "$SRC" ]; then
    echo "ERROR: $SRC not found. Cannot run tests."
    exit 1
fi

# Get original values for comparison
ORIG_RIP=$(otool -l "$SRC" | grep -A20 "LC_UNIXTHREAD" | grep rip | awk '{print $NF}')
ORIG_DATA_VMADDR=$(otool -l "$SRC" | grep -A4 "segname __DATA" | head -1 | grep -A3 "__DATA" | grep vmaddr | head -1 | awk '{print $2}')
ORIG_LINKEDIT_VMADDR=$(otool -l "$SRC" | grep -A4 "segname __LINKEDIT" | grep vmaddr | head -1 | awk '{print $2}')

# Save original symbol vmaddrs and mh pointer for later verification
ORIG_SYMBOLS=$(python3 -c "
import struct
def read_uleb(d, o):
    r = 0; b = 0
    while o < len(d):
        byte = d[o]; r |= (byte & 0x7f) << b; b += 7; o += 1
        if not (byte & 0x80): break
    return r, o
def walk(d, off, pfx, res):
    if off >= len(d): return
    o = off; ts, o = read_uleb(d, o)
    if ts > 0:
        te = o + ts; fl, o2 = read_uleb(d, o)
        if not (fl & 0x08):
            a, _ = read_uleb(d, o2); res.append((pfx, a))
        o = te
    cc = d[o]; o += 1
    for _ in range(cc):
        lb = b''
        while o < len(d) and d[o]: lb += bytes([d[o]]); o += 1
        o += 1; co, o = read_uleb(d, o)
        walk(d, co, pfx + lb.decode(), res)
with open('$SRC', 'rb') as f: d = f.read()
nc = struct.unpack_from('<I', d, 16)[0]; pos = 32; tv = eo = es = 0
for _ in range(nc):
    cmd, cs = struct.unpack_from('<II', d, pos)
    if cmd == 0x19 and d[pos+8:pos+24].rstrip(b'\x00') == b'__TEXT':
        tv = struct.unpack_from('<Q', d, pos+24)[0]
    elif cmd in (0x22, 0x80000022):
        eo = struct.unpack_from('<I', d, pos+40)[0]; es = struct.unpack_from('<I', d, pos+44)[0]
    pos += cs
res = []; walk(d[eo:eo+es], 0, '', res)
for sym, off in res:
    print(f'{sym}=0x{tv + off:x}')
")

echo ""
echo "=== Test 1: Short dylib path (no expansion needed) ==="
TEST1="$TESTDIR/test1"
cp "$SRC" "$TEST1"
OUTPUT=$($BINARY --all-yes --inplace /usr/lib/libz.dylib "$TEST1" 2>&1)
assert_ok "Insert short path succeeds"
assert_contains "No expansion message" "$OUTPUT" "Added LC_LOAD_DYLIB"
# Verify no expansion happened (no "WARNING" in output)
TOTAL=$((TOTAL + 1))
if ! echo "$OUTPUT" | grep -q "WARNING"; then
    PASS=$((PASS + 1))
    echo "  PASS: No expansion triggered for short path"
else
    FAIL=$((FAIL + 1))
    echo "  FAIL: Expansion was triggered unexpectedly"
fi
# Verify dylib is present
LIBS=$(otool -L "$TEST1" 2>&1)
assert_contains "libz appears in otool -L" "$LIBS" "libz.dylib"

echo ""
echo "=== Test 2: Long dylib path (expansion required) ==="
TEST2="$TESTDIR/test2"
cp "$SRC" "$TEST2"
# Generate a path long enough to guarantee expansion by exceeding all available free space
FREE_SPACE=$(python3 -c "
import struct
with open('$SRC', 'rb') as f: d = f.read()
nc, sc = struct.unpack_from('<II', d, 16)[:2]
pos = 32; mn = len(d)
for _ in range(nc):
    cmd, cs = struct.unpack_from('<II', d, pos)
    if cmd == 0x19:
        ns2 = struct.unpack_from('<I', d, pos+64)[0]
        for j in range(ns2):
            o = struct.unpack_from('<I', d, pos+72+j*80+48)[0]
            if 0 < o < mn: mn = o
    pos += cs
print(mn - 32 - sc)
")
# Path must be longer than free_space - sizeof(struct dylib_command) = free_space - 24
PAD_LEN=$((FREE_SPACE - 24 + 100))
LONG_PATH="@executable_path/../Frameworks/$(python3 -c "print('A' * $PAD_LEN)").dylib"
OUTPUT=$($BINARY --all-yes --inplace "$LONG_PATH" "$TEST2" 2>&1)
assert_ok "Insert long path succeeds"
assert_contains "Expansion triggered" "$OUTPUT" "WARNING"
assert_contains "Addition reported" "$OUTPUT" "Added LC_LOAD_DYLIB"

# Verify the new load command is present
LIBS=$(otool -L "$TEST2" 2>&1)
assert_contains "Long dylib path in otool -L" "$LIBS" "AAAA"

# Verify vmaddrs preserved
NEW_RIP=$(otool -l "$TEST2" | grep -A20 "LC_UNIXTHREAD" | grep rip | awk '{print $NF}')
assert_eq "Entry point (rip) unchanged" "$NEW_RIP" "$ORIG_RIP"

NEW_DATA_VMADDR=$(otool -l "$TEST2" | grep -A4 "segname __DATA" | head -1 | grep -A3 "__DATA" | grep vmaddr | head -1 | awk '{print $2}')
assert_eq "__DATA vmaddr unchanged" "$NEW_DATA_VMADDR" "$ORIG_DATA_VMADDR"

NEW_LINKEDIT_VMADDR=$(otool -l "$TEST2" | grep -A4 "segname __LINKEDIT" | grep vmaddr | head -1 | awk '{print $2}')
assert_eq "__LINKEDIT vmaddr unchanged" "$NEW_LINKEDIT_VMADDR" "$ORIG_LINKEDIT_VMADDR"

# Get original values for segment checks
ORIG_PZ_VMSIZE=$(otool -l "$SRC" | grep -A4 "segname __PAGEZERO" | grep vmsize | awk '{print $2}')
ORIG_TEXT_VMADDR=$(otool -l "$SRC" | grep -A5 "cmd LC_SEGMENT_64" | grep -A3 "segname __TEXT" | grep "vmaddr" | head -1 | awk '{print $2}')
ORIG_TEXT_VMSIZE=$(otool -l "$SRC" | grep -A5 "cmd LC_SEGMENT_64" | grep -A4 "segname __TEXT" | grep "vmsize" | head -1 | awk '{print $2}')
ORIG_TEXT_SECT_ADDR=$(otool -l "$SRC" | grep -B1 -A10 "sectname __text" | grep "addr " | head -1 | awk '{print $2}')

# Verify __PAGEZERO was shrunk (compare to original)
PAGEZERO_VMSIZE=$(otool -l "$TEST2" | grep -A4 "segname __PAGEZERO" | grep vmsize | awk '{print $2}')
TOTAL=$((TOTAL + 1))
if [ "$PAGEZERO_VMSIZE" != "$ORIG_PZ_VMSIZE" ]; then
    PASS=$((PASS + 1))
    echo "  PASS: __PAGEZERO shrunk (was $ORIG_PZ_VMSIZE, now $PAGEZERO_VMSIZE)"
else
    FAIL=$((FAIL + 1))
    echo "  FAIL: __PAGEZERO not shrunk"
fi

# Verify __TEXT expanded
TEXT_VMSIZE=$(otool -l "$TEST2" | grep -A5 "cmd LC_SEGMENT_64" | grep -A4 "segname __TEXT" | grep "vmsize" | head -1 | awk '{print $2}')
TOTAL=$((TOTAL + 1))
if [ "$TEXT_VMSIZE" != "$ORIG_TEXT_VMSIZE" ]; then
    PASS=$((PASS + 1))
    echo "  PASS: __TEXT vmsize grew (was $ORIG_TEXT_VMSIZE, now $TEXT_VMSIZE)"
else
    FAIL=$((FAIL + 1))
    echo "  FAIL: __TEXT vmsize did not grow"
fi

# Verify __text section addr unchanged
TEXT_SECT_ADDR=$(otool -l "$TEST2" | grep -B1 -A10 "sectname __text" | grep "addr " | head -1 | awk '{print $2}')
assert_eq "__text section vmaddr unchanged" "$TEXT_SECT_ADDR" "$ORIG_TEXT_SECT_ADDR"

# --- Image base fixup verification ---
# Verify export trie resolves all symbols to same vmaddrs as original
FIXUP_RESULT=$(python3 -c "
import struct
def read_uleb(d, o):
    r = 0; b = 0
    while o < len(d):
        byte = d[o]; r |= (byte & 0x7f) << b; b += 7; o += 1
        if not (byte & 0x80): break
    return r, o
def walk(d, off, pfx, res):
    if off >= len(d): return
    o = off; ts, o = read_uleb(d, o)
    if ts > 0:
        te = o + ts; fl, o2 = read_uleb(d, o)
        if not (fl & 0x08):
            a, _ = read_uleb(d, o2); res.append((pfx, a))
        o = te
    cc = d[o]; o += 1
    for _ in range(cc):
        lb = b''
        while o < len(d) and d[o]: lb += bytes([d[o]]); o += 1
        o += 1; co, o = read_uleb(d, o)
        walk(d, co, pfx + lb.decode(), res)

# Build expected map from original
orig = {}
for line in '''$ORIG_SYMBOLS'''.strip().split('\n'):
    if '=' in line:
        k, v = line.split('='); orig[k] = int(v, 16)

# Check patched
with open('$TEST2', 'rb') as f: d = f.read()
nc = struct.unpack_from('<I', d, 16)[0]; pos = 32; tv = eo = es = so = ns = sto = 0
for _ in range(nc):
    cmd, cs = struct.unpack_from('<II', d, pos)
    if cmd == 0x19:
        seg = d[pos+8:pos+24].rstrip(b'\x00').decode()
        if seg == '__TEXT': tv = struct.unpack_from('<Q', d, pos+24)[0]
        elif seg == '__DATA':
            nsects = struct.unpack_from('<I', d, pos+64)[0]
            for j in range(nsects):
                sp = pos + 72 + j*80
                sn = d[sp:sp+16].rstrip(b'\x00').decode()
                if sn == '__program_vars':
                    pv_off = struct.unpack_from('<I', d, sp+48)[0]
    elif cmd in (0x22, 0x80000022):
        eo = struct.unpack_from('<I', d, pos+40)[0]; es = struct.unpack_from('<I', d, pos+44)[0]
    elif cmd == 0x02:  # LC_SYMTAB
        so, ns, sto = struct.unpack_from('<III', d, pos+8)
    pos += cs

errors = []

# Check export trie
res = []; walk(d[eo:eo+es], 0, '', res)
for sym, off in res:
    resolved = tv + off
    # __mh_execute_header (offset 0) always equals __TEXT vmaddr, which changes by design
    if sym == '__mh_execute_header': continue
    if sym in orig and orig[sym] != resolved:
        errors.append(f'export_trie:{sym}=0x{resolved:x},expected=0x{orig[sym]:x}')

# Check __program_vars.mh
mh_ptr = struct.unpack_from('<Q', d, pv_off)[0]
if mh_ptr != tv:
    errors.append(f'program_vars_mh=0x{mh_ptr:x},expected=0x{tv:x}')

# Check nlist __mh_execute_header
for i in range(ns):
    eo2 = so + i*16
    strx = struct.unpack_from('<I', d, eo2)[0]
    nval = struct.unpack_from('<Q', d, eo2+8)[0]
    si = sto + strx; sym = ''
    while si < len(d) and d[si]: sym += chr(d[si]); si += 1
    if sym == '__mh_execute_header' and nval != tv:
        errors.append(f'nlist_mh=0x{nval:x},expected=0x{tv:x}')

if errors: print('ERRORS:' + ';'.join(errors))
else: print('ALL_OK')
")

TOTAL=$((TOTAL + 1))
if [ "$FIXUP_RESULT" = "ALL_OK" ]; then
    PASS=$((PASS + 1))
    echo "  PASS: Export trie symbols resolve correctly"
else
    FAIL=$((FAIL + 1))
    echo "  FAIL: Export trie symbols wrong ($FIXUP_RESULT)"
fi

TOTAL=$((TOTAL + 1))
if echo "$FIXUP_RESULT" | grep -q "program_vars_mh"; then
    FAIL=$((FAIL + 1))
    echo "  FAIL: __program_vars.mh pointer wrong ($FIXUP_RESULT)"
else
    PASS=$((PASS + 1))
    echo "  PASS: __program_vars.mh matches __TEXT vmaddr"
fi

TOTAL=$((TOTAL + 1))
if echo "$FIXUP_RESULT" | grep -q "nlist_mh"; then
    FAIL=$((FAIL + 1))
    echo "  FAIL: nlist __mh_execute_header wrong ($FIXUP_RESULT)"
else
    PASS=$((PASS + 1))
    echo "  PASS: nlist __mh_execute_header matches __TEXT vmaddr"
fi

echo ""
echo "=== Test 3: Multiple insertions ==="
TEST3="$TESTDIR/test3"
cp "$SRC" "$TEST3"
# First insertion: short (no expansion)
$BINARY --all-yes --inplace /usr/lib/libz.dylib "$TEST3" 2>&1 > /dev/null
# Second insertion: should trigger expansion since first consumed some space
LONG2="@executable_path/../Frameworks/AnotherLongishDylibNameForTesting.dylib"
OUTPUT=$($BINARY --all-yes --inplace "$LONG2" "$TEST3" 2>&1)
assert_ok "Second insert succeeds"
LIBS=$(otool -L "$TEST3" 2>&1)
assert_contains "Both dylibs present (libz)" "$LIBS" "libz.dylib"
assert_contains "Both dylibs present (second)" "$LIBS" "AnotherLongishDylib"

# Verify binary structure is still valid
NEW_RIP=$(otool -l "$TEST3" | grep -A20 "LC_UNIXTHREAD" | grep rip | awk '{print $NF}')
assert_eq "Entry point still correct after two inserts" "$NEW_RIP" "$ORIG_RIP"

echo ""
echo "=== Test 4: Output file mode (non-inplace) ==="
TEST4_IN="$TESTDIR/test4_in"
TEST4_OUT="$TESTDIR/test4_out"
cp "$SRC" "$TEST4_IN"
LONG3="@executable_path/../Frameworks/YetAnotherVeryLongDylibPathForOutputMode.dylib"
OUTPUT=$($BINARY --all-yes "$LONG3" "$TEST4_IN" "$TEST4_OUT" 2>&1)
assert_ok "Non-inplace insert with expansion succeeds"
assert_contains "Output file created" "$OUTPUT" "Added LC_LOAD_DYLIB"
TOTAL=$((TOTAL + 1))
if [ -f "$TEST4_OUT" ]; then
    PASS=$((PASS + 1))
    echo "  PASS: Output file exists"
else
    FAIL=$((FAIL + 1))
    echo "  FAIL: Output file not created"
fi
# Original should be unchanged (same load command count as source)
ORIG_NCMDS=$(otool -l "$TEST4_IN" | grep -c "^Load command")
SRC_NCMDS=$(otool -l "$SRC" | grep -c "^Load command")
assert_eq "Original unchanged" "$ORIG_NCMDS" "$SRC_NCMDS"

echo ""
echo "================================"
echo "Results: $PASS/$TOTAL passed, $FAIL failed"
echo "================================"

[ $FAIL -eq 0 ] && exit 0 || exit 1
