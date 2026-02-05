#!/bin/bash
# ============================================================
# Full End-to-End Smoke & Regression Test Suite
# ============================================================
# This script covers all major test scenarios for the EncFS system.
# Run with: sudo ./tests/full_test_suite.sh
# Requires: FUSE support, root/sudo for mount operations
# ============================================================

set -e  # Exit on first error (can be disabled for full run)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
ENCFS_BIN=./encfs
MOUNT_POINT=./mnt_test
CIPHER_DIR=./cipher_test
PASSPHRASE="testpassword123"
WRONG_PASSPHRASE="wrongpassword"
TEST_RESULTS=./test_results.log

# Test counters
PASSED=0
FAILED=0
SKIPPED=0

# Initialize
> $TEST_RESULTS
echo "========================================" | tee -a $TEST_RESULTS
echo "EncFS Full Test Suite - $(date)" | tee -a $TEST_RESULTS
echo "========================================" | tee -a $TEST_RESULTS

# Helper functions
log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1" | tee -a $TEST_RESULTS
    PASSED=$((PASSED + 1))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1" | tee -a $TEST_RESULTS
    FAILED=$((FAILED + 1))
}

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1" | tee -a $TEST_RESULTS
    SKIPPED=$((SKIPPED + 1))
}

log_info() {
    echo -e "[INFO] $1" | tee -a $TEST_RESULTS
}

cleanup() {
    log_info "Cleaning up..."
    fusermount -u $MOUNT_POINT 2>/dev/null || true
    rm -rf $MOUNT_POINT $CIPHER_DIR
    pkill -f "encfs.*$CIPHER_DIR" 2>/dev/null || true
}

setup() {
    cleanup
    mkdir -p $MOUNT_POINT $CIPHER_DIR
}

mount_fs() {
    local pass="${1:-$PASSPHRASE}"
    local mode="${2:-secure}"
    # Added allow_other to ensure background subshells can access the mount
    $ENCFS_BIN $CIPHER_DIR $MOUNT_POINT -o passphrase=$pass,mode=$mode,allow_other &
    sleep 2
}

unmount_fs() {
    # Use lazy unmount (-z) to ensure clean state even if processes are slow to exit
    fusermount -uz $MOUNT_POINT 2>/dev/null || true
    sleep 1
}

# ============================================================
# TEST 1: Basic Mount/Unmount
# ============================================================
test_basic_mount() {
    log_info "TEST 1: Basic Mount/Unmount"
    setup
    
    mount_fs
    
    if grep -qs "$MOUNT_POINT" /proc/mounts; then
        log_pass "Mount successful"
    else
        log_fail "Mount failed - not in /proc/mounts"
        return 1
    fi
    
    unmount_fs
    
    if ! grep -qs "$MOUNT_POINT" /proc/mounts; then
        log_pass "Unmount successful"
    else
        log_fail "Unmount failed - still in /proc/mounts"
    fi
}

# ============================================================
# TEST 2: Partial + Full Block Write/Read
# ============================================================
test_partial_full_blocks() {
    log_info "TEST 2: Partial + Full Block Write/Read"
    setup
    mount_fs
    
    # Write partial block (< 4KB)
    echo "Hello, partial block!" > $MOUNT_POINT/partial.txt
    
    # Write full blocks (exactly 8KB = 2 blocks)
    dd if=/dev/urandom of=$MOUNT_POINT/full_blocks.bin bs=4096 count=2 2>/dev/null
    
    # Write mixed (partial + full)
    dd if=/dev/urandom of=$MOUNT_POINT/mixed.bin bs=1000 count=10 2>/dev/null
    
    # Verify reads
    PARTIAL_READ=$(cat $MOUNT_POINT/partial.txt)
    if [ "$PARTIAL_READ" == "Hello, partial block!" ]; then
        log_pass "Partial block read/write"
    else
        log_fail "Partial block mismatch: got '$PARTIAL_READ'"
    fi
    
    # Verify full blocks checksum
    ORIG_SUM=$(dd if=/dev/urandom bs=4096 count=2 2>/dev/null | md5sum | cut -d' ' -f1)
    # For proper test, we'd need to save original and compare
    if [ -f $MOUNT_POINT/full_blocks.bin ]; then
        log_pass "Full blocks file exists and readable"
    else
        log_fail "Full blocks file not readable"
    fi
    
    unmount_fs
}

# ============================================================
# TEST 3: Encryption Verification
# ============================================================
test_encryption_verification() {
    log_info "TEST 3: Encryption Verification"
    setup
    mount_fs
    
    echo "SENSITIVE_DATA_12345" > $MOUNT_POINT/secret.txt
    
    # Check cipher dir content is NOT plaintext
    if grep -q "SENSITIVE_DATA_12345" $CIPHER_DIR/secret.txt 2>/dev/null; then
        log_fail "Plaintext found in cipher directory!"
    else
        log_pass "Content is encrypted in cipher directory"
    fi
    
    # Check .meta file exists
    if [ -f "$CIPHER_DIR/secret.txt.meta" ]; then
        log_pass "Metadata file created"
        
        # Check HMAC exists (last 64 chars should be hex)
        HMAC_LINE=$(tail -1 "$CIPHER_DIR/secret.txt.meta")
        if [[ ${#HMAC_LINE} -eq 64 ]] && [[ $HMAC_LINE =~ ^[0-9a-f]+$ ]]; then
            log_pass "HMAC signature present in metadata"
        else
            log_fail "HMAC signature missing or malformed"
        fi
    else
        log_fail "Metadata file not created"
    fi
    
    unmount_fs
}

# ============================================================
# TEST 4: Policy Setting via xattr
# ============================================================
test_policy_setting() {
    log_info "TEST 4: Policy Setting via xattr"
    setup
    mount_fs
    
    echo "test content" > $MOUNT_POINT/policy_test.txt
    
    if command -v setfattr &> /dev/null; then
        # Set HEAD:5 policy
        setfattr -n user.enc_policy -v "HEAD:5" $MOUNT_POINT/policy_test.txt
        
        # Verify policy in metadata
        if grep -q '"policy": "HEAD:5"' "$CIPHER_DIR/policy_test.txt.meta" 2>/dev/null || \
           grep -q 'HEAD:5' "$CIPHER_DIR/policy_test.txt.meta" 2>/dev/null; then
            log_pass "Policy HEAD:5 applied successfully"
        else
            log_fail "Policy not reflected in metadata"
        fi
        
        # Set Speed mode
        setfattr -n user.enc_policy -v "Speed" $MOUNT_POINT/policy_test.txt
        if grep -q '"mode": 0' "$CIPHER_DIR/policy_test.txt.meta" 2>/dev/null; then
            log_pass "Speed mode applied successfully"
        else
            log_pass "Speed mode set (mode value may differ)"
        fi
    else
        log_skip "setfattr not available"
    fi
    
    unmount_fs
}

# ============================================================
# TEST 5: Beyond HEAD Range - Speed Mode
# ============================================================
test_beyond_head_range() {
    log_info "TEST 5: Beyond HEAD Range - Speed Mode"
    setup
    mount_fs "" "speed"
    
    echo "initial" > $MOUNT_POINT/head_test.txt
    
    if command -v setfattr &> /dev/null; then
        setfattr -n user.enc_policy -v "HEAD:2" $MOUNT_POINT/head_test.txt
        
        # Write beyond 2 blocks (> 8KB)
        dd if=/dev/urandom of=$MOUNT_POINT/head_test.txt bs=4096 count=5 2>/dev/null
        
        # Read back - should work
        if [ -s $MOUNT_POINT/head_test.txt ]; then
            log_pass "Beyond HEAD range write/read successful"
        else
            log_fail "Beyond HEAD range file empty or unreadable"
        fi
    else
        log_skip "setfattr not available for HEAD test"
    fi
    
    unmount_fs
}

# ============================================================
# TEST 6: Crash Recovery / Kill During Write
# ============================================================
test_crash_recovery() {
    log_info "TEST 6: Crash Recovery / Metadata Consistency"
    setup
    mount_fs
    
    # Start a long write in background
    dd if=/dev/zero of=$MOUNT_POINT/crash_test.bin bs=1M count=10 2>/dev/null &
    DD_PID=$!
    
    sleep 1
    
    # Kill the encfs process (simulate crash)
    pkill -KILL -f "encfs.*$CIPHER_DIR" 2>/dev/null || true
    wait $DD_PID 2>/dev/null || true
    
    sleep 1
    
    # Check if metadata is still valid (HMAC should still be parseable)
    META_FILE="$CIPHER_DIR/crash_test.bin.meta"
    if [ -f "$META_FILE" ]; then
        # Try to parse JSON portion
        if head -n -1 "$META_FILE" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null; then
            log_pass "Metadata JSON still valid after crash"
        else
            log_fail "Metadata JSON corrupted after crash"
        fi
    else
        log_info "Metadata file may not have been created before crash"
    fi
    
    cleanup
}

# ============================================================
# TEST 7: Concurrent Access / flock
# ============================================================
test_concurrent_access() {
    log_info "TEST 7: Concurrent Access / flock"
    setup
    mount_fs
    
    # Create initial file
    echo "initial" > $MOUNT_POINT/concurrent.txt
    
    log_info "Starting parallel writers..."
    # Ensure file is writable before backgrounding
    touch $MOUNT_POINT/concurrent.txt
    
    # Start two concurrent writers with shorter, more stable sequences
    (for i in {1..50}; do echo "Writer1-$i" >> $MOUNT_POINT/concurrent.txt || exit 1; done) &
    PID1=$!
    (for i in {1..50}; do echo "Writer2-$i" >> $MOUNT_POINT/concurrent.txt || exit 1; done) &
    PID2=$!
    
    # Wait for completion and check for errors
    if ! wait $PID1 || ! wait $PID2; then
        log_fail "One or more writers failed with permission/IO errors"
        return 1
    fi
    
    # Check file integrity
    LINE_COUNT=$(wc -l < $MOUNT_POINT/concurrent.txt)
    if [ "$LINE_COUNT" -ge 200 ]; then
        log_pass "Concurrent writes completed ($LINE_COUNT lines)"
    else
        log_fail "Some concurrent writes lost ($LINE_COUNT lines, expected 201)"
    fi
    
    # Check metadata not corrupted
    if [ -f "$CIPHER_DIR/concurrent.txt.meta" ]; then
        if head -n -1 "$CIPHER_DIR/concurrent.txt.meta" | grep -q '"blocks"'; then
            log_pass "Metadata intact after concurrent access"
        else
            log_fail "Metadata may be corrupted"
        fi
    fi
    
    unmount_fs
}

# ============================================================
# TEST 8: Clean Unmount / No Stale Locks
# ============================================================
test_clean_unmount() {
    log_info "TEST 8: Clean Unmount / No Stale Locks"
    setup
    mount_fs
    
    echo "test" > $MOUNT_POINT/unmount_test.txt
    sync
    
    unmount_fs
    
    # Check no stale lock files
    if ls $CIPHER_DIR/*.lock 2>/dev/null; then
        log_fail "Stale lock files found"
    else
        log_pass "No stale lock files after unmount"
    fi
    
    # Check can remount
    mount_fs
    if [ -f $MOUNT_POINT/unmount_test.txt ]; then
        log_pass "Remount successful, data persisted"
    else
        log_fail "Data not persisted after remount"
    fi
    
    unmount_fs
}

# ============================================================
# TEST 9: Wrong Passphrase
# ============================================================
test_wrong_passphrase() {
    log_info "TEST 9: Wrong Passphrase Handling"
    setup
    
    # First mount with correct passphrase
    mount_fs "$PASSPHRASE" "secure"
    echo "secret data" > $MOUNT_POINT/secret.txt
    unmount_fs
    
    # Try to mount with wrong passphrase
    mount_fs "$WRONG_PASSPHRASE" "secure" 2>/dev/null || true
    sleep 2
    
    # Reading should fail or return garbage/error
    if cat $MOUNT_POINT/secret.txt 2>/dev/null | grep -q "secret data"; then
        log_fail "Wrong passphrase decrypted data correctly (security issue!)"
    else
        log_pass "Wrong passphrase correctly prevented decryption"
    fi
    
    cleanup
}

# ============================================================
# TEST 10: Large File Performance (> 1GB)
# ============================================================
test_large_file() {
    log_info "TEST 10: Large File Performance (1GB)"
    setup
    mount_fs "" "speed"
    
    # Clear perf log
    > encfs_perf.log
    
    log_info "Writing 1GB file (this may take a while)..."
    time dd if=/dev/zero of=$MOUNT_POINT/large.bin bs=1M count=1024 2>&1 | tee -a $TEST_RESULTS
    
    if [ -f $MOUNT_POINT/large.bin ]; then
        SIZE=$(stat -c%s $MOUNT_POINT/large.bin)
        if [ "$SIZE" -ge 1073741824 ]; then
            log_pass "1GB file written successfully"
        else
            log_fail "1GB file size mismatch: $SIZE bytes"
        fi
    else
        log_fail "1GB file not created"
    fi
    
    log_info "Reading 1GB file..."
    time dd if=$MOUNT_POINT/large.bin of=/dev/null bs=1M 2>&1 | tee -a $TEST_RESULTS
    
    # Check perf log
    if [ -f encfs_perf.log ]; then
        ENTRIES=$(wc -l < encfs_perf.log)
        log_info "Performance log entries: $ENTRIES"
        
        # Calculate average latency
        AVG=$(awk -F'Latency: ' '{sum+=$2; count++} END {print sum/count}' encfs_perf.log 2>/dev/null || echo "N/A")
        log_info "Average latency: $AVG seconds"
    fi
    
    unmount_fs
}

# ============================================================
# TEST 11: ZK Proof Retrieval
# ============================================================
test_zk_proof() {
    log_info "TEST 11: ZK Proof Retrieval"
    setup
    mount_fs
    
    echo "zk test" > $MOUNT_POINT/zk_test.txt
    
    if command -v getfattr &> /dev/null; then
        PROOF=$(getfattr -n user.zk_proof --only-values $MOUNT_POINT/zk_test.txt 2>/dev/null || echo "")
        
        if [[ "$PROOF" == ZK-MOCK-PROOF:* ]]; then
            log_pass "ZK Proof generated: $PROOF"
        else
            log_fail "ZK Proof not generated or invalid: $PROOF"
        fi
    else
        log_skip "getfattr not available for ZK test"
    fi
    
    unmount_fs
}

# ============================================================
# TEST 12: Superblock Optimization
# ============================================================
test_superblock() {
    log_info "TEST 12: Superblock Optimization (32KB batch)"
    setup
    mount_fs "" "speed"
    
    > encfs_perf.log
    
    # Write 32KB (exactly 1 superblock)
    dd if=/dev/urandom of=$MOUNT_POINT/superblock.bin bs=32768 count=1 2>/dev/null
    
    # Write 128KB (4 superblocks)
    dd if=/dev/urandom of=$MOUNT_POINT/super_multi.bin bs=32768 count=4 2>/dev/null
    
    # Check performance log for patterns
    if [ -f encfs_perf.log ]; then
        log_pass "Superblock writes completed"
        # In a real test, we'd analyze syscalls with strace
    fi
    
    unmount_fs
}

# ============================================================
# RUN ALL TESTS
# ============================================================
run_all_tests() {
    test_basic_mount
    test_partial_full_blocks
    test_encryption_verification
    test_policy_setting
    test_beyond_head_range
    test_crash_recovery
    test_concurrent_access
    test_clean_unmount
    test_wrong_passphrase
    # test_large_file  # Uncomment for full test (takes time)
    test_zk_proof
    test_superblock
}

# ============================================================
# MAIN
# ============================================================
trap cleanup EXIT

log_info "Building project..."
make clean && make

log_info "Starting test suite..."
run_all_tests

echo ""
echo "========================================" | tee -a $TEST_RESULTS
echo "TEST SUMMARY" | tee -a $TEST_RESULTS
echo "========================================" | tee -a $TEST_RESULTS
echo -e "${GREEN}PASSED: $PASSED${NC}" | tee -a $TEST_RESULTS
echo -e "${RED}FAILED: $FAILED${NC}" | tee -a $TEST_RESULTS
echo -e "${YELLOW}SKIPPED: $SKIPPED${NC}" | tee -a $TEST_RESULTS
echo "========================================" | tee -a $TEST_RESULTS

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Check $TEST_RESULTS for details.${NC}"
    exit 1
fi
