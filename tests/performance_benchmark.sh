#!/bin/bash
# ============================================================
# Performance Benchmark Suite for EncFS Novelty Validation
# ============================================================
# Purpose: Generate concrete numbers for viva defense
# Compares: Secure vs Speed vs Plain ext4 vs eCryptfs (if available)
# ============================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
ENCFS_BIN=./encfs
MOUNT_POINT=./mnt_bench
CIPHER_DIR=./cipher_bench
PASSPHRASE="benchmarkpassword123"
RESULTS_DIR=./benchmark_results
RESULTS_CSV=$RESULTS_DIR/performance_results.csv
PERF_LOG=encfs_perf.log
BENCH_LOG=benchmark_progress.log
TEST_SIZE_MB=${1:-1024}  # Default 1GB

# Test file paths
ECRYPTFS_MNT=/tmp/ecryptfs_mnt
PLAIN_DIR=/tmp/plain_bench

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}EncFS Performance Benchmarking Suite${NC}"
echo -e "${CYAN}========================================${NC}"
echo -e "Test Size: ${TEST_SIZE_MB}MB"
echo -e "Date: $(date)"
echo ""

# Create results directory
mkdir -p $RESULTS_DIR

# Redirect output to log file (and tee to stdout if interactive, but here just log)
echo "Benchmark starting at $(date)" > $BENCH_LOG
exec > >(tee -a $BENCH_LOG) 2>&1

# Initialize CSV with headers
echo "Scenario,Mode,Operation,Size_MB,Throughput_MBps,Latency_ms,CPU_User_pct,CPU_Sys_pct,Integrity_Checked,ZK_Proof_Generated" > $RESULTS_CSV

# ============================================================
# Helper Functions
# ============================================================
cleanup() {
    echo -e "${YELLOW}[CLEANUP]${NC} Unmounting filesystems..."
    fusermount -u $MOUNT_POINT 2>/dev/null || true
    sudo umount $ECRYPTFS_MNT 2>/dev/null || true
    rm -rf $MOUNT_POINT $CIPHER_DIR
    rm -rf $ECRYPTFS_MNT $PLAIN_DIR
    pkill -f "encfs.*$CIPHER_DIR" 2>/dev/null || true
    sleep 1
}

setup_encfs() {
    local mode=$1
    cleanup
    mkdir -p $MOUNT_POINT $CIPHER_DIR
    $ENCFS_BIN $CIPHER_DIR $MOUNT_POINT -o passphrase=$PASSPHRASE,mode=$mode > $PERF_LOG 2>&1 &
    sleep 2
    
    if ! grep -qs "$MOUNT_POINT" /proc/mounts; then
        echo -e "${RED}[ERROR]${NC} EncFS mount failed for mode: $mode"
        return 1
    fi
    echo -e "${GREEN}[OK]${NC} EncFS mounted in $mode mode"
}

setup_ecryptfs() {
    mkdir -p $ECRYPTFS_MNT
    mkdir -p /tmp/ecryptfs_backing
    
    # Check if ecryptfs is available
    if ! command -v ecryptfs-add-passphrase &> /dev/null; then
        echo -e "${YELLOW}[SKIP]${NC} eCryptfs not available"
        return 1
    fi
    
    # Simple ecryptfs mount (may require kernel module)
    echo "$PASSPHRASE" | ecryptfs-add-passphrase --fnek 2>/dev/null || true
    sudo mount -t ecryptfs /tmp/ecryptfs_backing $ECRYPTFS_MNT \
        -o ecryptfs_cipher=aes,ecryptfs_key_bytes=32,ecryptfs_passthrough=n,no_sig_cache,ecryptfs_enable_filename_crypto=n 2>/dev/null || return 1
    
    echo -e "${GREEN}[OK]${NC} eCryptfs mounted"
    return 0
}

setup_plain() {
    mkdir -p $PLAIN_DIR
    echo -e "${GREEN}[OK]${NC} Plain directory ready at $PLAIN_DIR"
}

# Parse perf log to get CPU stats
parse_perf_log() {
    local op_type=$1
    local log_file=$2
    
    if [ ! -f "$log_file" ]; then
        echo "0,0"
        return
    fi
    
    # Calculate averages from perf log
    awk -F',' -v op="$op_type" '
        /Op:/ && $0 ~ op {
            gsub(/[^0-9.]/, "", $2); latency += $2; 
            gsub(/[^0-9.]/, "", $3); user += $3;
            gsub(/[^0-9.]/, "", $4); sys += $4;
            count++
        }
        END {
            if (count > 0) {
                printf "%.2f,%.2f", (user/count)*100, (sys/count)*100
            } else {
                print "0,0"
            }
        }
    ' "$log_file"
}

# Run dd benchmark and capture throughput
run_dd_benchmark() {
    local target_dir=$1
    local test_file="$target_dir/benchmark_file.bin"
    local size_mb=$2
    local operation=$3  # "write" or "read"
    
    if [ "$operation" == "write" ]; then
        # Drop caches before write test
        sync; echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null 2>&1 || true
        
        # Timed write
        local output=$(dd if=/dev/zero of="$test_file" bs=1M count=$size_mb conv=fdatasync 2>&1)
        local throughput=$(echo "$output" | grep -oP '[\d.]+\s*[MG]B/s' | head -1 | sed 's/ //g')
        
        # Also measure with random data for more realistic crypto load
        # dd if=/dev/urandom of="$test_file" bs=1M count=$size_mb conv=fdatasync 2>&1
    else
        # Drop caches before read test
        sync; echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null 2>&1 || true
        
        local output=$(dd if="$test_file" of=/dev/null bs=1M 2>&1)
        local throughput=$(echo "$output" | grep -oP '[\d.]+\s*[MG]B/s' | head -1 | sed 's/ //g')
    fi
    
    # Parse throughput value (handle GB/s vs MB/s)
    if echo "$throughput" | grep -qi "GB"; then
        throughput=$(echo "$throughput" | sed 's/[^0-9.]//g')
        throughput=$(echo "$throughput * 1024" | bc)
    else
        throughput=$(echo "$throughput" | sed 's/[^0-9.]//g')
    fi
    
    echo "${throughput:-0}"
}

# Run fio benchmark for random I/O
run_fio_benchmark() {
    local target_dir=$1
    local operation=$2  # "randread" or "randwrite"
    local block_size=${3:-4k}
    
    if ! command -v fio &> /dev/null; then
        echo "0,0"
        return
    fi
    
    local output=$(fio --name=test --directory="$target_dir" --size=64M \
        --rw=$operation --bs=$block_size --direct=1 --numjobs=1 \
        --time_based --runtime=10 --group_reporting --output-format=json 2>/dev/null)
    
    # Parse JSON output for IOPS and latency
    local iops=$(echo "$output" | jq -r '.jobs[0].'"${operation}"'.iops' 2>/dev/null || echo "0")
    local lat_ns=$(echo "$output" | jq -r '.jobs[0].'"${operation}"'.lat_ns.mean' 2>/dev/null || echo "0")
    local lat_ms=$(echo "scale=3; $lat_ns / 1000000" | bc 2>/dev/null || echo "0")
    
    # Calculate throughput: IOPS * block_size (in KB) / 1024 = MB/s
    local bs_kb=$(echo "$block_size" | sed 's/k//i')
    local throughput=$(echo "scale=2; $iops * $bs_kb / 1024" | bc 2>/dev/null || echo "0")
    
    echo "${throughput:-0},${lat_ms:-0}"
}

# ============================================================
# Benchmark Tests
# ============================================================

run_sequential_benchmark() {
    local mode=$1
    local target_dir=$2
    local scenario_name=$3
    local integrity_check=$4
    local zk_proof=$5
    
    echo -e "${BLUE}[BENCH]${NC} Sequential benchmark: $scenario_name ($mode mode)"
    
    # Clear perf log
    > $PERF_LOG
    
    # Sequential Write
    local start_time=$(date +%s.%N)
    local write_throughput=$(run_dd_benchmark "$target_dir" $TEST_SIZE_MB "write")
    local end_time=$(date +%s.%N)
    local write_latency=$(echo "scale=3; ($end_time - $start_time) / ($TEST_SIZE_MB * 256) * 1000" | bc)  # per 4KB block
    
    local cpu_stats=$(parse_perf_log "write" $PERF_LOG)
    local cpu_user=$(echo $cpu_stats | cut -d',' -f1)
    local cpu_sys=$(echo $cpu_stats | cut -d',' -f2)
    
    echo "$scenario_name,$mode,Sequential_Write,$TEST_SIZE_MB,$write_throughput,$write_latency,$cpu_user,$cpu_sys,$integrity_check,$zk_proof" >> $RESULTS_CSV
    
    echo -e "  Write: ${GREEN}${write_throughput} MB/s${NC}, Latency: ${write_latency} ms/op"
    
    # Sequential Read
    > $PERF_LOG
    start_time=$(date +%s.%N)
    local read_throughput=$(run_dd_benchmark "$target_dir" $TEST_SIZE_MB "read")
    end_time=$(date +%s.%N)
    local read_latency=$(echo "scale=3; ($end_time - $start_time) / ($TEST_SIZE_MB * 256) * 1000" | bc)
    
    cpu_stats=$(parse_perf_log "read" $PERF_LOG)
    cpu_user=$(echo $cpu_stats | cut -d',' -f1)
    cpu_sys=$(echo $cpu_stats | cut -d',' -f2)
    
    echo "$scenario_name,$mode,Sequential_Read,$TEST_SIZE_MB,$read_throughput,$read_latency,$cpu_user,$cpu_sys,$integrity_check,$zk_proof" >> $RESULTS_CSV
    
    echo -e "  Read:  ${GREEN}${read_throughput} MB/s${NC}, Latency: ${read_latency} ms/op"
}

run_random_benchmark() {
    local mode=$1
    local target_dir=$2
    local scenario_name=$3
    local integrity_check=$4
    local zk_proof=$5
    
    echo -e "${BLUE}[BENCH]${NC} Random 4KB benchmark: $scenario_name ($mode mode)"
    
    if command -v fio &> /dev/null; then
        # Random Write
        local result=$(run_fio_benchmark "$target_dir" "randwrite" "4k")
        local write_throughput=$(echo $result | cut -d',' -f1)
        local write_latency=$(echo $result | cut -d',' -f2)
        
        echo "$scenario_name,$mode,Random_4K_Write,64,$write_throughput,$write_latency,0,0,$integrity_check,$zk_proof" >> $RESULTS_CSV
        echo -e "  4K RandWrite: ${GREEN}${write_throughput} MB/s${NC}, Latency: ${write_latency} ms"
        
        # Random Read
        result=$(run_fio_benchmark "$target_dir" "randread" "4k")
        local read_throughput=$(echo $result | cut -d',' -f1)
        local read_latency=$(echo $result | cut -d',' -f2)
        
        echo "$scenario_name,$mode,Random_4K_Read,64,$read_throughput,$read_latency,0,0,$integrity_check,$zk_proof" >> $RESULTS_CSV
        echo -e "  4K RandRead:  ${GREEN}${read_throughput} MB/s${NC}, Latency: ${read_latency} ms"
    else
        echo -e "${YELLOW}[SKIP]${NC} fio not available, using dd fallback for random I/O simulation"
        
        # Fallback: multiple small dd operations
        local start_time=$(date +%s.%N)
        for i in {1..100}; do
            dd if=/dev/urandom of="$target_dir/small_$i.bin" bs=4096 count=1 2>/dev/null
        done
        local end_time=$(date +%s.%N)
        local elapsed=$(echo "scale=3; $end_time - $start_time" | bc)
        local throughput=$(echo "scale=2; 100 * 4 / 1024 / $elapsed" | bc)  # 100 files * 4KB / time
        local latency=$(echo "scale=3; $elapsed / 100 * 1000" | bc)
        
        echo "$scenario_name,$mode,Random_4K_Write,0.4,$throughput,$latency,0,0,$integrity_check,$zk_proof" >> $RESULTS_CSV
        echo -e "  4K Writes (100 files): ${GREEN}${throughput} MB/s${NC}, Latency: ${latency} ms/op"
    fi
}

run_policy_benchmark() {
    echo -e "${BLUE}[BENCH]${NC} HEAD:100 Policy benchmark (Mixed mode)"
    
    setup_encfs "secure"
    local test_file="$MOUNT_POINT/policy_test.bin"
    
    # Set HEAD:100 policy - first 100 blocks (400KB) encrypted, rest not
    echo "initial" > "$test_file"
    
    if command -v setfattr &> /dev/null; then
        setfattr -n user.enc_policy -v "HEAD:100" "$test_file" 2>/dev/null || true
    fi
    
    # Write 1MB file spanning policy boundary
    > $PERF_LOG
    local start_time=$(date +%s.%N)
    dd if=/dev/zero of="$test_file" bs=1M count=1 conv=fdatasync 2>/dev/null
    local end_time=$(date +%s.%N)
    local elapsed=$(echo "scale=3; $end_time - $start_time" | bc)
    local throughput=$(echo "scale=2; 1 / $elapsed" | bc)
    local latency=$(echo "scale=3; $elapsed * 1000" | bc)
    
    echo "HEAD_100_Policy,Mixed,Sequential_Write,1,$throughput,$latency,0,0,Partial,Partial" >> $RESULTS_CSV
    echo -e "  HEAD:100 Write: ${GREEN}${throughput} MB/s${NC}, Latency: ${latency} ms"
    
    # Read
    start_time=$(date +%s.%N)
    dd if="$test_file" of=/dev/null bs=1M 2>/dev/null
    end_time=$(date +%s.%N)
    elapsed=$(echo "scale=3; $end_time - $start_time" | bc)
    throughput=$(echo "scale=2; 1 / $elapsed" | bc)
    latency=$(echo "scale=3; $elapsed * 1000" | bc)
    
    echo "HEAD_100_Policy,Mixed,Sequential_Read,1,$throughput,$latency,0,0,Partial,Partial" >> $RESULTS_CSV
    echo -e "  HEAD:100 Read:  ${GREEN}${throughput} MB/s${NC}, Latency: ${latency} ms"
    
    cleanup
}

# ============================================================
# Main Benchmark Execution
# ============================================================

trap cleanup EXIT

# Build project first
echo -e "${YELLOW}[BUILD]${NC} Building EncFS..."
make clean && make

echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}Starting Benchmarks${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

# 1. EncFS Secure Mode
echo -e "${CYAN}--- EncFS Secure Mode (AES-GCM + Integrity) ---${NC}"
setup_encfs "secure"
run_sequential_benchmark "Secure" "$MOUNT_POINT" "EncFS_Secure" "Yes" "Yes (mock)"
run_random_benchmark "Secure" "$MOUNT_POINT" "EncFS_Secure" "Yes" "Yes (mock)"
cleanup
echo ""

# 2. EncFS Speed Mode
echo -e "${CYAN}--- EncFS Speed Mode (AES-CTR + Superblocks) ---${NC}"
setup_encfs "speed"
run_sequential_benchmark "Speed" "$MOUNT_POINT" "EncFS_Speed" "No" "No"
run_random_benchmark "Speed" "$MOUNT_POINT" "EncFS_Speed" "No" "No"
cleanup
echo ""

# 3. Plain ext4 Baseline
echo -e "${CYAN}--- Plain ext4 (Baseline) ---${NC}"
setup_plain
run_sequential_benchmark "Baseline" "$PLAIN_DIR" "Plain_ext4" "No" "No"
run_random_benchmark "Baseline" "$PLAIN_DIR" "Plain_ext4" "No" "No"
rm -rf $PLAIN_DIR
echo ""

# 4. eCryptfs (if available)
echo -e "${CYAN}--- eCryptfs (Comparison) ---${NC}"
if setup_ecryptfs; then
    run_sequential_benchmark "eCryptfs" "$ECRYPTFS_MNT" "eCryptfs" "Yes" "No"
    run_random_benchmark "eCryptfs" "$ECRYPTFS_MNT" "eCryptfs" "Yes" "No"
    sudo umount $ECRYPTFS_MNT 2>/dev/null || true
else
    echo -e "${YELLOW}[SKIP]${NC} eCryptfs benchmarks skipped (not available)"
    echo "eCryptfs,N/A,Sequential_Write,$TEST_SIZE_MB,N/A,N/A,N/A,N/A,Yes,No" >> $RESULTS_CSV
    echo "eCryptfs,N/A,Sequential_Read,$TEST_SIZE_MB,N/A,N/A,N/A,N/A,Yes,No" >> $RESULTS_CSV
fi
echo ""

# 5. HEAD:100 Policy Mix
echo -e "${CYAN}--- HEAD:100 Policy (Mixed Mode) ---${NC}"
run_policy_benchmark
echo ""

# ============================================================
# Summary Report
# ============================================================

echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}Benchmark Complete!${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""
echo "Results saved to: $RESULTS_CSV"
echo ""
echo -e "${GREEN}CSV Contents:${NC}"
cat $RESULTS_CSV | column -t -s','
echo ""
echo "To generate graphs, run: python3 tests/generate_perf_graphs.py"
