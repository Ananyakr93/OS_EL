#!/bin/bash
# ============================================================
# Dashboard UI Test Script
# ============================================================
# Tests the Flask dashboard functionality
# Usage: ./tests/test_dashboard.sh
# Requires: Python 3, Flask, curl
# ============================================================

set -e

DASHBOARD_URL="http://localhost:5000"
PID_FILE="/tmp/encfs_dashboard.pid"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }

cleanup() {
    if [ -f "$PID_FILE" ]; then
        kill $(cat $PID_FILE) 2>/dev/null || true
        rm -f $PID_FILE
    fi
}
trap cleanup EXIT

echo "=== Dashboard UI Tests ==="

# Start dashboard
echo "Starting dashboard..."
# Ensure clean state
fusermount3 -u -q mnt || true
cd dashboard
python3 app.py &
DASHBOARD_PID=$!
echo $DASHBOARD_PID > $PID_FILE
cd ..
sleep 3

# Test 1: Index Page
echo "Test 1: Index page loads"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" $DASHBOARD_URL/)
if [ "$HTTP_CODE" == "200" ]; then
    log_pass "Index page returns 200"
else
    log_fail "Index page returned $HTTP_CODE"
fi

# Test 2: Status API
echo "Test 2: Status API"
STATUS=$(curl -s $DASHBOARD_URL/api/status)
if echo "$STATUS" | grep -q "mounted"; then
    log_pass "Status API returns JSON with 'mounted' field"
else
    log_fail "Status API malformed: $STATUS"
fi

# Test 3: Files API
echo "Test 3: Files API"
FILES=$(curl -s $DASHBOARD_URL/api/files)
if echo "$FILES" | grep -q "\["; then
    log_pass "Files API returns array"
else
    log_fail "Files API malformed: $FILES"
fi

# Test 4: Perf API
echo "Test 4: Performance API"
PERF=$(curl -s $DASHBOARD_URL/api/perf)
if echo "$PERF" | grep -q "\["; then
    log_pass "Perf API returns array"
else
    log_fail "Perf API malformed: $PERF"
fi

# Test 5: Static CSS
echo "Test 5: Static CSS loads"
CSS_CODE=$(curl -s -o /dev/null -w "%{http_code}" $DASHBOARD_URL/static/css/style.css)
if [ "$CSS_CODE" == "200" ]; then
    log_pass "CSS file loads"
else
    log_fail "CSS file returned $CSS_CODE"
fi

# Test 6: Static JS
echo "Test 6: Static JS loads"
JS_CODE=$(curl -s -o /dev/null -w "%{http_code}" $DASHBOARD_URL/static/js/script.js)
if [ "$JS_CODE" == "200" ]; then
    log_pass "JS file loads"
else
    log_fail "JS file returned $JS_CODE"
fi

# Test 7: Mount API (POST) - should work even if mount fails (graceful)
echo "Test 7: Mount API (POST)"
MOUNT_RESP=$(curl -s -X POST -H "Content-Type: application/json" \
    -d '{"passphrase":"test","mode":"secure"}' \
    $DASHBOARD_URL/api/mount)
if echo "$MOUNT_RESP" | grep -q "success"; then
    log_pass "Mount API returns success field"
else
    log_fail "Mount API malformed: $MOUNT_RESP"
fi

# Test 8: Policy API (POST)
echo "Test 8: Policy API (POST)"
POLICY_RESP=$(curl -s -X POST -H "Content-Type: application/json" \
    -d '{"filename":"test.txt","policy":"Speed"}' \
    $DASHBOARD_URL/api/policy)
if echo "$POLICY_RESP" | grep -q "success\|error"; then
    log_pass "Policy API returns success/error field"
else
    log_fail "Policy API malformed: $POLICY_RESP"
fi

# Test 9: Check for JS errors in HTML
echo "Test 9: No obvious JS errors in HTML"
HTML=$(curl -s $DASHBOARD_URL/)
if echo "$HTML" | grep -q "switchTab" && echo "$HTML" | grep -q "initChart"; then
    log_pass "HTML contains required JS function calls"
else
    log_fail "HTML missing required JS functions"
fi

# Test 10: Analytics tab exists
echo "Test 10: Analytics tab in HTML"
if echo "$HTML" | grep -q "tab-analytics"; then
    log_pass "Analytics tab present"
else
    log_fail "Analytics tab missing"
fi

# Test 11: Education tab exists
echo "Test 11: Education tab in HTML"
if echo "$HTML" | grep -q "tab-education"; then
    log_pass "Education tab present"
else
    log_fail "Education tab missing"
fi

echo ""
echo "=== All Dashboard Tests Passed ==="
