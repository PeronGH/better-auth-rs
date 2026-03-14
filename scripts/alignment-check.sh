#!/usr/bin/env bash
# alignment-check.sh — Single-command alignment check for better-auth-rs.
#
# Builds the Rust workspace, starts the TS reference server, runs
# dual-server comparison tests, and prints a pass/fail summary.
#
# Usage:
#   ./scripts/alignment-check.sh          # full check
#   ./scripts/alignment-check.sh --skip-build   # skip cargo build
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REF_SERVER_DIR="$PROJECT_ROOT/compat-tests/reference-server"
REF_PORT=3100
REF_PID=""
SKIP_BUILD=false

# Parse arguments
for arg in "$@"; do
  case "$arg" in
    --skip-build) SKIP_BUILD=true ;;
    *) echo "Unknown argument: $arg"; exit 1 ;;
  esac
done

# ---------------------------------------------------------------------------
# Cleanup — always kill the reference server on exit
# ---------------------------------------------------------------------------
cleanup() {
  if [[ -n "$REF_PID" ]] && kill -0 "$REF_PID" 2>/dev/null; then
    echo "[alignment] Stopping reference server (PID $REF_PID)..."
    kill "$REF_PID" 2>/dev/null || true
    wait "$REF_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------
echo "=== Alignment Check ==="
echo ""
echo "[preflight] Checking prerequisites..."

if ! command -v node &>/dev/null; then
  echo "ERROR: node is not available. Install Node.js and try again."
  exit 1
fi
echo "  node $(node --version) ✓"

if ! command -v cargo &>/dev/null; then
  echo "ERROR: cargo is not available. Install Rust and try again."
  exit 1
fi
echo "  cargo $(cargo --version | awk '{print $2}') ✓"

if [[ ! -d "$REF_SERVER_DIR/node_modules" ]]; then
  echo "ERROR: Reference server dependencies not installed."
  echo "  Run: cd compat-tests/reference-server && npm install"
  exit 1
fi
echo "  reference-server node_modules ✓"

if [[ ! -f "$PROJECT_ROOT/better-auth.yaml" ]]; then
  echo "WARNING: better-auth.yaml not found in workspace root."
fi

echo ""

# ---------------------------------------------------------------------------
# Step 1: Build the Rust workspace
# ---------------------------------------------------------------------------
if [[ "$SKIP_BUILD" == "true" ]]; then
  echo "[1/5] Skipping build (--skip-build)"
else
  echo "[1/5] Building Rust workspace..."
  cd "$PROJECT_ROOT"
  if ! cargo build --workspace 2>&1; then
    echo ""
    echo "FAIL: Rust workspace failed to build."
    exit 1
  fi
  echo "  Build succeeded ✓"
fi
echo ""

# ---------------------------------------------------------------------------
# Step 2: Start the TS reference server
# ---------------------------------------------------------------------------
echo "[2/5] Starting TS reference server on port $REF_PORT..."

# Kill any existing process on the port
if command -v lsof &>/dev/null; then
  EXISTING_PID=$(lsof -ti :"$REF_PORT" 2>/dev/null || true)
  if [[ -n "$EXISTING_PID" ]]; then
    echo "  Killing existing process on port $REF_PORT (PID $EXISTING_PID)"
    kill "$EXISTING_PID" 2>/dev/null || true
    sleep 1
  fi
fi

cd "$REF_SERVER_DIR"
PORT=$REF_PORT node server.mjs &
REF_PID=$!
cd "$PROJECT_ROOT"

# Wait for readiness (up to 15 seconds)
echo "  Waiting for reference server to become ready..."
READY=false
for i in $(seq 1 30); do
  if curl -sf "http://localhost:$REF_PORT/__health" >/dev/null 2>&1; then
    READY=true
    break
  fi
  sleep 0.5
done

if [[ "$READY" != "true" ]]; then
  echo "FAIL: Reference server did not become ready within 15 seconds."
  exit 1
fi
echo "  Reference server ready (PID $REF_PID) ✓"
echo ""

# ---------------------------------------------------------------------------
# Step 3: Run dual-server comparison tests
# ---------------------------------------------------------------------------
echo "[3/5] Running dual-server comparison tests..."
cd "$PROJECT_ROOT"

DUAL_EXIT=0
cargo test --test dual_server_tests -- --nocapture 2>&1 | tee /tmp/alignment-dual.log || DUAL_EXIT=$?

if [[ "$DUAL_EXIT" -ne 0 ]]; then
  echo "  Dual-server tests: FAIL (exit $DUAL_EXIT)"
else
  echo "  Dual-server tests: PASS ✓"
fi
echo ""

# ---------------------------------------------------------------------------
# Step 4: Run spec coverage report
# ---------------------------------------------------------------------------
echo "[4/5] Running spec-driven compatibility tests..."

COMPAT_EXIT=0
cargo test --test compat_endpoint_tests -- --nocapture 2>&1 | tee /tmp/alignment-compat.log || COMPAT_EXIT=$?

if [[ "$COMPAT_EXIT" -ne 0 ]]; then
  echo "  Compat endpoint tests: FAIL (exit $COMPAT_EXIT)"
else
  echo "  Compat endpoint tests: PASS ✓"
fi

COVERAGE_EXIT=0
cargo test --test compat_coverage_tests -- --nocapture 2>&1 | tee /tmp/alignment-coverage.log || COVERAGE_EXIT=$?

if [[ "$COVERAGE_EXIT" -ne 0 ]]; then
  echo "  Coverage tests: FAIL (exit $COVERAGE_EXIT)"
else
  echo "  Coverage tests: PASS ✓"
fi
echo ""

# ---------------------------------------------------------------------------
# Step 5: Summary
# ---------------------------------------------------------------------------
echo "====================================="
echo "       Alignment Check Summary"
echo "====================================="

TOTAL_FAIL=0

report_result() {
  local name="$1"
  local code="$2"
  if [[ "$code" -eq 0 ]]; then
    echo "  [PASS] $name"
  else
    echo "  [FAIL] $name"
    TOTAL_FAIL=$((TOTAL_FAIL + 1))
  fi
}

report_result "Dual-server comparison" "$DUAL_EXIT"
report_result "Spec endpoint validation" "$COMPAT_EXIT"
report_result "Route coverage" "$COVERAGE_EXIT"

echo ""
if [[ "$TOTAL_FAIL" -eq 0 ]]; then
  echo "Result: ALL CHECKS PASSED ✓"
  echo ""
  exit 0
else
  echo "Result: $TOTAL_FAIL CHECK(S) FAILED ✗"
  echo ""
  echo "Logs:"
  echo "  /tmp/alignment-dual.log"
  echo "  /tmp/alignment-compat.log"
  echo "  /tmp/alignment-coverage.log"
  echo ""
  exit 1
fi
