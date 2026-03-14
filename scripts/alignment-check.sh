#!/usr/bin/env bash
# alignment-check.sh — Single-command alignment check for better-auth-rs.
#
# Builds the Rust workspace, starts the TS reference server, runs
# dual-server comparison tests, client integration tests, and prints
# a pass/fail summary.
#
# Usage:
#   ./scripts/alignment-check.sh          # full check
#   ./scripts/alignment-check.sh --skip-build   # skip cargo build
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REF_SERVER_DIR="$PROJECT_ROOT/compat-tests/reference-server"
RUST_SERVER_DIR="$PROJECT_ROOT/compat-tests/rust-server"
CLIENT_DIR="$PROJECT_ROOT/compat-tests/client-tests"
REF_PORT=3100
RUST_PORT=3200
REF_PID=""
RUST_PID=""
SKIP_BUILD=false
LOCAL_NO_PROXY="localhost,127.0.0.1"

# Parse arguments
for arg in "$@"; do
  case "$arg" in
    --skip-build) SKIP_BUILD=true ;;
    *) echo "Unknown argument: $arg"; exit 1 ;;
  esac
done

require_node_modules() {
  local dir="$1"
  local label="$2"

  if [[ ! -d "$dir/node_modules" ]]; then
    echo "ERROR: $label dependencies are not installed."
    echo "Run: cd \"$dir\" && bun install"
    exit 1
  fi
}

wait_for_local_health() {
  local port="$1"

  for _ in $(seq 1 30); do
    if curl --noproxy '*' -sf "http://127.0.0.1:$port/__health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done

  return 1
}

# ---------------------------------------------------------------------------
# Cleanup — always kill servers on exit
# ---------------------------------------------------------------------------
cleanup() {
  if [[ -n "$REF_PID" ]] && kill -0 "$REF_PID" 2>/dev/null; then
    echo "[alignment] Stopping reference server (PID $REF_PID)..."
    kill "$REF_PID" 2>/dev/null || true
    wait "$REF_PID" 2>/dev/null || true
  fi
  if [[ -n "$RUST_PID" ]] && kill -0 "$RUST_PID" 2>/dev/null; then
    echo "[alignment] Stopping Rust compat server (PID $RUST_PID)..."
    kill "$RUST_PID" 2>/dev/null || true
    wait "$RUST_PID" 2>/dev/null || true
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

if ! command -v bun &>/dev/null; then
  echo "ERROR: bun is not available. Install Bun and try again."
  exit 1
fi
echo "  bun $(bun --version) ✓"

if ! command -v cargo &>/dev/null; then
  echo "ERROR: cargo is not available. Install Rust and try again."
  exit 1
fi
echo "  cargo $(cargo --version | awk '{print $2}') ✓"

require_node_modules "$REF_SERVER_DIR" "reference-server"
echo "  reference-server deps ✓"

require_node_modules "$CLIENT_DIR" "client-tests"
echo "  client-tests deps ✓"

if [[ ! -f "$PROJECT_ROOT/better-auth.yaml" ]]; then
  echo "WARNING: better-auth.yaml not found in workspace root."
fi

echo ""

# ---------------------------------------------------------------------------
# Step 1: Build the Rust workspace
# ---------------------------------------------------------------------------
if [[ "$SKIP_BUILD" == "true" ]]; then
  echo "[1/6] Skipping build (--skip-build)"
else
  echo "[1/6] Building Rust workspace..."
  cd "$PROJECT_ROOT"
  if ! cargo build --workspace 2>&1; then
    echo ""
    echo "FAIL: Rust workspace failed to build."
    exit 1
  fi
  # Also build the compat server
  if ! cargo build --manifest-path "$RUST_SERVER_DIR/Cargo.toml" 2>&1; then
    echo ""
    echo "FAIL: Rust compat server failed to build."
    exit 1
  fi
  echo "  Build succeeded ✓"
fi
echo ""

# ---------------------------------------------------------------------------
# Step 2: Start the TS reference server
# ---------------------------------------------------------------------------
echo "[2/6] Starting TS reference server on port $REF_PORT..."

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
if wait_for_local_health "$REF_PORT"; then
  READY=true
fi

if [[ "$READY" != "true" ]]; then
  echo "FAIL: Reference server did not become ready within 15 seconds."
  exit 1
fi
echo "  Reference server ready (PID $REF_PID) ✓"
echo ""

# ---------------------------------------------------------------------------
# Step 3: Run dual-server comparison tests
# ---------------------------------------------------------------------------
echo "[3/6] Running dual-server comparison tests..."
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
echo "[4/6] Running spec-driven compatibility tests..."

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
# Step 5: Client integration tests (real better-auth client SDK)
# ---------------------------------------------------------------------------
echo "[5/6] Running client integration tests..."

# Start Rust compat server
echo "  Starting Rust compat server on port $RUST_PORT..."
if command -v lsof &>/dev/null; then
  EXISTING_PID=$(lsof -ti :"$RUST_PORT" 2>/dev/null || true)
  if [[ -n "$EXISTING_PID" ]]; then
    kill "$EXISTING_PID" 2>/dev/null || true
    sleep 1
  fi
fi

PORT=$RUST_PORT cargo run --manifest-path "$RUST_SERVER_DIR/Cargo.toml" &
RUST_PID=$!

READY=false
for _ in $(seq 1 2); do
  if wait_for_local_health "$RUST_PORT"; then
    READY=true
    break
  fi
done

if [[ "$READY" != "true" ]]; then
  echo "  WARN: Rust compat server did not become ready, skipping client tests against Rust."
  CLIENT_TS_EXIT=0
  CLIENT_RUST_EXIT=1
else
  echo "  Rust compat server ready (PID $RUST_PID) ✓"

  cd "$CLIENT_DIR"
  CLIENT_TS_EXIT=0
  NO_PROXY="$LOCAL_NO_PROXY" no_proxy="$LOCAL_NO_PROXY" AUTH_BASE_URL="http://localhost:$REF_PORT" node --test tests/*.test.mjs 2>&1 | tee /tmp/client-test-ts.log || CLIENT_TS_EXIT=$?

  CLIENT_RUST_EXIT=0
  NO_PROXY="$LOCAL_NO_PROXY" no_proxy="$LOCAL_NO_PROXY" AUTH_BASE_URL="http://localhost:$RUST_PORT" node --test tests/*.test.mjs 2>&1 | tee /tmp/client-test-rust.log || CLIENT_RUST_EXIT=$?
fi

if [[ "$CLIENT_TS_EXIT" -eq 0 ]]; then
  echo "  Client tests (TS): PASS ✓"
else
  echo "  Client tests (TS): FAIL (exit $CLIENT_TS_EXIT)"
fi

if [[ "$CLIENT_RUST_EXIT" -eq 0 ]]; then
  echo "  Client tests (Rust): PASS ✓"
else
  echo "  Client tests (Rust): FAIL (exit $CLIENT_RUST_EXIT)"
fi
echo ""

# ---------------------------------------------------------------------------
# Step 6: Summary
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
report_result "Client tests (TS)" "$CLIENT_TS_EXIT"
report_result "Client tests (Rust)" "$CLIENT_RUST_EXIT"

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
  echo "  /tmp/client-test-ts.log"
  echo "  /tmp/client-test-rust.log"
  echo ""
  exit 1
fi
