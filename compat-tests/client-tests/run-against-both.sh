#!/usr/bin/env bash
# run-against-both.sh — Run client integration tests against both TS and Rust servers.
#
# Usage:
#   bash run-against-both.sh              # build Rust, start both, test both
#   bash run-against-both.sh --skip-build # skip cargo build
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REF_SERVER_DIR="$PROJECT_ROOT/compat-tests/reference-server"
RUST_SERVER_DIR="$PROJECT_ROOT/compat-tests/rust-server"
CLIENT_DIR="$SCRIPT_DIR"

TS_PORT=3100
RUST_PORT=3200
TS_PID=""
RUST_PID=""
SKIP_BUILD=false
LOCAL_NO_PROXY="localhost,127.0.0.1"

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
# Cleanup
# ---------------------------------------------------------------------------
cleanup() {
  if [[ -n "$TS_PID" ]] && kill -0 "$TS_PID" 2>/dev/null; then
    kill "$TS_PID" 2>/dev/null || true
    wait "$TS_PID" 2>/dev/null || true
  fi
  if [[ -n "$RUST_PID" ]] && kill -0 "$RUST_PID" 2>/dev/null; then
    kill "$RUST_PID" 2>/dev/null || true
    wait "$RUST_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
echo "=== Client Integration Tests ==="
echo ""

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

require_node_modules "$REF_SERVER_DIR" "reference-server"
echo "  reference-server deps ✓"

require_node_modules "$CLIENT_DIR" "client-tests"
echo "  client-tests deps ✓"
echo ""

# ---------------------------------------------------------------------------
# Build Rust server
# ---------------------------------------------------------------------------
if [[ "$SKIP_BUILD" == "true" ]]; then
  echo "[1/5] Skipping Rust build (--skip-build)"
else
  echo "[1/5] Building Rust compat server..."
  cd "$PROJECT_ROOT"
  if ! cargo build --manifest-path "$RUST_SERVER_DIR/Cargo.toml" 2>&1; then
    echo "FAIL: Rust compat server failed to build."
    exit 1
  fi
  echo "  Build succeeded ✓"
fi
echo ""

# ---------------------------------------------------------------------------
# Start TS reference server
# ---------------------------------------------------------------------------
echo "[2/5] Starting TS reference server on port $TS_PORT..."
cd "$REF_SERVER_DIR"
PORT=$TS_PORT node server.mjs &
TS_PID=$!
cd "$PROJECT_ROOT"

READY=false
if wait_for_local_health "$TS_PORT"; then
  READY=true
fi

if [[ "$READY" != "true" ]]; then
  echo "FAIL: TS reference server did not become ready."
  exit 1
fi
echo "  TS server ready (PID $TS_PID) ✓"
echo ""

# ---------------------------------------------------------------------------
# Start Rust server
# ---------------------------------------------------------------------------
echo "[3/5] Starting Rust compat server on port $RUST_PORT..."
cd "$PROJECT_ROOT"
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
  echo "FAIL: Rust compat server did not become ready within 30s."
  exit 1
fi
echo "  Rust server ready (PID $RUST_PID) ✓"
echo ""

# ---------------------------------------------------------------------------
# Run tests against TS
# ---------------------------------------------------------------------------
echo "[4/5] Running client tests against TS server..."
cd "$CLIENT_DIR"
TS_EXIT=0
NO_PROXY="$LOCAL_NO_PROXY" no_proxy="$LOCAL_NO_PROXY" AUTH_BASE_URL="http://localhost:$TS_PORT" node --test tests/*.test.mjs 2>&1 | tee /tmp/client-test-ts.log || TS_EXIT=$?

if [[ "$TS_EXIT" -eq 0 ]]; then
  echo "  TS tests: PASS ✓"
else
  echo "  TS tests: FAIL (exit $TS_EXIT)"
fi
echo ""

# ---------------------------------------------------------------------------
# Run tests against Rust
# ---------------------------------------------------------------------------
echo "[5/5] Running client tests against Rust server..."
RUST_EXIT=0
NO_PROXY="$LOCAL_NO_PROXY" no_proxy="$LOCAL_NO_PROXY" AUTH_BASE_URL="http://localhost:$RUST_PORT" node --test tests/*.test.mjs 2>&1 | tee /tmp/client-test-rust.log || RUST_EXIT=$?

if [[ "$RUST_EXIT" -eq 0 ]]; then
  echo "  Rust tests: PASS ✓"
else
  echo "  Rust tests: FAIL (exit $RUST_EXIT)"
fi
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "====================================="
echo "    Client Integration Test Summary"
echo "====================================="

TOTAL_FAIL=0

if [[ "$TS_EXIT" -eq 0 ]]; then
  echo "  [PASS] TS reference server"
else
  echo "  [FAIL] TS reference server"
  TOTAL_FAIL=$((TOTAL_FAIL + 1))
fi

if [[ "$RUST_EXIT" -eq 0 ]]; then
  echo "  [PASS] Rust compat server"
else
  echo "  [FAIL] Rust compat server"
  TOTAL_FAIL=$((TOTAL_FAIL + 1))
fi

echo ""
if [[ "$TOTAL_FAIL" -eq 0 ]]; then
  echo "Result: BOTH SERVERS PASS ✓"
  exit 0
else
  echo "Result: $TOTAL_FAIL SERVER(S) FAILED ✗"
  echo ""
  echo "Logs:"
  echo "  /tmp/client-test-ts.log"
  echo "  /tmp/client-test-rust.log"
  exit 1
fi
