#!/usr/bin/env bash
set -euo pipefail

skip_build=false

for arg in "$@"; do
  case "$arg" in
    --skip-build) skip_build=true ;;
    *) echo "Unknown argument: $arg" >&2; exit 1 ;;
  esac
done

if [[ "$skip_build" != "true" ]]; then
  cargo build --workspace
  cargo build --manifest-path compat-tests/rust-server/Cargo.toml
fi

cargo test --features axum --test axum_integration_tests
cargo test --test compat_endpoint_tests -- --nocapture
cargo test --test compat_coverage_tests -- --nocapture
cargo test --test wire_compat_smoke_tests -- --nocapture
cargo test --test client_compat_tests full_client_compat -- --ignored --nocapture
