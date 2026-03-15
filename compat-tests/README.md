# Compatibility Testing Framework

This directory contains the **dual-server compatibility testing** infrastructure
for validating better-auth-rs against the canonical better-auth (TypeScript)
implementation.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  Compatibility Testing Framework                                     │
│                                                                      │
│  ┌──────────────────────┐   ┌──────────────────────────────────┐   │
│  │  Spec-Driven Tests   │   │  Dual-Server Tests               │   │
│  │  (tests/ directory)  │   │  (compat-tests/)                 │   │
│  │                      │   │                                   │   │
│  │  - OpenAPI schema    │   │  ┌─────────┐   ┌──────────────┐ │   │
│  │    auto-validation   │   │  │ Rust    │   │ Node.js ref  │ │   │
│  │  - camelCase check   │   │  │ (mem)   │   │ server       │ │   │
│  │  - Field type check  │   │  └────┬────┘   └──────┬───────┘ │   │
│  │  - Coverage report   │   │       │               │          │   │
│  └──────────────────────┘   │       └───────┬───────┘          │   │
│                              │               │                  │   │
│  better-auth.yaml            │     Response Shape Comparison    │   │
│  (OpenAPI 3.1.1 ref spec)   │                                   │   │
│                              └──────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Spec-Driven Validation (`tests/compat_endpoint_tests.rs`)

Automated tests that parse `better-auth.yaml` and validate Rust responses
against the OpenAPI spec. Runs with `cargo test`:

```bash
# Run all spec-driven compatibility tests
cargo test --test compat_endpoint_tests -- --nocapture
```

Features:
- **Schema auto-validation**: Parses OpenAPI spec schemas and validates response fields
- **`$ref` resolution**: Follows `$ref` references to component schemas
- **camelCase enforcement**: Ensures all field names use camelCase (not snake_case)
- **Route coverage analysis**: Reports what % of spec endpoints are implemented
- **Response type signatures**: Generates human-readable type docs for all endpoints
- **Cross-endpoint consistency**: Validates user/session objects are consistent across responses
- **Shape comparison engine**: Compares two JSON structures ignoring dynamic values

### 2. Existing Compatibility Tests (`tests/compatibility_tests.rs`)

Contract tests and route coverage reports against the reference spec.

### 3. Response Shape Tests (`src/tests/response_shape_tests.rs`)

Per-endpoint response shape validation tests.

### 4. Reference Server (`compat-tests/reference-server/`)

A Node.js server running the canonical better-auth (TypeScript) implementation
for dual-server comparison testing.

#### Setup

```bash
cd compat-tests/reference-server
bun install
node server.mjs  # starts on port 3100
```

The alignment scripts expect `node_modules` to already exist and fail fast with
an actionable message if either JS workspace has not been installed yet.

#### Usage

The reference server is used by the dual-server test runner to:
1. Send identical requests to both implementations
2. Compare response shapes (not exact values)
3. Report any structural differences

The phase-scoped dual-server comparison is currently split across:

- `tests/dual_server_phase0_tests.rs`
- `tests/dual_server_phase1_tests.rs`

## Test Categories

| Category | Command | Description |
|----------|---------|-------------|
| Spec validation | `cargo test --test compat_endpoint_tests -- --nocapture` | Auto-validates responses against OpenAPI spec |
| Route coverage | `cargo test --test compat_coverage_tests -- --nocapture` | Reports which spec endpoints are implemented |
| Dual-server Phase 0 | `cargo test --test dual_server_phase0_tests -- --nocapture` | Compares Phase 0 responses against TS |
| Dual-server Phase 1 | `cargo test --test dual_server_phase1_tests -- --nocapture` | Compares Phase 1 responses against TS |
| Axum integration | `cargo test --features axum --test axum_integration_tests` | Verifies mounted HTTP behavior and cookies |
| Existing compat | `cargo test --test compatibility_tests` | Route coverage + contract tests |
| Response shapes | `cargo test response_shape_tests` | Per-endpoint response shape tests |

## Adding New Tests

### Adding a new spec-driven endpoint test

Add a new section to the `test_spec_driven_endpoint_validation` test:

```rust
// --- POST /your-endpoint ---
let (status, body) = send_request(
    &auth,
    post_json_with_auth("/your-endpoint", serde_json::json!({...}), &token),
).await;
validator.validate_endpoint("/your-endpoint", "post", status, &body);
```

The validator will automatically:
1. Look up the endpoint in `better-auth.yaml`
2. Extract the expected response schema
3. Validate all required fields are present
4. Check field types match
5. Verify camelCase naming

### Adding a new shape comparison test

```rust
let diffs = compare_shapes(&reference_json, &target_json, "", false);
assert!(diffs.is_empty(), "Shape mismatch: {:?}", diffs);
```
