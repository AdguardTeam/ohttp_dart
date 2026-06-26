# AGENTS.md

This file provides LLM agents with project context, commands, and contribution rules.

## Project Overview

ohttp_dart is a pure Dart implementation of Oblivious HTTP (OHTTP) client based on RFC 9458.
It provides HPKE (Hybrid Public Key Encryption, RFC 9180) and BHTTP (Binary HTTP, RFC 9292)
support without native dependencies. The library is transport-agnostic in its core, with an
optional adapter for `package:http`.

## Technical Context

| Field                | Value                                                                          |
| -------------------- | ------------------------------------------------------------------------------ |
| **Language**         | Dart 3.11.1+                                                                   |
| **Crypto**           | `cryptography` 2.9.0 (pure Dart, no native dependencies)                       |
| **HTTP Client**      | `http` 1.6.0 (optional adapter)                                                |
| **Annotations**      | `meta` 1.16.0 (`@visibleForTesting`)                                           |
| **Architecture**     | Transport-agnostic core + optional `package:http` adapter                      |
| **Testing**          | `test` 1.25.6 + `kiri_check` 1.3.1 (property-based testing)                    |
| **Linting**          | `lints` 3.0.0 + Dart Code Metrics (inline in `analysis_options.yaml`)          |
| **Target Platforms** | iOS, macOS, Android, Windows                                                   |
| **Formatter**        | `line-length: 120`, `require_trailing_commas` enabled                          |
| **Strict analysis**  | `strict-casts: true`, `strict-raw-types: true`                                 |
| **Version**          | 0.1.0                                                                          |
| **Publish**          | Not published (`publish_to: none`)                                             |

## Project Structure

```
ohttp_dart/
├── lib/
│   ├── ohttp_dart.dart                   # Core library entry point (transport-agnostic)
│   ├── http.dart                         # Optional package:http adapter entry point
│   └── src/
│       ├── bhttp.dart                    # Binary HTTP (RFC 9292)
│       ├── bhttp_response_limits.dart    # Response size limits configuration
│       ├── cipher_suite.dart             # Cipher suite constants
│       ├── exceptions.dart               # Exception hierarchy
│       ├── hpke.dart                     # HPKE Base Mode Sender (RFC 9180)
│       ├── key_config_cache.dart         # TTL cache with single-flight for key configs
│       ├── ohttp.dart                    # OHTTP encap/decap + KeyConfig (RFC 9458)
│       ├── ohttp_data.dart               # Request / response data types
│       ├── ohttp_observer.dart           # Lifecycle event observer interface
│       ├── ohttp_session.dart            # OHTTP session orchestrator
│       ├── ohttp_transport.dart          # Transport abstraction interface
│       ├── erasable_byte_array.dart       # Byte buffer that zeroes on erase(), guards post-erase reads
│       └── adapters/
│           └── http/
│               ├── http_client_transport.dart   # HttpClientTransport implementation
│               └── ohttp_http_client.dart       # OhttpHttpClient drop-in replacement
├── test/                                  # Unit tests (mirrors lib/ structure)
│   ├── bhttp_test.dart                    # Includes property-based tests (kiri_check)
│   ├── erasable_byte_array_test.dart      # ErasableByteArray zeroing / post-erase guard
│   ├── hpke_test.dart                     # RFC 9180 vectors + property-based tests (kiri_check)
│   ├── key_config_cache_test.dart
│   ├── ohttp_observer_test.dart          # Observer lifecycle tests
│   ├── ohttp_session_test.dart
│   ├── ohttp_test.dart
│   ├── test_utils.dart
│   └── adapters/
│       └── http_adapter_test.dart
├── example/                               # Usage examples
│   └── ohttp_dart_example.dart
└── analysis_options.yaml                  # Linter rules, DCM config, formatter settings
```

### Core Concepts

- **OHTTP (RFC 9458)**: Oblivious HTTP protocol for privacy-preserving requests via gateway
- **HPKE (RFC 9180)**: Hybrid Public Key Encryption used for request encryption
- **BHTTP (RFC 9292)**: Binary HTTP format for serializing HTTP messages
- **Cipher Suite**: DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM
- **Key Config TTL**: Cache key configurations with configurable TTL (default 1 hour)
- **Transport Abstraction**: Core library defines interfaces, no hard dependency on HTTP client

## Build And Test Commands

All commands use FVM (Flutter Version Management) for Dart SDK management.

### Setup

| Command              | Purpose                                    |
| -------------------- | ------------------------------------------ |
| `fvm dart pub get`   | Install dependencies                       |
| `dart pub get`       | Alternative without FVM                    |

### Testing

| Command                                                        | Purpose                        |
| -------------------------------------------------------------- | ------------------------------ |
| `fvm dart test test/<file>_test.dart`                          | Run specific test file         |
| `dart test test/<file>_test.dart`                              | Alternative without FVM        |
| `fvm dart test`                                                | Run all tests                  |
| `mcp_dart_sdk_mcp__mcp__dart_sdk_mcp__run_tests`               | Run tests via MCP (preferred)  |

Use MCP tools when available for better integration and output handling.

### Code Quality

| Command                        | Purpose                                                      |
| ------------------------------ | ------------------------------------------------------------ |
| `fvm dart analyze`             | Run Dart analyzer with `--fatal-warnings --fatal-infos`     |
| `dart analyze`                 | Alternative without FVM                                      |
| `mcp_dcm_mcp_serve_dcm_analyze`| Dart Code Metrics analysis (preferred)                       |
| `fvm dart format <file>.dart`  | Format specific file                                         |
| `dart format <file>.dart`      | Alternative without FVM                                      |
| `mcp_dcm_mcp_serve_dcm_format` | Format via DCM (preferred, always specify `roots` parameter) |

**Formatting:** Always format changed files before committing. Use MCP tools when available.

### Dart MCP Tools (Agent Use)

Prefer MCP tools over shell commands when available:

| Tool                                              | Purpose                                      |
| ------------------------------------------------- | -------------------------------------------- |
| `mcp_dart_sdk_mcp__mcp__dart_sdk_mcp__format`     | Format files (preferred, specify `paths`)    |
| `mcp_dcm_mcp_serve_dcm_analyze`                   | Analyze entire project with DCM              |
| `mcp_dcm_mcp_serve_dcm_format`                    | Format files with DCM                        |
| `mcp_dart_sdk_mcp__mcp__dart_sdk_mcp__pub`        | Pub commands (add, get, remove, upgrade)      |
| `mcp_dart_sdk_mcp__mcp__dart_sdk_mcp__hover`      | Get docs/type info at position               |

### Code Generation

This project does not use code generation tools (no `build_runner`, `freezed`, etc.).

### Localization

This project does not include localization.

## Contribution Instructions

### Before Making Changes

1. Run `fvm dart pub get` to ensure dependencies are up to date.
2. Review the architecture: core library is transport-agnostic, adapters are optional.
3. Use MCP tools when available, otherwise use FVM commands. Do not invent ad hoc shell commands.
4. Follow RFC specifications for cryptographic and protocol implementations.
5. If the required workflow is missing or broken, stop and report — do not invent unsupported paths.

### After Making Changes

1. **Analyze** — use `mcp_dcm_mcp_serve_dcm_analyze` (preferred) or `fvm dart analyze`. Zero warnings/infos required.
2. **Format** — use MCP tools (preferred) or `fvm dart format <file>.dart`. Format all changed files.
3. **Test** — run relevant tests with `fvm dart test test/<file>_test.dart` or MCP equivalent.
4. **Validate** — ensure all tests pass and analyzer reports no issues.

### Dependencies

- Use **exact versions without caret** (e.g., `http: 1.6.0` not `http: ^1.6.0`).
- Sort alphabetically (SDK dependencies first, then third-party).

## Testing Requirements

Tests are **mandatory** for all non-trivial logic.

Primary command: `fvm dart test test/<file>_test.dart` or MCP equivalent.

### When Agents Must Run Tests

Run tests after any change to:

- OHTTP encapsulation/decapsulation logic (`lib/src/ohttp.dart`)
- HPKE encryption (`lib/src/hpke.dart`)
- BHTTP serialization/parsing (`lib/src/bhttp.dart`)
- Key config caching (`lib/src/key_config_cache.dart`)
- Session orchestration (`lib/src/ohttp_session.dart`)
- Observer events (`lib/src/ohttp_observer.dart`)
- Transport implementations (`lib/src/adapters/**`)

### When Agents Must Write or Update Tests

Write or update tests when:

- Adding or modifying any public API method
- Fixing a bug (write a regression test that reproduces the bug)
- Changing cryptographic implementations (verify against RFC test vectors)
- Modifying data serialization formats
- Adding or changing observer lifecycle events

**Test location** mirrors source: `test/` mirrors `lib/` structure.

**Coverage expectation**: Maintain high test coverage for cryptographic and protocol logic.

## Code Style Requirements

### Formatting

- **Line length**: 120 characters
- **Trailing commas**: Required (`require_trailing_commas: true`)
- **Strict mode**: `strict-casts: true`, `strict-raw-types: true`

### Documentation

- **RFC references**: Cite RFC section numbers in comments for protocol-specific code
- **Test vectors**: Document RFC test vector sources in test files

### Naming Conventions

- Follow standard Dart naming conventions
- Use clear, descriptive names for cryptographic operations
- Prefix private members with underscore

### Error Handling

The library uses a sealed exception hierarchy:

- `OhttpException` (sealed base) — base for all library exceptions
- `OhttpConfigException` — invalid configuration parameters (wrong URL scheme, invalid timeouts, negative limits)
- `OhttpKeyConfigException` — malformed KeyConfig binary data
- `OhttpUnsupportedSuiteException` — unsupported KEM/KDF/AEAD cipher suite
- `OhttpGatewayException` — gateway returned non-2xx response (triggers cache invalidation, includes `statusCode`)
- `OhttpCryptoException` — cryptographic operation failure (AEAD auth, HPKE errors; includes optional `cause`)
- `OhttpDecapsulationException` — OHTTP response decapsulation failure
- `OhttpFormatException` — malformed BHTTP data (wrong framing, invalid status code)
- `OhttpSizeLimitException` — response/request exceeds configured size limits (includes `limit` and `actualSize`)
- `OhttpNetworkException` — network-level error (DNS, connection, etc.; includes optional `cause`)
- `OhttpTimeoutException` — HTTP request exceeded configured timeout (includes `timeout` duration and optional `url`)

## Security Considerations

This library handles cryptographic operations. Follow these rules:

1. **Never** use random values without verification against RFC test vectors
2. **Never** modify HPKE or OHTTP implementations without extensive testing
3. **Always** validate input data before processing (nonces, keys, ciphertext)
4. **Always** use constant-time operations for sensitive comparisons
5. **Document** security assumptions and limitations

## Validation Requirements

### Definition of Done

A task is complete **only** when all of the following are true:

1. All acceptance criteria are satisfied.
2. Code passes analyzer with zero warnings/infos.
3. All relevant tests pass.
4. Code is properly formatted.
5. Public APIs have documentation.
6. No unresolved security concerns exist.

### Self-Validation Flow

After completing implementation, execute this flow **before** declaring the task done:

1. **Re-read** the task requirements or specification.
2. **Check** every acceptance criterion — confirm it is satisfied.
3. **Run** `fvm dart analyze` — must report zero issues.
4. **Run** relevant tests — all must pass.
5. **Format** all changed files.
6. **Review** cryptographic implementations against RFC specifications if applicable.

### Agent Validation Trigger Rules

| Change Type                        | Required Commands                          |
| ---------------------------------- | ------------------------------------------ |
| Any Dart code                      | `fvm dart analyze`                         |
| Protocol logic (OHTTP, HPKE, BHTTP)| `fvm dart test` (full test suite)          |
| Public API changes                 | Update documentation + run tests           |
| Cryptographic changes              | Verify against RFC test vectors            |
| Observer event changes             | Run `ohttp_observer_test.dart`             |

### Failure Handling

- **Fixable failures**: Fix and rerun the validation.
- **Cryptographic test failures**: Stop immediately. Do not modify test vectors without expert review.
- **Spec contradicts RFC**: Report the deviation and request clarification.
- **Observer test failures**: Observer must never throw; check `notifySafe()` error suppression.

## AGENTS.md Files Rules

- This root file defines global project rules.
- A local `AGENTS.md` inside a subdirectory (e.g., `lib/src/`) captures area-specific constraints.
- Read and follow a local `AGENTS.md` only when working in that area.
- Local instructions extend this root file; they do not replace or duplicate it.

## Known Patterns and Conventions

### Transport Abstraction

The core library defines `OhttpTransport` interface. Implementations:
- `HttpClientTransport` — uses `package:http`
- Custom implementations can wrap any HTTP client

### Key Config Caching

- `KeyConfigCache` provides TTL-based caching with single-flight requests
- Default TTL: 1 hour
- Cache invalidation occurs on `OhttpGatewayException` (4xx/5xx responses)

### Session Management

- `OhttpSession` orchestrates the full request/response pipeline
- Each session owns its transport and cache instances
- Sessions are NOT thread-safe by default (use external synchronization if needed)
- Sessions accept an optional `OhttpObserver` for lifecycle event notifications

### Observer Pattern

- `OhttpObserver` provides lifecycle event hooks (abstract class with no-op default methods)
- Events: `onKeyConfigFetched`, `onKeyConfigCacheHit`, `onPostToGateway`, `onDecapsulationError`, `onGatewayError`, `onCacheInvalidated`, `onEncapsulationError`
- Observer errors are suppressed via `notifySafe()` — they must not affect the OHTTP pipeline
- Observer is optional and nullable throughout the API
- **Security**: observer callbacks must never receive or log cryptographic material (keys, nonces, shared secrets), raw inner request/response bodies, or plaintext headers — only lifecycle signals (success/failure events) and safe metadata (status codes, error types) are permitted

### Data Types

- `OhttpRequestData` — represents an HTTP request to send through OHTTP
- `OhttpResponseData` — represents the decrypted HTTP response
- Both are immutable data classes

### Error Handling

- `OhttpGatewayException` — gateway returned error (cache invalidated automatically)
- `OhttpDecapsulationException` — failed to decrypt response
- `OhttpFormatException` — malformed BHTTP data (wrong framing, invalid status)
- `OhttpCryptoException` — AES-GCM / HPKE crypto failure
- `OhttpSizeLimitException` — response body or encrypted payload too large
- `OhttpTimeoutException` — request timed out (subclass of `OhttpNetworkException`)
- All exceptions extend sealed `OhttpException` — catch with one handler

## References

- [RFC 9458 — Oblivious HTTP](https://www.ietf.org/rfc/rfc9458.html)
- [RFC 9180 — HPKE](https://www.ietf.org/rfc/rfc9180.html)
- [RFC 9292 — Binary HTTP](https://www.ietf.org/rfc/rfc9292.html)
- [cryptography package](https://pub.dev/packages/cryptography)
