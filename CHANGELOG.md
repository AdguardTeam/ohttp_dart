## Unreleased

### AW-2953 Phase 2 — Fuzz / property-based tests

- Added `test/integration/fuzz_test.dart` with three `kiri_check` property tests: varint round-trip identity on `[0, 2^62)`, `parseResponse` typed-exception closure (only `OhttpFormatException` or `OhttpSizeLimitException` may escape), and `OhttpKeyConfig.parse` typed-exception closure (only `OhttpKeyConfigException` or `OhttpUnsupportedSuiteException` may escape). All properties run with `seed: 42` for deterministic CI output.
- Added `test/integration/README.md` disambiguating the directory from Flutter device tests and documenting the gateway-stub approach and seed-override mechanism.
- No production code changed; no new dependencies added.

### AW-2953 Phase 1 — Extract gateway stub

- Extracted inline HPKE-receiver and response-sealing helpers from `test/ohttp_test.dart` into a new shared file `test/support/gateway_stub.dart`, with a fixed X25519 keypair for reuse by integration tests.

## 0.1.0

- OHTTP client (RFC 9458) — encapsulate/decapsulate HTTP requests via gateway
- HPKE Base Mode Sender (RFC 9180) — pure Dart, tested against RFC test vectors
- Binary HTTP (RFC 9292) — serialize/parse HTTP messages
- `OhttpSession` orchestrator with a TTL key-config cache (single-flight) and an optional `OhttpObserver`
- Transport-agnostic core (`OhttpTransport`) plus an optional `package:http` adapter: `HttpClientTransport` and the drop-in `OhttpHttpClient` (`http.BaseClient`)
- Tested on iOS, macOS, Android, Windows
