## Unreleased

### AW-2953 Phase 4 — Failure-path integration tests

- Added 5 failure-path tests to `test/integration/ohttp_pipeline_test.dart`: gateway 503 (`OhttpGatewayException` with `statusCode == 503` + cache-invalidation verified by a second GET to `keysUrl`), flipped ciphertext byte (`OhttpCryptoException`), truncated response body below `responseNonceLen` (`OhttpDecapsulationException`), gateway POST delay 2 s vs. 100 ms transport timeout (`OhttpTimeoutException`), and 512-byte response body vs. 64-byte cap (`OhttpSizeLimitException`). All five tests use the most-specific shipped exception subtype and assert matching `OhttpObserver` callbacks where applicable. `test/integration/ohttp_pipeline_test.dart` now covers 7 end-to-end scenarios.
- No production code changed; no new dependencies added.

### AW-2953 Phase 3 — End-to-end integration tests

- Added `test/integration/ohttp_pipeline_test.dart` with two end-to-end integration tests: a happy-path full round-trip (KeyConfig discovery → HPKE encapsulation → gateway POST → real KEM Decap in the stub → decapsulation → BHTTP parse; asserts `statusCode 200`, body, and observer flags) and a cache-hit test (second `send()` within TTL issues exactly one GET to the keys endpoint; asserts `observer.keyConfigCacheHit`).
- Extended `test/support/gateway_stub.dart` with `decapExportedSecret` — a full HPKE KEM Decap implementation (RFC 9180 §7.1.2) using the gateway private key — plus private `_labeledExtract`/`_labeledExpand` helpers. These enable the stub to independently re-derive the exported secret and seal a canned BHTTP response for the client to decapsulate.
- No production code changed; no new dependencies added.

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
