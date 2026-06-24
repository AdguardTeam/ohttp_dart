# test/integration

These are pure-Dart, VM-run hermetic `package:test` tests (run by `dart test`) — **not** Flutter `integration_test/` device tests. "Integration" here means the tests exercise multiple library layers together (`OhttpHttpClient` → `OhttpSession` → transport → `MockClient`) without any real sockets or device.

## Stub approach

Gateway requests are handled by a `MockClient` from `package:http/testing.dart` (available transitively via `http: 1.6.0` — no new dependency). The mock client:

- Responds to `keysUrl` with a synthetic `OhttpKeyConfig` built from the fixed keypair in `test/support/gateway_stub.dart`.
- Responds to `gatewayUrl` POSTs using `decapExportedSecret` (HPKE KEM Decap) + `sealBhttpResponse` (HKDF + AES-128-GCM per RFC 9458 §4.6.2) from `test/support/gateway_stub.dart`. The stub also exposes `openEncapsulatedRequest`, which derives the HPKE request AEAD key and decrypts the inner BHTTP request ciphertext (used by the request-content round-trip test).

Because the normal `HttpClientTransport` constructor rejects `http://` URLs, the integration tests use `HttpClientTransport.insecureForTesting(...)` (`@visibleForTesting`, never called from production code).

## Pipeline tests (`ohttp_pipeline_test.dart`)

Eleven end-to-end tests exercise the complete OHTTP pipeline:

| Test | What it checks |
|------|----------------|
| Happy-path full round-trip | KeyConfig discovery → HPKE encapsulation → gateway POST → real KEM Decap in stub → decapsulation → BHTTP parse; asserts `statusCode 200`, decoded body, and observer event flags |
| Header round-trip | Same pipeline with a BHTTP response carrying a `content-type` header; asserts the header survives decapsulation into `response.headers` |
| Cache-hit within TTL | Two sequential `send()` calls on the same client; asserts exactly one GET to `keysUrl` and `observer.keyConfigCacheHit` fires on the second call |
| Gateway 503 (cache invalidated) | `OhttpGatewayException(statusCode: 503)`; observer `gatewayError = true`; `cacheInvalidated = true`; second key-config fetch on retry |
| Flipped ciphertext byte | `OhttpCryptoException` thrown when one AEAD ciphertext byte is flipped |
| Truncated response body | `OhttpDecapsulationException` when the encrypted payload is shorter than `responseNonceLen` (16 bytes) and is rejected before decryption |
| Gateway POST timeout | `OhttpTimeoutException` when the mock gateway delays beyond the session timeout |
| Response over size cap | `OhttpSizeLimitException` with correct `limit` and `actualSize` when the encrypted response exceeds `maxEncryptedResponseBytes` |
| Decrypted body over size cap | `OhttpSizeLimitException` when the decrypted BHTTP response body exceeds `BhttpResponseLimits.maxBodyBytes`; distinct from the encrypted-byte cap checked before decryption |
| Unsupported cipher suite | `OhttpUnsupportedSuiteException` thrown during key-config validation before encapsulation; the only test asserting `observer.encapsulationError == false` and `observer.postToGateway == false` |
| Request content round-trip | Decrypts the encapsulated BHTTP request via `openEncapsulatedRequest` and asserts the custom outbound header name and value survive HPKE + BHTTP serialisation |

## Property / fuzz tests (`fuzz_test.dart`)

Three `kiri_check` property tests run with a fixed CI seed for reproducibility:

| Property | Generator | Accepted outcomes |
|----------|-----------|-------------------|
| Varint round-trip identity on `[0, 2^62)` | `integer(min: 0, max: 0x3FFFFFFFFFFFFFFF)` | `decodeVarint(encodeVarint(v), 0) == (v, _)` |
| `parseResponse(randomBytes)` robustness | `binary()` | success, `OhttpFormatException`, or `OhttpSizeLimitException` |
| `OhttpKeyConfig.parse(randomBytes)` closure | `binary()` | success, `OhttpKeyConfigException`, or `OhttpUnsupportedSuiteException` |

### Overriding the seed for deeper runs

Each `forAll()` call uses `seed: 42`. To run with a different seed, edit the `seed:` argument on each `forAll()` call in `fuzz_test.dart`. For a deeper periodic run, add a `maxExamples:` argument to each `forAll(...)` call and increase the `binary(maxLength:)` bound as needed:

```bash
fvm dart test test/integration/fuzz_test.dart
fvm dart test test/integration/ohttp_pipeline_test.dart
fvm dart test test/integration/  # run all integration tests
```
