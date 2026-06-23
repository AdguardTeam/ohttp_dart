# test/integration

These are pure-Dart, VM-run hermetic `package:test` tests (run by `dart test`) — **not** Flutter `integration_test/` device tests. "Integration" here means the tests exercise multiple library layers together (`OhttpHttpClient` → `OhttpSession` → transport → `MockClient`) without any real sockets or device.

## Stub approach

Gateway requests are handled by a `MockClient` from `package:http/testing.dart` (available transitively via `http: 1.6.0` — no new dependency). The mock client:

- Responds to `keysUrl` with a synthetic `OhttpKeyConfig` built from the fixed keypair in `test/support/gateway_stub.dart`.
- Responds to `gatewayUrl` POSTs using the in-test HPKE receiver (`sealBhttpResponse`) from `test/support/gateway_stub.dart`, which derives response key material via HKDF and seals the BHTTP response with AES-128-GCM per RFC 9458 §4.6.2.

## Property / fuzz tests (`fuzz_test.dart`)

Three `kiri_check` property tests run with a fixed CI seed for reproducibility:

| Property | Generator | Accepted outcomes |
|----------|-----------|-------------------|
| Varint round-trip identity on `[0, 2^62)` | `integer(min: 0, max: 0x3FFFFFFFFFFFFFFF)` | `decodeVarint(encodeVarint(v), 0) == (v, _)` |
| `parseResponse(randomBytes)` robustness | `binary()` | success, `OhttpFormatException`, or `OhttpSizeLimitException` |
| `OhttpKeyConfig.parse(randomBytes)` closure | `binary()` | success, `OhttpKeyConfigException`, or `OhttpUnsupportedSuiteException` |

### Overriding the seed for deeper runs

Each `forAll()` call uses `seed: 42`. To run with a different seed, edit the `seed:` argument on each `forAll()` call in `fuzz_test.dart`. For a deeper periodic run, also increase `maxExamples` and the `binary(maxLength:)` bound as needed:

```bash
dart test test/integration/fuzz_test.dart
```
