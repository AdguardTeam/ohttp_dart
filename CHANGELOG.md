## 0.4.0

- Added `OhttpRequestAbortedException` to the sealed `OhttpException` hierarchy — a sibling of
  `OhttpNetworkException` (deliberately not a subtype) that preserves the original error in `cause` and the
  captured stack trace in `stackTrace`. It is exported from the public API automatically via
  `package:ohttp_dart/ohttp_dart.dart`.
- `HttpClientTransport.fetchKeyConfig()` and `postToGateway()` now throw `OhttpRequestAbortedException` instead
  of `OhttpNetworkException` when the underlying request is cancelled client-side
  (`http.RequestAbortedException`), so consumers can distinguish an intentional abort from a real network error
  with a plain `on OhttpRequestAbortedException`.
- Because the new type is a sibling and not a subtype, existing `on OhttpNetworkException` handlers no longer
  match a client-side cancellation (intentional).
- Behavior of all other errors is unchanged: timeouts still throw `OhttpTimeoutException`, non-2xx responses
  still throw `OhttpGatewayException`, and other network errors still throw `OhttpNetworkException`.
- A cancellation is not a gateway error, so it propagates transparently — no key-config cache invalidation and
  no single retry.

## 0.3.0

- Added automatic retry on gateway errors with key rotation in `OhttpSession` (`retryOnGatewayError`, default `true`).
- Added `OhttpHttpClient.create()` factory.
- Added `onGatewayRetry()` observer event (fired when a gateway error triggers retry).
- Added `onRoundTripCompleted(Duration elapsed)` observer event (fired after a successful round trip only).
- Added `OhttpConstants` — centralized default values replacing scattered private constants.
- Added tests for retry behavior, observer events, `OhttpHttpClient.create()` wiring, and pipeline observers.

## 0.2.0

### Breaking changes

- Removed `OhttpClient`. The OHTTP round trip is now orchestrated by `OhttpSession`, which works over the
  transport-agnostic `OhttpTransport` interface (`fetchKeyConfig()` / `postToGateway()`).
- Moved the `package:http` integration out of the core into a separate entry point
  `package:ohttp_dart/http.dart` — `HttpClientTransport` plus the drop-in `OhttpHttpClient`
  (an `http.BaseClient`). The core no longer depends on any HTTP client.
- BHTTP signatures changed: `serializeRequest` takes headers as an order-preserving
  `List<(String, String)>` instead of `Map<String, String>`, and `parseResponse` requires a
  `BhttpResponseLimits` argument.
- All errors thrown by the package now extend the sealed `OhttpException` instead of generic exceptions.

### Added

- `KeyConfigCache` — TTL cache for the gateway key config (default 1 hour) with single-flight
  deduplication of concurrent fetches; invalidated automatically on `OhttpGatewayException`.
- Typed exception hierarchy: sealed `OhttpException` with 9 subtypes (`OhttpConfigException`,
  `OhttpCryptoException`, `OhttpDecapsulationException`, `OhttpFormatException`, `OhttpGatewayException`,
  `OhttpKeyConfigException`, `OhttpNetworkException`, `OhttpSizeLimitException`,
  `OhttpUnsupportedSuiteException`), each carrying a stack trace.
- Timeouts for the key-config fetch and the gateway POST in `HttpClientTransport`; expiry throws
  `OhttpTimeoutException`.
- Response size limits: a cap on the encrypted gateway response (`maxResponseBytes`) and BHTTP
  header-section/body caps via `BhttpResponseLimits`; violations throw `OhttpSizeLimitException`.
- `OhttpObserver` — optional lifecycle hooks around the round trip. Callbacks receive only safe metadata
  (status codes, error types); observer errors never affect the pipeline.
- Zeroization of sensitive material: `ErasableByteArray` (zeroes on `erase()`, guards post-erase reads);
  HPKE keys, nonces and intermediate secrets are wiped after use (`HpkeSenderContext.dispose()`).
- Input validation: `HttpClientTransport` accepts HTTPS URLs only (an `insecureForTesting` constructor is
  available for tests); `OhttpRequestData` validates the authority.
- Multi-suite key configs: the first supported cipher suite is selected from `OhttpKeyConfig`;
  `OhttpUnsupportedSuiteException` is thrown when none is supported.
- Test suites: unit tests verified against RFC 9180 / RFC 5869 vectors, property-based fuzz tests
  (`kiri_check`) and end-to-end integration tests with an in-memory gateway stub.

### Changed

- Non-2xx responses from the key-config endpoint or the gateway throw `OhttpGatewayException` before
  decapsulation is attempted.
- `OhttpResponseData` normalizes header names to lowercase.
- Documentation reworked for the new architecture (README.md, AGENTS.md).

### Fixed

- HPKE encapsulation aborts when the X25519 DH result is the identity element (low-order recipient
  public key), per RFC 9180 §7.1.4.
- `HpkeSenderContext.export` enforces the RFC 9180 §5.3 length limit (1..255 × Nh).
- `encodeVarint` rejects values outside the QUIC 62-bit range and `decodeVarint` reports truncated input
  as `OhttpFormatException` (RFC 9000 §16).

## 0.1.0

- OHTTP client (RFC 9458) — encapsulate/decapsulate HTTP requests via gateway
- HPKE Base Mode Sender (RFC 9180) — pure Dart, tested against RFC test vectors
- Binary HTTP (RFC 9292) — serialize/parse HTTP messages
- High-level `OhttpClient` with configurable gateway
- Tested on iOS, macOS, Android, Windows
