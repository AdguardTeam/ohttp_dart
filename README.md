# ohttp_dart

Pure Dart implementation of [Oblivious HTTP (RFC 9458)](https://www.ietf.org/rfc/rfc9458.html) — no native dependencies.

## Features

- **OHTTP encapsulation / decapsulation** (RFC 9458)
- **HPKE Base Mode Sender** (RFC 9180) — hand-written from crypto primitives
- **Binary HTTP** (RFC 9292) — serialize/parse HTTP messages
- **Transport-agnostic core** — plug in any HTTP client via the `OhttpTransport` interface
- **`package:http` adapter** — drop-in `http.BaseClient` replacement
- **TTL-based key config cache** with single-flight deduplication
- **Configurable size limits** for encrypted and decrypted responses

**Cipher suite:** DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM

## Architecture

```
package:ohttp_dart/ohttp_dart.dart   ← core (transport-agnostic)
package:ohttp_dart/http.dart         ← package:http adapter
```

The core library defines abstractions (`OhttpTransport`, `OhttpSession`,
`KeyConfigCache`) that any HTTP client can plug into. The `http.dart`
adapter provides `HttpClientTransport` and `OhttpHttpClient` for
consumers using `package:http`.

`OhttpSession` orchestrates the full pipeline: cache lookup → BHTTP
serialization → OHTTP encapsulation → transport call → decapsulation →
BHTTP parsing. Cache invalidation happens automatically on gateway errors.

### Observer Pattern

Sessions accept an optional `OhttpObserver` to receive lifecycle event notifications:

```dart
class MyObserver extends OhttpObserver {
  @override
  void onKeyConfigFetched() => print('Key config fetched');
  
  @override
  void onKeyConfigCacheHit() => print('Using cached key config');
  
  @override
  void onPostToGateway() => print('Posting to gateway');
  
  @override
  void onDecapsulationError([Object? error]) => print('Decapsulation failed: $error');
  
  @override
  void onGatewayError([Object? error]) => print('Gateway error: $error');
  
  @override
  void onCacheInvalidated() => print('Cache invalidated');
  
  @override
  void onEncapsulationError([Object? error]) => print('Encapsulation failed: $error');
}

final session = OhttpSession.withTransport(
  transport: transport,
  observer: MyObserver(),
);
```

Observer methods have no-op defaults, so you only override the events you care about.
Observer errors are suppressed via `notifySafe()` — they never affect the OHTTP pipeline.

## Project Structure

```
lib/
├── ohttp_dart.dart                     # Core library entry point (transport-agnostic)
├── http.dart                           # Optional package:http adapter entry point
└── src/
    ├── bhttp.dart                      # Binary HTTP (RFC 9292)
    ├── bhttp_response_limits.dart      # Response size limits configuration
    ├── cipher_suite.dart               # Cipher suite constants
    ├── exceptions.dart                 # Sealed exception hierarchy
    ├── hpke.dart                       # HPKE Base Mode Sender (RFC 9180)
    ├── key_config_cache.dart           # TTL cache with single-flight for key configs
    ├── ohttp.dart                      # OHTTP encap/decap + KeyConfig (RFC 9458)
    ├── ohttp_data.dart                 # Request / response data types
    ├── ohttp_observer.dart             # Lifecycle event observer interface
    ├── ohttp_session.dart              # OHTTP session orchestrator
    ├── ohttp_transport.dart            # Transport abstraction interface
    ├── wipe_bytes_extension.dart      # Secure memory wipe utility
    └── adapters/
        └── http/
            ├── http_client_transport.dart   # HttpClientTransport implementation
            └── ohttp_http_client.dart       # OhttpHttpClient drop-in replacement
```

## Error Handling

All exceptions thrown by the library extend `OhttpException` (sealed class),
so consumers can catch every library error with a single handler:

```dart
try {
  final response = await session.send(request);
} on OhttpException catch (e) {
  // All library errors land here
  print('OHTTP error: $e');
}
```

Specific exception types:

| Type | When |
|---|---|
| `OhttpConfigException` | Invalid request/URL config (non-HTTPS scheme, bad authority, negative limits) |
| `OhttpUnsupportedSuiteException` | KeyConfig advertises only unsupported KEM/KDF/AEAD |
| `OhttpKeyConfigException` | Structurally malformed KeyConfig binary data (too short, wrong lengths, trailing data) |
| `OhttpFormatException` | Malformed BHTTP data (wrong framing indicator, truncated fields, invalid varint) |
| `OhttpGatewayException` | Gateway returned non-2xx response (includes `statusCode`; triggers cache invalidation) |
| `OhttpDecapsulationException` | OHTTP response decapsulation failure (response too short, ciphertext too short for GCM tag) |
| `OhttpCryptoException` | AES-GCM / HPKE crypto failure (includes optional `cause`) |
| `OhttpSizeLimitException` | Response exceeds configured size limits (includes `limit` and `actualSize`) |
| `OhttpNetworkException` | Network-level error — DNS, connection refused, etc. (includes optional `cause`) |
| `OhttpTimeoutException` | HTTP request exceeded configured timeout (includes `timeout` duration and optional `url`) |

## Usage

### Quick-start: drop-in `http.BaseClient`

```dart
import 'package:http/http.dart' as http;
import 'package:ohttp_dart/http.dart';
import 'package:ohttp_dart/ohttp_dart.dart';

final raw = http.Client();
final transport = HttpClientTransport(
  client: raw,
  keysUrl: Uri.parse('https://gateway.example.com/ohttp/config'),
  gatewayUrl: Uri.parse('https://gateway.example.com/ohttp/gateway'),
);
final session = OhttpSession.withTransport(transport: transport);
final client = OhttpHttpClient(session: session, closeWith: raw);

final response = await client.get(Uri.https('target.example.com', '/api/data'));
// Use response as a standard http.StreamedResponse
client.close();
```

### Low-level: `OhttpSession.send`

```dart
final session = OhttpSession.withTransport(transport: transport);
final request = OhttpRequestData(
  method: 'GET',
  scheme: 'https',
  authority: 'target.example.com',
  path: '/api/data',
  headers: [('accept', 'application/json')],
);
final response = await session.send(request);
```

### Session configuration

`OhttpSession` supports configurable limits for response sizes:

```dart
final session = OhttpSession.withTransport(
  transport: transport,
  maxEncryptedResponseBytes: 32 * 1024 * 1024, // 32 MiB (default: 16 MiB)
  decryptedResponseLimits: BhttpResponseLimits(
    maxHeaderBytes: 32 * 1024,  // 32 KiB (default: 16 KiB)
    maxBodyBytes: 20 * 1024 * 1024, // 20 MiB (default: 10 MiB)
  ),
);
```

For full control over the cache, use the primary constructor:

```dart
final cache = KeyConfigCache(
  transport: transport,
  ttl: Duration(hours: 2),
);
final session = OhttpSession(
  transport: transport,
  cache: cache,
  maxEncryptedResponseBytes: 32 * 1024 * 1024,
);
```

### Transport configuration

`HttpClientTransport` enforces HTTPS per RFC 9458 §1 and supports
configurable timeouts:

```dart
final transport = HttpClientTransport(
  client: httpClient,
  keysUrl: Uri.parse('https://gateway.example.com/ohttp/config'),
  gatewayUrl: Uri.parse('https://gateway.example.com/ohttp/gateway'),
  fetchKeyConfigTimeout: Duration(seconds: 10),  // default: 30s
  postToGatewayTimeout: Duration(seconds: 15),   // default: 30s
);
```

For testing with non-HTTPS endpoints (e.g., `MockClient` with `http://localhost`):

```dart
final transport = HttpClientTransport.insecureForTesting(
  client: mockClient,
  keysUrl: Uri.parse('http://localhost:8080/keys'),
  gatewayUrl: Uri.parse('http://localhost:8080/gateway'),
);
```

### Custom transport

Implement `OhttpTransport` to integrate with any HTTP client (Dio, etc.):

```dart
class DioTransport implements OhttpTransport {
  @override
  Future<Uint8List> fetchKeyConfig() async {
    // GET the key config URL, throw OhttpGatewayException on non-2xx
  }

  @override
  Future<Uint8List> postToGateway(Uint8List body) async {
    // POST to gateway with Content-Type: message/ohttp-req
    // throw OhttpGatewayException on non-2xx
  }
}
```

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `cryptography` | 2.9.0 | Pure Dart crypto primitives (X25519, HMAC, AES-GCM) |
| `http` | 1.6.0 | HTTP client for the `package:http` adapter |

## Testing

```bash
dart test
```

Tests cover:
- RFC test vectors for HPKE (RFC 9180 Appendix A.1), HKDF (RFC 5869)
- OHTTP encapsulation/decapsulation (RFC 9458)
- BHTTP encoding/decoding (RFC 9292)
- Key config TTL cache with single-flight deduplication
- Observer lifecycle events and error suppression
- Session orchestration and pipeline integration
- `package:http` adapter integration

## License

See [LICENSE](LICENSE).
