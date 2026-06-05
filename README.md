# ohttp_dart

Pure Dart implementation of [Oblivious HTTP (RFC 9458)](https://www.ietf.org/rfc/rfc9458.html) — no native dependencies.

## Features

- **OHTTP encapsulation / decapsulation** (RFC 9458)
- **HPKE Base Mode Sender** (RFC 9180) — hand-written from crypto primitives
- **Binary HTTP** (RFC 9292) — serialize/parse HTTP messages
- **Transport-agnostic core** — no HTTP-client dependency in the core library
- **Optional `package:http` adapter** — drop-in `http.Client` replacement

**Cipher suite:** DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM

## Architecture

```
package:ohttp_dart/ohttp_dart.dart   ← core (transport-agnostic)
package:ohttp_dart/http.dart         ← optional package:http adapter
```

The core library defines abstractions (`OhttpTransport`, `OhttpSession`,
`KeyConfigCache`) that any HTTP client can plug into. The `http.dart`
adapter provides `HttpClientTransport` and `OhttpHttpClient` for
consumers using `package:http`.

## Project Structure

```
lib/
├── ohttp_dart.dart              # Core library entry point
├── http.dart                    # Optional http adapter entry point
└── src/
    ├── bhttp.dart               # Binary HTTP (RFC 9292)
    ├── hpke.dart                # HPKE Base Mode Sender (RFC 9180)
    ├── ohttp.dart               # OHTTP encap/decap + KeyConfig (RFC 9458)
    ├── ohttp_transport.dart     # Transport abstraction interface
    ├── ohttp_data.dart          # Request / response data types
    ├── key_config_cache.dart    # TTL cache with single-flight
    ├── ohttp_session.dart       # OHTTP session orchestrator
    ├── cipher_suite.dart        # Cipher suite constants
    ├── exceptions.dart          # Typed exception hierarchy
    └── adapters/
        └── http/
            ├── http_client_transport.dart  # HttpClientTransport
            └── ohttp_http_client.dart      # OhttpHttpClient
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
| `OhttpConfigException` | Invalid configuration parameters, unsupported cipher suite |
| `OhttpFormatException` | Malformed KeyConfig, BHTTP, or varint data |
| `OhttpGatewayException` | Gateway returned non-2xx response (includes `statusCode`) |
| `OhttpDecapsulationException` | Response too short or ciphertext too short for AES-GCM tag |
| `OhttpCryptoException` | AES-GCM authentication failure (wraps underlying `cause`) |
| `OhttpNetworkException` | DNS failure, connection refused, timeout (wraps underlying `cause`) |

## Usage

### Quick-start: drop-in `http.Client`

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
// Use response as a standard http.Response
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
);
final response = await session.send(request);
```

## Dependencies

| Package | Purpose |
|---------|---------|
| `cryptography` 2.9.0 | Pure Dart crypto primitives (X25519, HMAC, AES-GCM) |
| `http` 1.6.0 | HTTP client for gateway communication |

## Testing

```bash
dart test
```

Tests cover RFC test vectors for HPKE (RFC 9180 Appendix A.1), HKDF (RFC 5869), and BHTTP encoding.
