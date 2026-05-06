# ohttp_dart

Pure Dart implementation of [Oblivious HTTP (RFC 9458)](https://www.ietf.org/rfc/rfc9458.html) — no native dependencies.

## Features

- **OHTTP client** (RFC 9458) — encapsulate/decapsulate HTTP requests
- **HPKE Base Mode Sender** (RFC 9180) — hand-written from crypto primitives
- **Binary HTTP** (RFC 9292) — serialize/parse HTTP messages
- **High-level OhttpClient** — fetch KeyConfig + send requests via gateway

**Cipher suite:** DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM

## Architecture

```
OhttpClient ──► Dart crypto (cryptography package)
     │                    │
     │ HTTP               ├─ HPKE (RFC 9180)
     ▼                    ├─ BHTTP (RFC 9292)
OHTTP Gateway             └─ OHTTP (RFC 9458)
```

## Project Structure

```
lib/
├── ohttp_dart.dart          # Library exports
└── src/
    ├── ohttp_client.dart    # High-level OHTTP client (HTTP + OHTTP)
    ├── ohttp.dart           # OHTTP encapsulate/decapsulate + KeyConfig parser
    ├── hpke.dart            # HPKE Base Mode Sender (RFC 9180)
    └── bhttp.dart           # Binary HTTP serialize/parse (RFC 9292)
test/
├── bhttp_test.dart          # Varint, serialization, parsing
├── hpke_test.dart           # RFC 9180 test vectors
└── ohttp_test.dart          # Encapsulate/decapsulate, KeyConfig
```

## Usage

```dart
import 'package:ohttp_dart/ohttp_dart.dart';

// High-level: send a request through an OHTTP gateway
final client = OhttpClient(
  configUrl: 'https://example.com/ohttp/config',
  gatewayUrl: 'https://example.com/ohttp/gateway',
);
final response = await client.send('GET', 'https', 'example.com', '/api/data');
print(response.statusCode);
print(response.body);
```

## Dependencies

| Package | Purpose |
|---------|---------|
| `cryptography` ^2.9.0 | Pure Dart crypto primitives (X25519, HMAC, AES-GCM) |
| `http` ^1.6.0 | HTTP client for gateway communication |

## Testing

```bash
dart test
```

Tests cover RFC test vectors for HPKE (RFC 9180 Appendix A.1), HKDF (RFC 5869), and BHTTP encoding.
