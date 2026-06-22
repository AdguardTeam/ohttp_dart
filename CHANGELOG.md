## 0.1.0

- OHTTP client (RFC 9458) — encapsulate/decapsulate HTTP requests via gateway
- HPKE Base Mode Sender (RFC 9180) — pure Dart, tested against RFC test vectors
- Binary HTTP (RFC 9292) — serialize/parse HTTP messages
- `OhttpSession` orchestrator with a TTL key-config cache (single-flight) and an optional `OhttpObserver`
- Transport-agnostic core (`OhttpTransport`) plus an optional `package:http` adapter: `HttpClientTransport` and the drop-in `OhttpHttpClient` (`http.BaseClient`)
- Tested on iOS, macOS, Android, Windows
