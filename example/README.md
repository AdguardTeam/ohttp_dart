# OHTTP Flutter Example

Flutter example app demonstrating [Oblivious HTTP (RFC 9458)](https://www.ietf.org/rfc/rfc9458.html) — pure Dart implementation, no native dependencies.

## Architecture

```
Flutter UI ──► OhttpSession ──► HttpClientTransport ──► OHTTP Gateway
                    │                          │
                    │                          ├─ GET /ohttp/config   (KeyConfig)
                    │                          ├─ POST /ohttp/gateway (encrypted request)
                    │                          │
                    │                   Pure Dart crypto (cryptography)
                    │                    ├─ HPKE (RFC 9180)
                    │                    ├─ BHTTP (RFC 9292)
                    └─ OhttpObserver        └─ OHTTP (RFC 9458)
                         └─ LogObserver (UI logging)
```

**Flow:**

1. `GET /ohttp/config` — fetch gateway's KeyConfig (public key + HPKE params)
2. Serialize HTTP request to [BHTTP (RFC 9292)](https://www.ietf.org/rfc/rfc9292.html)
3. Encrypt BHTTP message with [HPKE (RFC 9180)](https://www.ietf.org/rfc/rfc9180.html) using gateway's public key
4. `POST /ohttp/gateway` — send encrypted request
5. Decrypt and deserialize the response

## Tech Stack

| Component | Version |
|-----------|---------|
| Flutter | 3.41.4 (via `fvm`) |
| Dart | ^3.11.1 |
| ohttp_dart | 0.3.0 (local, via `package:ohttp_dart`) |
| http | 1.6.0 |
| flutter_lints (dev) | 6.0.0 |

**Cipher suite:** DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM

## Project Structure

```
lib/
├── main.dart                     # Flutter UI — OHTTP demo screen
├── src/
│   ├── gateways.dart             # Gateway transport factories
│   ├── log_entry.dart            # Log entry model (level, source, message)
│   ├── log_observer.dart         # OhttpObserver → typed log events
│   ├── log_panel.dart            # Color-coded, auto-scrolling log list
│   ├── json_highlighter.dart     # Dependency-free JSON syntax highlighting
│   ├── path_defaults.dart        # Method → default echo path sync
│   ├── privacy_facts.dart        # Echo-response privacy fact extraction
│   ├── response_view.dart        # Status chip, meta line, highlighted body
│   └── compare_view.dart         # OHTTP vs direct privacy comparison table
integration_test/
├── simple_test.dart              # E2E: GET/POST via OHTTP, Direct, comparison
test/
├── json_highlighter_test.dart    # Span structure and palette tests
├── path_defaults_test.dart       # Method↔path sync rule tests
├── privacy_facts_test.dart       # Echo extraction tests
└── widget_test.dart              # UI rendering tests
```

## Build & Run

```bash
# Prerequisites: fvm

# Get dependencies
fvm flutter pub get

# Run on macOS
fvm flutter run -d macos

# Run unit tests
fvm flutter test

# Run integration tests (requires network)
fvm flutter test integration_test/simple_test.dart -d macos
```

## Backend

Uses [AdguardTeam/HttpBin](https://github.com/AdguardTeam/HttpBin) deployed at `https://httpbin.agrd.workers.dev/`:

- `GET /ohttp/config` — OHTTP KeyConfig (41 bytes, KEM=X25519, KDF=HKDF-SHA256, AEAD=AES-128-GCM)
- `POST /ohttp/gateway` — OHTTP gateway (accepts `message/ohttp-req`)

## Library Architecture

The app uses the **ohttp_dart** package which provides:

| Component | Description |
|-----------|-------------|
| `OhttpSession` | High-level request-response orchestrator |
| `OhttpTransport` | Transport abstraction interface |
| `HttpClientTransport` | `package:http`-based transport implementation |
| `OhttpRequestData` / `OhttpResponseData` | Request/response data types |
| `KeyConfigCache` | TTL cache with single-flight for KeyConfig fetches |
| `OhttpObserver` | Lifecycle event hooks (logging, monitoring) |
| `OhttpHttpClient` | Drop-in `http.Client` replacement |

All cryptographic implementations (HPKE RFC 9180, BHTTP RFC 9292, OHTTP RFC 9458) are contained within the **ohttp_dart** package and tested against RFC test vectors.

## Limitations

- **No relay** — client sends directly to the gateway (no privacy relay in between), sufficient for demo purposes
- **Tested on macOS** — should work on all platforms (iOS, Android, Windows) but not yet verified
