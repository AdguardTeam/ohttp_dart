# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

`ohttp_dart` is a pure-Dart Oblivious HTTP client: OHTTP (RFC 9458) over a hand-written HPKE Base-Mode
sender (RFC 9180) with Binary HTTP framing (RFC 9292). No native dependencies. Cipher suite is fixed to
`DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM`.

## Commands

```bash
dart pub get                              # install dependencies
dart test                                 # run all tests
dart test test/hpke_test.dart             # run a single test file
dart test --name "HKDF"                   # run tests matching a name pattern
dart analyze                              # static analysis — must be zero warnings/infos
dart format .                             # format (page_width 120 is read from analysis_options.yaml)
dcm analyze lib test                      # Dart Code Metrics rules (member-ordering, file-name match, etc.)
```

`dart` resolves through the user's FVM default; `fvm dart ...` and the `dart`/`dcm` MCP tools are equivalent.
After changing Dart code (or after a pull/merge/rebase), run `ast-index update` to keep the search index fresh.

## Code search

This project is indexed with `ast-index`. **Use it as the primary code-search tool** — see the rules below for the
search-first / read-with-outline / subagent conventions.

@.claude/rules/ast-index.md

## Architecture

### Two-layer packaging — keep the core transport-agnostic

- `package:ohttp_dart/ohttp_dart.dart` — the **core** library. It must have **no dependency on any HTTP client**
  for the request path. All network I/O is injected through the `OhttpTransport` interface (`lib/src/ohttp_transport.dart`).
- `package:ohttp_dart/http.dart` — the **optional adapter** for `package:http`. It provides the only concrete
  transport (`HttpClientTransport`) and a drop-in `http.BaseClient` (`OhttpHttpClient`) under `lib/src/adapters/http/`.

When adding functionality, decide which layer it belongs to. Anything that reaches for `package:http` (or any
specific client) belongs under `lib/src/adapters/`, never in the core `src/` files.

### Request flow

`OhttpSession.send()` (`lib/src/ohttp_session.dart`) is the orchestrator and the best entry point for understanding
the whole pipeline. One round trip:

1. `KeyConfigCache.get()` — fetch/return the gateway's HPKE key config (TTL cache, default 1h, with single-flight dedup).
2. `bhttp.serializeRequest(...)` — encode the request as Binary HTTP (`lib/src/bhttp.dart`).
3. `ohttpEncapsulate(config, binaryRequest)` — HPKE-seal the BHTTP into an encapsulated request; returns the
   `enc` public key, the AEAD context's exported secret, and the wire bytes (`lib/src/ohttp.dart` + `lib/src/hpke.dart`).
4. `transport.postToGateway(encRequest)` — the injected transport POSTs to the gateway.
5. `ohttpDecapsulate(enc, exportedSecret, encResponse)` — derive the response key from the exported secret and
   open the AEAD-sealed response back into BHTTP bytes.
6. `bhttp.parseResponse(...)` — decode BHTTP into `OhttpResponseData`.

An optional `OhttpObserver` (`lib/src/ohttp_observer.dart`) receives lifecycle signals at each step. Its callbacks
are invoked through `notifySafe()` so an observer that throws never affects the pipeline, and they must only receive
safe metadata (event type, status codes) — never keys, nonces, shared secrets, or plaintext bodies/headers.

### Key invariants

- **Cache invalidation is gateway-error-only.** `send()` invalidates the cached `OhttpKeyConfig` *only* when the
  transport throws `OhttpGatewayException` (the gateway likely rotated keys). Network errors, decapsulation
  failures, and crypto failures propagate without touching the cache. Preserve this when editing `send()`.
- **A cache must wrap the same transport its session uses** — invalidation and gateway POSTs have to target the
  same gateway. `OhttpSession.withTransport` enforces this by constructing the cache internally.
- **Response size limits are enforced** — `maxEncryptedResponseBytes` on the session and `BhttpResponseLimits`
  (`maxHeaderBytes` / `maxBodyBytes`) bound the encrypted and decrypted responses; over-limit data raises
  `OhttpSizeLimitException`.

### HPKE is hand-rolled and client-only

`lib/src/hpke.dart` implements HPKE Base-Mode **Sender** from `package:cryptography` primitives (X25519, HMAC-SHA256,
AES-128-GCM). There is no receiver/decryptor and no agility — the suite is fixed in `lib/src/cipher_suite.dart`.
Treat this file as security-critical: it is validated against the RFC 9180 Appendix A.1 test vectors in
`test/hpke_test.dart`, so any change to the key schedule, labeled extract/expand, or nonce computation must keep
those vectors passing. Do **not** edit test vectors to make a change pass.

### Errors

Every error the library raises is a subclass of the `sealed` `OhttpException` (`lib/src/exceptions.dart`), so a
single `on OhttpException` handler catches them all, and the sealed-ness lets `switch` exhaustively match. The
9 direct subtypes: `OhttpConfigException`, `OhttpUnsupportedSuiteException`, `OhttpKeyConfigException`,
`OhttpGatewayException` (carries `statusCode`), `OhttpCryptoException` (wraps a `cause`), `OhttpDecapsulationException`,
`OhttpFormatException`, `OhttpSizeLimitException` (carries `limit` / `actualSize`), and `OhttpNetworkException`
(wraps a `cause`) — with `OhttpTimeoutException` (carries `timeout` / `url`) extending `OhttpNetworkException`.

## Conventions

`analysis_options.yaml` is strict and enforced — notable points beyond `package:lints/recommended`:

- `public_member_api_docs` is on: every public member needs a `///` doc comment (use `// ignore_for_file:
  public_member_api_docs` only for intentionally-undocumented files, as `exceptions.dart` does).
- `require_trailing_commas` + `always_put_control_body_on_new_line` — formatting is mechanical; run `dart format`.
- `strict-casts` and `strict-raw-types` are enabled; `dead_code` and `invalid_assignment` are **errors**, not warnings.
- `dart_code_metrics` enforces member ordering (constants → fields → constructors → getters/setters → overrides →
  public methods → private methods) and `prefer-match-file-name` (a file's primary class matches its filename);
  check it with `dcm analyze lib test`.
- Dependencies are **pinned without a caret** (`http: 1.6.0`, not `^1.6.0`) and sorted alphabetically.
- Tests mirror `lib/` under `test/`; cite RFC section numbers in protocol code and test-vector sources in tests.
