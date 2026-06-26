// ignore_for_file: public_member_api_docs

import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart';
import 'package:http/testing.dart';
import 'package:ohttp_dart/http.dart';
import 'package:ohttp_dart/ohttp_dart.dart';
import 'package:ohttp_dart/src/cipher_suite.dart';
import 'package:test/test.dart';

import '../stubs/gateway_stub.dart';
import '../test_utils.dart';

// ---------------------------------------------------------------------------
// Test observer — records which lifecycle events fired (safe fields only).
// Never captures keys, nonces, shared secrets, or plaintext bodies.
// ---------------------------------------------------------------------------

final class _TestObserver extends OhttpObserver {
  bool keyConfigFetched = false;
  bool keyConfigCacheHit = false;
  bool postToGateway = false;
  bool gatewayError = false;
  bool cacheInvalidated = false;
  bool decapsulationError = false;
  bool encapsulationError = false;
  int? lastGatewayErrorStatus;
  Type? lastDecapsulationErrorType;
  Type? lastEncapsulationErrorType;

  @override
  void onKeyConfigFetched() => keyConfigFetched = true;

  @override
  void onKeyConfigCacheHit() => keyConfigCacheHit = true;

  @override
  void onPostToGateway() => postToGateway = true;

  @override
  void onGatewayError(int statusCode) {
    gatewayError = true;
    lastGatewayErrorStatus = statusCode;
  }

  @override
  void onCacheInvalidated() => cacheInvalidated = true;

  @override
  void onDecapsulationError(Type errorType) {
    decapsulationError = true;
    lastDecapsulationErrorType = errorType;
  }

  @override
  void onEncapsulationError(Type errorType) {
    encapsulationError = true;
    lastEncapsulationErrorType = errorType;
  }
}

// ---------------------------------------------------------------------------
// Test constants — http:// URLs require HttpClientTransport.insecureForTesting.
// ---------------------------------------------------------------------------

const _keysUrl = 'http://test.local/keys';
const _gatewayUrl = 'http://test.local/gateway';

// ---------------------------------------------------------------------------
// MockClient builder
// ---------------------------------------------------------------------------

/// Returns a [MockClient] routing:
///   GET  [_keysUrl]    → 200, body = [keyConfigBytes]
///   POST [_gatewayUrl] → [gatewayHandler](request)
MockClient _buildMockClient({
  required Uint8List keyConfigBytes,
  required Future<Response> Function(Request) gatewayHandler,
}) => MockClient((request) async {
  if (request.method == 'GET' && request.url.toString() == _keysUrl) {
    return Response.bytes(keyConfigBytes, 200);
  }
  if (request.method == 'POST' && request.url.toString() == _gatewayUrl) {
    return gatewayHandler(request);
  }

  return Response('Not found', 404);
});

// ---------------------------------------------------------------------------
// BHTTP helper — builds a minimal Known-Length 200 response (RFC 9292 §3.2).
// framing(1) || status(200) || hdrSectionLen(0) || bodyLen || body || trailerLen(0)
// ---------------------------------------------------------------------------

Uint8List _buildBhttpResponse(List<int> body) {
  final buf = BytesBuilder()
    ..add(encodeVarint(1)) // framing indicator: 1 = known-length response
    ..add(encodeVarint(200)) // status code
    ..add(encodeVarint(0)) // header section length = 0
    ..add(encodeVarint(body.length)) // body length
    ..add(body) // body bytes
    ..add(encodeVarint(0)); // trailer section length = 0

  return Uint8List.fromList(buf.toBytes());
}

// Builds a Known-Length 200 BHTTP response (RFC 9292 §3.2) with named headers.
// Each field line: nameLen(varint) || name || valueLen(varint) || value.
Uint8List _buildBhttpResponseWithHeaders(List<int> body, List<(String, String)> headers) {
  final headerBuf = BytesBuilder();
  for (final (name, value) in headers) {
    final nameBytes = utf8.encode(name);
    final valueBytes = utf8.encode(value);
    headerBuf
      ..add(encodeVarint(nameBytes.length))
      ..add(nameBytes)
      ..add(encodeVarint(valueBytes.length))
      ..add(valueBytes);
  }
  final headerBytes = headerBuf.toBytes();

  final buf = BytesBuilder()
    ..add(encodeVarint(1)) // framing indicator
    ..add(encodeVarint(200)) // status code
    ..add(encodeVarint(headerBytes.length))
    ..add(headerBytes)
    ..add(encodeVarint(body.length))
    ..add(body)
    ..add(encodeVarint(0)); // trailer section length = 0

  return Uint8List.fromList(buf.toBytes());
}

// ---------------------------------------------------------------------------
// Shared gateway handler — KEM decap + seal canned BHTTP response.
// ---------------------------------------------------------------------------

Future<Response> _gatewayHandlerFor(Request request, Uint8List bhttpResponseBytes) async {
  final postBody = request.bodyBytes;
  final exportedSecret = await decapExportedSecret(postBody);
  final enc = postBody.sublist(ohttpHeaderLen, ohttpHeaderLen + CipherSuite.kemPublicKeyLength);
  final encResponse = await sealBhttpResponse(enc, exportedSecret, bhttpResponseBytes);

  return Response.bytes(encResponse, 200);
}

// Shorthand for the default KeyConfig used by 9 of 10 tests:
// DHKEM(X25519) + HKDF-SHA256 + AES-128-GCM against the fixed gateway key.
Uint8List _defaultKeyConfigBytes() => multiSuiteKeyConfig(
  publicKey: gatewayPublicKeyBytes,
  suiteIds: [(0x0001, 0x0001)],
);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

void main() {
  group('OhttpHttpClient integration (RFC 9458 end-to-end)', () {
    test('happy path: full round-trip decrypts canned BHTTP response', () async {
      // Use the fixed gateway public key so the sender's ohttpEncapsulate produces
      // an enc/exportedSecret the stub can re-derive via KEM decap.
      final keyConfigBytes = _defaultKeyConfigBytes();
      final bhttpResponseBytes = _buildBhttpResponse(utf8.encode('hello'));

      final mockClient = _buildMockClient(
        keyConfigBytes: keyConfigBytes,
        gatewayHandler: (req) => _gatewayHandlerFor(req, bhttpResponseBytes),
      );

      final observer = _TestObserver();
      final transport = HttpClientTransport.insecureForTesting(
        client: mockClient,
        keysUrl: Uri.parse(_keysUrl),
        gatewayUrl: Uri.parse(_gatewayUrl),
      );
      final client = OhttpHttpClient(
        session: OhttpSession.withTransport(transport: transport, observer: observer),
      );

      final response = await client.send(Request('GET', Uri.parse('https://example.com/resource')));
      final body = await response.stream.toBytes();

      expect(response.statusCode, 200);
      expect(utf8.decode(body), 'hello');
      expect(observer.keyConfigFetched, isTrue, reason: 'onKeyConfigFetched must fire on cache miss');
      expect(observer.postToGateway, isTrue, reason: 'onPostToGateway must fire before the POST');
      expect(observer.keyConfigCacheHit, isFalse, reason: 'first call is always a miss');
      expect(observer.gatewayError, isFalse);
      expect(observer.decapsulationError, isFalse);
      expect(observer.encapsulationError, isFalse);
    });

    test('happy path: response headers survive the HPKE + BHTTP round trip', () async {
      final keyConfigBytes = _defaultKeyConfigBytes();
      final bhttpResponseBytes = _buildBhttpResponseWithHeaders(
        utf8.encode('hello'),
        [('content-type', 'text/plain')],
      );

      final mockClient = _buildMockClient(
        keyConfigBytes: keyConfigBytes,
        gatewayHandler: (req) => _gatewayHandlerFor(req, bhttpResponseBytes),
      );

      final transport = HttpClientTransport.insecureForTesting(
        client: mockClient,
        keysUrl: Uri.parse(_keysUrl),
        gatewayUrl: Uri.parse(_gatewayUrl),
      );
      final client = OhttpHttpClient(
        session: OhttpSession.withTransport(transport: transport),
      );

      final response = await client.send(Request('GET', Uri.parse('https://example.com/resource')));
      final body = await response.stream.toBytes();

      expect(response.statusCode, 200);
      expect(utf8.decode(body), 'hello');
      expect(
        response.headers['content-type'],
        'text/plain',
        reason: 'response headers must survive BHTTP decapsulation',
      );
    });

    test('happy path: request headers and body survive HPKE + BHTTP encapsulation', () async {
      // Verifies that the client serialises outbound headers into the BHTTP
      // request before encapsulation: openEncapsulatedRequest decrypts the
      // inner ciphertext and the custom header bytes must be present.
      final keyConfigBytes = _defaultKeyConfigBytes();
      Uint8List? decryptedBhttp;

      final bhttpResponseBytes = _buildBhttpResponse(utf8.encode('ok'));
      final mockClient = _buildMockClient(
        keyConfigBytes: keyConfigBytes,
        gatewayHandler: (request) async {
          final postBody = request.bodyBytes;
          decryptedBhttp = await openEncapsulatedRequest(postBody);
          // Still seal a valid response so client.send() completes normally.

          return _gatewayHandlerFor(request, bhttpResponseBytes);
        },
      );

      final transport = HttpClientTransport.insecureForTesting(
        client: mockClient,
        keysUrl: Uri.parse(_keysUrl),
        gatewayUrl: Uri.parse(_gatewayUrl),
      );
      final client = OhttpHttpClient(
        session: OhttpSession.withTransport(transport: transport),
      );

      final outboundRequest = Request('GET', Uri.parse('https://example.com/resource'));
      outboundRequest.headers['x-request-id'] = 'test-42';
      final response = await client.send(outboundRequest);
      await response.stream.drain<void>();

      expect(response.statusCode, 200);
      // BHTTP field names/values are written as raw ASCII bytes; String.fromCharCodes
      // lets us assert both are present without a full BHTTP parser.
      final bhttpStr = String.fromCharCodes(decryptedBhttp!);
      expect(
        bhttpStr,
        contains('x-request-id'),
        reason: 'request header name must survive HPKE + BHTTP encapsulation',
      );
      expect(
        bhttpStr,
        contains('test-42'),
        reason: 'request header value must survive HPKE + BHTTP encapsulation',
      );
    });

    test('cache hit: second send within TTL issues only one GET to keysUrl', () async {
      final keyConfigBytes = _defaultKeyConfigBytes();
      final bhttpResponseBytes = _buildBhttpResponse(utf8.encode('hi'));
      var keysGetCount = 0;

      final mockClient = MockClient((request) async {
        if (request.method == 'GET' && request.url.toString() == _keysUrl) {
          keysGetCount++;

          return Response.bytes(keyConfigBytes, 200);
        }
        if (request.method == 'POST' && request.url.toString() == _gatewayUrl) {
          return _gatewayHandlerFor(request, bhttpResponseBytes);
        }

        return Response('Not found', 404);
      });

      final observer = _TestObserver();
      final transport = HttpClientTransport.insecureForTesting(
        client: mockClient,
        keysUrl: Uri.parse(_keysUrl),
        gatewayUrl: Uri.parse(_gatewayUrl),
      );
      final client = OhttpHttpClient(
        session: OhttpSession.withTransport(transport: transport, observer: observer),
      );

      // First send — cache miss: exactly one GET to keysUrl.
      await (await client.send(Request('GET', Uri.parse('https://example.com/')))).stream.drain<void>();
      expect(keysGetCount, 1, reason: 'first send must fetch keysUrl once');
      expect(observer.keyConfigCacheHit, isFalse, reason: 'first send is a cache miss');

      // Second send — within TTL: cache hit, no additional GET.
      await (await client.send(Request('GET', Uri.parse('https://example.com/')))).stream.drain<void>();
      expect(keysGetCount, 1, reason: 'second send within TTL must not re-fetch keysUrl');
      expect(observer.keyConfigCacheHit, isTrue, reason: 'onKeyConfigCacheHit must fire on second send');
    });

    // -----------------------------------------------------------------------
    // Failure-path tests (phase 4)
    // -----------------------------------------------------------------------

    test('gateway 503 throws OhttpGatewayException and invalidates the cache', () async {
      final keyConfigBytes = _defaultKeyConfigBytes();
      var keysGetCount = 0;
      final mockClient = MockClient((request) async {
        if (request.method == 'GET' && request.url.toString() == _keysUrl) {
          keysGetCount++;

          return Response.bytes(keyConfigBytes, 200);
        }

        return Response('', 503);
      });
      final observer = _TestObserver();
      final transport = HttpClientTransport.insecureForTesting(
        client: mockClient,
        keysUrl: Uri.parse(_keysUrl),
        gatewayUrl: Uri.parse(_gatewayUrl),
      );
      final client = OhttpHttpClient(
        session: OhttpSession.withTransport(transport: transport, observer: observer),
      );

      // First send → OhttpGatewayException; cache must be invalidated.
      await expectLater(
        client.send(Request('GET', Uri.parse('https://example.com/'))),
        throwsA(isA<OhttpGatewayException>().having((e) => e.statusCode, 'statusCode', 503)),
      );
      expect(keysGetCount, 1);
      expect(observer.gatewayError, isTrue);
      expect(observer.lastGatewayErrorStatus, 503);
      expect(observer.cacheInvalidated, isTrue);

      // Second send → must re-fetch keysUrl because the cache was invalidated.
      await expectLater(
        client.send(Request('GET', Uri.parse('https://example.com/'))),
        throwsA(isA<OhttpGatewayException>()),
      );
      expect(keysGetCount, 2, reason: 'cache invalidation must trigger a second GET to keysUrl');
    });

    test('flipped ciphertext byte throws OhttpCryptoException', () async {
      final keyConfigBytes = _defaultKeyConfigBytes();
      final mockClient = _buildMockClient(
        keyConfigBytes: keyConfigBytes,
        gatewayHandler: (request) async {
          final postBody = request.bodyBytes;
          final exportedSecret = await decapExportedSecret(postBody);
          final enc = postBody.sublist(ohttpHeaderLen, ohttpHeaderLen + CipherSuite.kemPublicKeyLength);
          final bhttpResponseBytes = _buildBhttpResponse(utf8.encode('ok'));
          final sealed = await sealBhttpResponse(enc, exportedSecret, bhttpResponseBytes);
          // XOR the first ciphertext byte (immediately after the 16-byte response_nonce)
          // to produce an AEAD authentication failure.
          sealed[responseNonceLen] ^= 0xFF;

          return Response.bytes(sealed, 200);
        },
      );
      final observer = _TestObserver();
      final transport = HttpClientTransport.insecureForTesting(
        client: mockClient,
        keysUrl: Uri.parse(_keysUrl),
        gatewayUrl: Uri.parse(_gatewayUrl),
      );
      final client = OhttpHttpClient(
        session: OhttpSession.withTransport(transport: transport, observer: observer),
      );

      await expectLater(
        client.send(Request('GET', Uri.parse('https://example.com/'))),
        throwsA(isA<OhttpCryptoException>()),
      );
      expect(observer.decapsulationError, isTrue);
      expect(observer.lastDecapsulationErrorType, OhttpCryptoException);
    });

    test('truncated response body throws OhttpDecapsulationException', () async {
      final keyConfigBytes = _defaultKeyConfigBytes();
      // 8 bytes is fewer than responseNonceLen (16), so ohttpDecapsulate
      // must reject it as too short before attempting any AEAD operation.
      final mockClient = _buildMockClient(
        keyConfigBytes: keyConfigBytes,
        gatewayHandler: (request) async => Response.bytes(Uint8List(8), 200),
      );
      final observer = _TestObserver();
      final transport = HttpClientTransport.insecureForTesting(
        client: mockClient,
        keysUrl: Uri.parse(_keysUrl),
        gatewayUrl: Uri.parse(_gatewayUrl),
      );
      final client = OhttpHttpClient(
        session: OhttpSession.withTransport(transport: transport, observer: observer),
      );

      await expectLater(
        client.send(Request('GET', Uri.parse('https://example.com/'))),
        throwsA(isA<OhttpDecapsulationException>()),
      );
      expect(observer.decapsulationError, isTrue);
    });

    test('gateway POST delay exceeds timeout throws OhttpTimeoutException', () async {
      final keyConfigBytes = _defaultKeyConfigBytes();
      // Gateway delays 2 s — 20× the 100 ms transport timeout — to absorb CI variance.
      final mockClient = _buildMockClient(
        keyConfigBytes: keyConfigBytes,
        gatewayHandler: (request) async {
          await Future<void>.delayed(const Duration(seconds: 2));

          return Response('', 200);
        },
      );
      final transport = HttpClientTransport.insecureForTesting(
        client: mockClient,
        keysUrl: Uri.parse(_keysUrl),
        gatewayUrl: Uri.parse(_gatewayUrl),
        postToGatewayTimeout: const Duration(milliseconds: 100),
      );
      final client = OhttpHttpClient(
        session: OhttpSession.withTransport(transport: transport),
      );

      await expectLater(
        client.send(Request('GET', Uri.parse('https://example.com/'))),
        throwsA(isA<OhttpTimeoutException>()),
      );
    });

    test('response body over size cap throws OhttpSizeLimitException', () async {
      final keyConfigBytes = _defaultKeyConfigBytes();
      // 512-byte body exceeds the 64-byte cap; size check fires before decapsulation.
      final mockClient = _buildMockClient(
        keyConfigBytes: keyConfigBytes,
        gatewayHandler: (request) async => Response.bytes(Uint8List(512), 200),
      );
      final transport = HttpClientTransport.insecureForTesting(
        client: mockClient,
        keysUrl: Uri.parse(_keysUrl),
        gatewayUrl: Uri.parse(_gatewayUrl),
      );
      final client = OhttpHttpClient(
        session: OhttpSession.withTransport(
          transport: transport,
          maxEncryptedResponseBytes: 64,
        ),
      );

      await expectLater(
        client.send(Request('GET', Uri.parse('https://example.com/'))),
        throwsA(
          isA<OhttpSizeLimitException>()
              .having((e) => e.limit, 'limit', 64)
              .having((e) => e.actualSize, 'actualSize', 512),
        ),
      );
    });

    test('decrypted body over maxBodyBytes limit throws OhttpSizeLimitException', () async {
      final keyConfigBytes = _defaultKeyConfigBytes();
      // 100-byte BHTTP body; limit set to 50 — layer-2 check fires after HPKE decryption.
      final bhttpResponseBytes = _buildBhttpResponse(Uint8List(100));

      final mockClient = _buildMockClient(
        keyConfigBytes: keyConfigBytes,
        gatewayHandler: (req) => _gatewayHandlerFor(req, bhttpResponseBytes),
      );
      final transport = HttpClientTransport.insecureForTesting(
        client: mockClient,
        keysUrl: Uri.parse(_keysUrl),
        gatewayUrl: Uri.parse(_gatewayUrl),
      );
      final client = OhttpHttpClient(
        session: OhttpSession.withTransport(
          transport: transport,
          decryptedResponseLimits: const BhttpResponseLimits(maxBodyBytes: 50),
        ),
      );

      await expectLater(
        client.send(Request('GET', Uri.parse('https://example.com/'))),
        throwsA(
          isA<OhttpSizeLimitException>()
              .having((e) => e.limit, 'limit', 50)
              .having((e) => e.actualSize, 'actualSize', 100),
        ),
      );
    });

    test('unsupported cipher suite in KeyConfig throws OhttpUnsupportedSuiteException', () async {
      // KeyConfig advertises only kdf=0x0002/aead=0x0002 — no supported suite.
      // OhttpKeyConfig.parse() throws OhttpUnsupportedSuiteException before
      // ohttpEncapsulate is ever called, so encapsulationError is not set.
      final keyConfigBytes = multiSuiteKeyConfig(
        publicKey: gatewayPublicKeyBytes,
        suiteIds: [(0x0002, 0x0002)],
      );
      final mockClient = _buildMockClient(
        keyConfigBytes: keyConfigBytes,
        gatewayHandler: (request) async => Response('', 200),
      );
      final transport = HttpClientTransport.insecureForTesting(
        client: mockClient,
        keysUrl: Uri.parse(_keysUrl),
        gatewayUrl: Uri.parse(_gatewayUrl),
      );
      final observer = _TestObserver();
      final client = OhttpHttpClient(
        session: OhttpSession.withTransport(transport: transport, observer: observer),
      );

      await expectLater(
        client.send(Request('GET', Uri.parse('https://example.com/'))),
        throwsA(isA<OhttpUnsupportedSuiteException>()),
      );
      expect(observer.encapsulationError, isFalse);
      expect(observer.postToGateway, isFalse);
    });
  });
}
