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
import 'pipeline_test_utils.dart';

void main() {
  group('OhttpHttpClient integration (RFC 9458 end-to-end)', () {
    test('happy path: full round-trip decrypts canned BHTTP response', () async {
      // Use the fixed gateway public key so the sender's ohttpEncapsulate produces
      // an enc/exportedSecret the stub can re-derive via KEM decap.
      final keyConfigBytes = defaultKeyConfigBytes();
      final bhttpResponseBytes = buildBhttpResponse(utf8.encode('hello'));

      final mockClient = buildMockClient(
        keyConfigBytes: keyConfigBytes,
        gatewayHandler: (req) => gatewayHandlerFor(req, bhttpResponseBytes),
      );

      final observer = PipelineTestObserver();
      final transport = HttpClientTransport.insecureForTesting(
        client: mockClient,
        keysUrl: Uri.parse(testKeysUrl),
        gatewayUrl: Uri.parse(testGatewayUrl),
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
      final keyConfigBytes = defaultKeyConfigBytes();
      final bhttpResponseBytes = buildBhttpResponseWithHeaders(
        utf8.encode('hello'),
        [('content-type', 'text/plain')],
      );

      final mockClient = buildMockClient(
        keyConfigBytes: keyConfigBytes,
        gatewayHandler: (req) => gatewayHandlerFor(req, bhttpResponseBytes),
      );

      final transport = HttpClientTransport.insecureForTesting(
        client: mockClient,
        keysUrl: Uri.parse(testKeysUrl),
        gatewayUrl: Uri.parse(testGatewayUrl),
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
      final keyConfigBytes = defaultKeyConfigBytes();
      Uint8List? decryptedBhttp;

      final bhttpResponseBytes = buildBhttpResponse(utf8.encode('ok'));
      final mockClient = buildMockClient(
        keyConfigBytes: keyConfigBytes,
        gatewayHandler: (request) async {
          final postBody = request.bodyBytes;
          decryptedBhttp = await openEncapsulatedRequest(postBody);
          // Still seal a valid response so client.send() completes normally.

          return gatewayHandlerFor(request, bhttpResponseBytes);
        },
      );

      final transport = HttpClientTransport.insecureForTesting(
        client: mockClient,
        keysUrl: Uri.parse(testKeysUrl),
        gatewayUrl: Uri.parse(testGatewayUrl),
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
      final keyConfigBytes = defaultKeyConfigBytes();
      final bhttpResponseBytes = buildBhttpResponse(utf8.encode('hi'));
      var keysGetCount = 0;

      final mockClient = MockClient((request) async {
        if (request.method == 'GET' && request.url.toString() == testKeysUrl) {
          keysGetCount++;

          return Response.bytes(keyConfigBytes, 200);
        }
        if (request.method == 'POST' && request.url.toString() == testGatewayUrl) {
          return gatewayHandlerFor(request, bhttpResponseBytes);
        }

        return Response('Not found', 404);
      });

      final observer = PipelineTestObserver();
      final transport = HttpClientTransport.insecureForTesting(
        client: mockClient,
        keysUrl: Uri.parse(testKeysUrl),
        gatewayUrl: Uri.parse(testGatewayUrl),
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
      final keyConfigBytes = defaultKeyConfigBytes();
      var keysGetCount = 0;
      final mockClient = MockClient((request) async {
        if (request.method == 'GET' && request.url.toString() == testKeysUrl) {
          keysGetCount++;

          return Response.bytes(keyConfigBytes, 200);
        }

        return Response('', 503);
      });
      final observer = PipelineTestObserver();
      final transport = HttpClientTransport.insecureForTesting(
        client: mockClient,
        keysUrl: Uri.parse(testKeysUrl),
        gatewayUrl: Uri.parse(testGatewayUrl),
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
      final keyConfigBytes = defaultKeyConfigBytes();
      final mockClient = buildMockClient(
        keyConfigBytes: keyConfigBytes,
        gatewayHandler: (request) async {
          final postBody = request.bodyBytes;
          final exportedSecret = await decapExportedSecret(postBody);
          final enc = postBody.sublist(ohttpHeaderLen, ohttpHeaderLen + CipherSuite.kemPublicKeyLength);
          final bhttpResponseBytes = buildBhttpResponse(utf8.encode('ok'));
          final sealed = await sealBhttpResponse(enc, exportedSecret, bhttpResponseBytes);
          // XOR the first ciphertext byte (immediately after the 16-byte response_nonce)
          // to produce an AEAD authentication failure.
          sealed[responseNonceLen] ^= 0xFF;

          return Response.bytes(sealed, 200);
        },
      );
      final observer = PipelineTestObserver();
      final transport = HttpClientTransport.insecureForTesting(
        client: mockClient,
        keysUrl: Uri.parse(testKeysUrl),
        gatewayUrl: Uri.parse(testGatewayUrl),
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
      final keyConfigBytes = defaultKeyConfigBytes();
      // 8 bytes is fewer than responseNonceLen (16), so ohttpDecapsulate
      // must reject it as too short before attempting any AEAD operation.
      final mockClient = buildMockClient(
        keyConfigBytes: keyConfigBytes,
        gatewayHandler: (request) async => Response.bytes(Uint8List(8), 200),
      );
      final observer = PipelineTestObserver();
      final transport = HttpClientTransport.insecureForTesting(
        client: mockClient,
        keysUrl: Uri.parse(testKeysUrl),
        gatewayUrl: Uri.parse(testGatewayUrl),
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
      final keyConfigBytes = defaultKeyConfigBytes();
      // Gateway delays 2 s — 20× the 100 ms transport timeout — to absorb CI variance.
      final mockClient = buildMockClient(
        keyConfigBytes: keyConfigBytes,
        gatewayHandler: (request) async {
          await Future<void>.delayed(const Duration(seconds: 2));

          return Response('', 200);
        },
      );
      final transport = HttpClientTransport.insecureForTesting(
        client: mockClient,
        keysUrl: Uri.parse(testKeysUrl),
        gatewayUrl: Uri.parse(testGatewayUrl),
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
      final keyConfigBytes = defaultKeyConfigBytes();
      // 512-byte body exceeds the 64-byte cap; size check fires before decapsulation.
      final mockClient = buildMockClient(
        keyConfigBytes: keyConfigBytes,
        gatewayHandler: (request) async => Response.bytes(Uint8List(512), 200),
      );
      final transport = HttpClientTransport.insecureForTesting(
        client: mockClient,
        keysUrl: Uri.parse(testKeysUrl),
        gatewayUrl: Uri.parse(testGatewayUrl),
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
      final keyConfigBytes = defaultKeyConfigBytes();
      // 100-byte BHTTP body; limit set to 50 — layer-2 check fires after HPKE decryption.
      final bhttpResponseBytes = buildBhttpResponse(Uint8List(100));

      final mockClient = buildMockClient(
        keyConfigBytes: keyConfigBytes,
        gatewayHandler: (req) => gatewayHandlerFor(req, bhttpResponseBytes),
      );
      final transport = HttpClientTransport.insecureForTesting(
        client: mockClient,
        keysUrl: Uri.parse(testKeysUrl),
        gatewayUrl: Uri.parse(testGatewayUrl),
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
      final mockClient = buildMockClient(
        keyConfigBytes: keyConfigBytes,
        gatewayHandler: (request) async => Response('', 200),
      );
      final transport = HttpClientTransport.insecureForTesting(
        client: mockClient,
        keysUrl: Uri.parse(testKeysUrl),
        gatewayUrl: Uri.parse(testGatewayUrl),
      );
      final observer = PipelineTestObserver();
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
