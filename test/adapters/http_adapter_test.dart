import 'dart:typed_data';

import 'package:http/http.dart';
import 'package:http/testing.dart';
import 'package:ohttp_dart/http.dart';
import 'package:ohttp_dart/ohttp_dart.dart';
import 'package:test/test.dart';

import '../test_utils.dart';

MockClient _mockClient(
  String url, {
  Uint8List? body,
  int statusCode = 200,
}) => MockClient((request) async {
  if (request.url.toString() == url) {
    return Response.bytes(body ?? Uint8List(0), statusCode);
  }

  return Response('Not found', 404);
});

/// Client that tracks how many times [close] was called.
class _CloseTrackingClient extends BaseClient {
  int closeCallCount = 0;

  @override
  Future<StreamedResponse> send(BaseRequest request) async => StreamedResponse(ByteStream.fromBytes(Uint8List(0)), 200);

  @override
  void close() {
    closeCallCount++;
    super.close();
  }
}

/// Fake session that captures the [OhttpRequestData] for inspection.
class _FakeSession implements OhttpSession {
  final OhttpResponseData _response = OhttpResponseData(statusCode: 200, body: Uint8List(0));
  OhttpRequestData? lastRequest;

  @override
  Future<OhttpResponseData> send(OhttpRequestData request) async {
    lastRequest = request;

    return _response;
  }
}

void main() {
  const httpsKeysUrl = 'https://gateway.example.com/ohttp/config';
  const httpsRelayUrl = 'https://relay.example.com/ohttp/relay';

  group('HttpClientTransport URL validation', () {
    test('accepts https scheme for both URLs', () {
      final client = MockClient((request) async => Response.bytes(Uint8List(0), 200));

      expect(
        () => HttpClientTransport(
          client: client,
          keysUrl: Uri.parse(httpsKeysUrl),
          relayUrl: Uri.parse(httpsRelayUrl),
        ),
        returnsNormally,
      );
    });

    test('rejects http scheme for keysUrl', () {
      final client = MockClient((request) async => Response.bytes(Uint8List(0), 200));

      expect(
        () => HttpClientTransport(
          client: client,
          keysUrl: Uri.parse('http://gateway.example.com/ohttp/config'),
          relayUrl: Uri.parse(httpsRelayUrl),
        ),
        throwsA(isA<OhttpConfigException>()),
      );
    });

    test('rejects http scheme for relayUrl', () {
      final client = MockClient((request) async => Response.bytes(Uint8List(0), 200));

      expect(
        () => HttpClientTransport(
          client: client,
          keysUrl: Uri.parse(httpsKeysUrl),
          relayUrl: Uri.parse('http://relay.example.com/ohttp/relay'),
        ),
        throwsA(isA<OhttpConfigException>()),
      );
    });

    test('rejects ftp scheme', () {
      final client = MockClient((request) async => Response.bytes(Uint8List(0), 200));

      expect(
        () => HttpClientTransport(
          client: client,
          keysUrl: Uri.parse('ftp://gateway.example.com/ohttp/config'),
          relayUrl: Uri.parse(httpsRelayUrl),
        ),
        throwsA(isA<OhttpConfigException>()),
      );
    });

    test('rejects empty scheme', () {
      final client = MockClient((request) async => Response.bytes(Uint8List(0), 200));

      expect(
        () => HttpClientTransport(
          client: client,
          keysUrl: Uri.parse('gateway.example.com/ohttp/config'),
          relayUrl: Uri.parse(httpsRelayUrl),
        ),
        throwsA(isA<OhttpConfigException>()),
      );
    });

    test('allows http with insecureForTesting constructor', () {
      final client = MockClient((request) async => Response.bytes(Uint8List(0), 200));

      expect(
        () => HttpClientTransport.insecureForTesting(
          client: client,
          keysUrl: Uri.parse('http://localhost/ohttp/config'),
          relayUrl: Uri.parse('http://localhost/ohttp/relay'),
        ),
        returnsNormally,
      );
    });
  });

  group('HttpClientTransport timeout validation', () {
    final client = MockClient((request) async => Response.bytes(Uint8List(0), 200));
    final keysUrl = Uri.parse(httpsKeysUrl);
    final relayUrl = Uri.parse(httpsRelayUrl);

    test('rejects negative or zero Duration for either timeout', () {
      for (final invalid in [Duration.zero, const Duration(seconds: -1)]) {
        expect(
          () => HttpClientTransport(
            client: client,
            keysUrl: keysUrl,
            relayUrl: relayUrl,
            fetchKeyConfigTimeout: invalid,
          ),
          throwsA(isA<OhttpConfigException>()),
          reason: 'fetchKeyConfigTimeout = $invalid',
        );
        expect(
          () => HttpClientTransport(
            client: client,
            keysUrl: keysUrl,
            relayUrl: relayUrl,
            postToRelayTimeout: invalid,
          ),
          throwsA(isA<OhttpConfigException>()),
          reason: 'postToRelayTimeout = $invalid',
        );
        expect(
          () => HttpClientTransport.insecureForTesting(
            client: client,
            keysUrl: Uri.parse('http://localhost/ohttp/config'),
            relayUrl: Uri.parse('http://localhost/ohttp/relay'),
            fetchKeyConfigTimeout: invalid,
          ),
          throwsA(isA<OhttpConfigException>()),
          reason: 'insecureForTesting fetchKeyConfigTimeout = $invalid',
        );
      }
    });
  });

  group('HttpClientTransport', () {
    const keysUrl = 'http://localhost/ohttp/config';
    const relayUrl = 'http://localhost/ohttp/relay';

    test('fetchKeyConfig returns bytes on 200', () async {
      final client = _mockClient(keysUrl, body: validKeyConfig());
      final transport = HttpClientTransport.insecureForTesting(
        client: client,
        keysUrl: Uri.parse(keysUrl),
        relayUrl: Uri.parse(relayUrl),
      );

      final result = await transport.fetchKeyConfig();
      expect(result.bytes, validKeyConfig());
      expect(result.maxAge, isNull);
    });

    test('fetchKeyConfig throws OhttpRelayException on non-2xx', () async {
      final client = _mockClient(keysUrl, statusCode: 500);
      final transport = HttpClientTransport.insecureForTesting(
        client: client,
        keysUrl: Uri.parse(keysUrl),
        relayUrl: Uri.parse(relayUrl),
      );

      await expectLater(
        transport.fetchKeyConfig(),
        throwsA(isA<OhttpRelayException>().having((e) => e.statusCode, 'statusCode', 500)),
      );
    });

    test('postToRelay sends Content-Type message/ohttp-req', () async {
      final body = Uint8List.fromList([1, 2, 3]);
      final client = MockClient((request) async {
        expect(request.headers['content-type'], 'message/ohttp-req');
        expect(request.bodyBytes, body);

        return Response.bytes(Uint8List(4), 200);
      });

      final transport = HttpClientTransport.insecureForTesting(
        client: client,
        keysUrl: Uri.parse(keysUrl),
        relayUrl: Uri.parse(relayUrl),
      );

      await transport.postToRelay(body);
    });

    test('postToRelay throws OhttpRelayException on non-2xx', () async {
      final client = _mockClient(relayUrl, statusCode: 502);
      final transport = HttpClientTransport.insecureForTesting(
        client: client,
        keysUrl: Uri.parse(keysUrl),
        relayUrl: Uri.parse(relayUrl),
      );

      await expectLater(
        transport.postToRelay(Uint8List(0)),
        throwsA(isA<OhttpRelayException>().having((e) => e.statusCode, 'statusCode', 502)),
      );
    });

    test('wraps network errors in OhttpNetworkException during fetchKeyConfig', () async {
      final client = MockClient((request) async {
        throw ClientException('connection refused');
      });
      final transport = HttpClientTransport.insecureForTesting(
        client: client,
        keysUrl: Uri.parse(keysUrl),
        relayUrl: Uri.parse(relayUrl),
      );

      await expectLater(
        transport.fetchKeyConfig(),
        throwsA(
          isA<OhttpNetworkException>().having((e) => e.cause, 'cause', isA<ClientException>()),
        ),
      );
    });

    test('fetchKeyConfig throws OhttpRequestAbortedException on client-side cancellation', () async {
      final client = MockClient((request) async {
        throw RequestAbortedException();
      });
      final transport = HttpClientTransport.insecureForTesting(
        client: client,
        keysUrl: Uri.parse(keysUrl),
        relayUrl: Uri.parse(relayUrl),
      );

      await expectLater(
        transport.fetchKeyConfig(),
        throwsA(
          isA<OhttpRequestAbortedException>().having((e) => e.cause, 'cause', isA<RequestAbortedException>()),
        ),
      );
    });

    test('postToRelay throws OhttpRequestAbortedException on client-side cancellation', () async {
      final client = MockClient((request) async {
        throw RequestAbortedException();
      });
      final transport = HttpClientTransport.insecureForTesting(
        client: client,
        keysUrl: Uri.parse(keysUrl),
        relayUrl: Uri.parse(relayUrl),
      );

      await expectLater(
        transport.postToRelay(Uint8List(0)),
        throwsA(
          isA<OhttpRequestAbortedException>().having((e) => e.cause, 'cause', isA<RequestAbortedException>()),
        ),
      );
    });

    test('wraps network errors in OhttpNetworkException during postToRelay', () async {
      final client = MockClient((request) async {
        throw ClientException('connection refused');
      });
      final transport = HttpClientTransport.insecureForTesting(
        client: client,
        keysUrl: Uri.parse(keysUrl),
        relayUrl: Uri.parse(relayUrl),
      );

      await expectLater(
        transport.postToRelay(Uint8List(0)),
        throwsA(
          isA<OhttpNetworkException>().having((e) => e.cause, 'cause', isA<ClientException>()),
        ),
      );
    });

    test('fetchKeyConfig throws OhttpTimeoutException on timeout', () async {
      final client = MockClient((request) async {
        await Future<void>.delayed(const Duration(seconds: 2));

        return Response.bytes(Uint8List(0), 200);
      });
      final transport = HttpClientTransport.insecureForTesting(
        client: client,
        keysUrl: Uri.parse(keysUrl),
        relayUrl: Uri.parse(relayUrl),
        fetchKeyConfigTimeout: const Duration(milliseconds: 100),
      );

      await expectLater(
        transport.fetchKeyConfig(),
        throwsA(
          isA<OhttpTimeoutException>()
              .having((e) => e.message, 'message', contains('timeout'))
              .having((e) => e.timeout, 'timeout', const Duration(milliseconds: 100))
              .having((e) => e.url, 'url', Uri.parse(keysUrl)),
        ),
      );
    });

    test('postToRelay throws OhttpTimeoutException on timeout', () async {
      final client = MockClient((request) async {
        await Future<void>.delayed(const Duration(seconds: 2));

        return Response.bytes(Uint8List(0), 200);
      });
      final transport = HttpClientTransport.insecureForTesting(
        client: client,
        keysUrl: Uri.parse(keysUrl),
        relayUrl: Uri.parse(relayUrl),
        postToRelayTimeout: const Duration(milliseconds: 100),
      );

      await expectLater(
        transport.postToRelay(Uint8List(0)),
        throwsA(
          isA<OhttpTimeoutException>()
              .having((e) => e.timeout, 'timeout', const Duration(milliseconds: 100))
              .having((e) => e.url, 'url', Uri.parse(relayUrl)),
        ),
      );
    });

    test('respects custom timeout values', () async {
      final client = MockClient((request) async {
        await Future<void>.delayed(const Duration(milliseconds: 200));

        return Response.bytes(Uint8List(0), 200);
      });

      final transport = HttpClientTransport.insecureForTesting(
        client: client,
        keysUrl: Uri.parse(keysUrl),
        relayUrl: Uri.parse(relayUrl),
        fetchKeyConfigTimeout: const Duration(milliseconds: 300),
      );

      // Should succeed with 300ms timeout
      final result = await transport.fetchKeyConfig();
      expect(result, isNotNull);
    });

    group('Cache-Control max-age parsing', () {
      test('parses max-age from Cache-Control header', () async {
        final client = MockClient(
          (request) async => Response.bytes(
            validKeyConfig(),
            200,
            headers: {'cache-control': 'public, max-age=300'},
          ),
        );
        final transport = HttpClientTransport.insecureForTesting(
          client: client,
          keysUrl: Uri.parse(keysUrl),
          relayUrl: Uri.parse(relayUrl),
        );

        final result = await transport.fetchKeyConfig();
        expect(result.bytes, validKeyConfig());
        expect(result.maxAge, const Duration(seconds: 300));
      });

      test('returns null maxAge when no Cache-Control header', () async {
        final client = MockClient(
          (request) async => Response.bytes(validKeyConfig(), 200),
        );
        final transport = HttpClientTransport.insecureForTesting(
          client: client,
          keysUrl: Uri.parse(keysUrl),
          relayUrl: Uri.parse(relayUrl),
        );

        final result = await transport.fetchKeyConfig();
        expect(result.maxAge, isNull);
      });

      test('returns null maxAge for malformed max-age value', () async {
        final client = MockClient(
          (request) async => Response.bytes(
            validKeyConfig(),
            200,
            headers: {'cache-control': 'max-age=abc'},
          ),
        );
        final transport = HttpClientTransport.insecureForTesting(
          client: client,
          keysUrl: Uri.parse(keysUrl),
          relayUrl: Uri.parse(relayUrl),
        );

        final result = await transport.fetchKeyConfig();
        expect(result.maxAge, isNull);
      });

      test('parses max-age=0', () async {
        final client = MockClient(
          (request) async => Response.bytes(
            validKeyConfig(),
            200,
            headers: {'cache-control': 'max-age=0'},
          ),
        );
        final transport = HttpClientTransport.insecureForTesting(
          client: client,
          keysUrl: Uri.parse(keysUrl),
          relayUrl: Uri.parse(relayUrl),
        );

        final result = await transport.fetchKeyConfig();
        expect(result.maxAge, Duration.zero);
      });

      test('returns Duration.zero for no-cache', () async {
        final client = MockClient(
          (request) async => Response.bytes(
            validKeyConfig(),
            200,
            headers: {'cache-control': 'no-cache'},
          ),
        );
        final transport = HttpClientTransport.insecureForTesting(
          client: client,
          keysUrl: Uri.parse(keysUrl),
          relayUrl: Uri.parse(relayUrl),
        );

        final result = await transport.fetchKeyConfig();
        expect(result.maxAge, Duration.zero);
      });

      test('returns Duration.zero for no-store', () async {
        final client = MockClient(
          (request) async => Response.bytes(
            validKeyConfig(),
            200,
            headers: {'cache-control': 'no-store'},
          ),
        );
        final transport = HttpClientTransport.insecureForTesting(
          client: client,
          keysUrl: Uri.parse(keysUrl),
          relayUrl: Uri.parse(relayUrl),
        );

        final result = await transport.fetchKeyConfig();
        expect(result.maxAge, Duration.zero);
      });

      test('no-cache takes precedence over max-age', () async {
        final client = MockClient(
          (request) async => Response.bytes(
            validKeyConfig(),
            200,
            headers: {'cache-control': 'max-age=300, no-cache'},
          ),
        );
        final transport = HttpClientTransport.insecureForTesting(
          client: client,
          keysUrl: Uri.parse(keysUrl),
          relayUrl: Uri.parse(relayUrl),
        );

        final result = await transport.fetchKeyConfig();
        expect(result.maxAge, Duration.zero);
      });
    });
  });

  group('OhttpHttpClient', () {
    test('extracts method, scheme, authority, path from URL', () async {
      final session = _FakeSession();
      final client = OhttpHttpClient(session: session);
      final request = Request('POST', Uri.parse('https://example.com/api/data'));

      await client.send(request);

      expect(session.lastRequest!.method, 'POST');
      expect(session.lastRequest!.scheme, 'https');
      expect(session.lastRequest!.authority, 'example.com');
      expect(session.lastRequest!.path, '/api/data');
    });

    test('includes query string in path', () async {
      final session = _FakeSession();
      final client = OhttpHttpClient(session: session);
      final request = Request('GET', Uri.parse('https://example.com/api?key=value&foo=bar'));

      await client.send(request);

      expect(session.lastRequest!.path, '/api?key=value&foo=bar');
    });

    test('synthesises host header when absent', () async {
      final session = _FakeSession();
      final client = OhttpHttpClient(session: session);
      final request = Request('GET', Uri.parse('https://example.com/'));

      await client.send(request);

      final hostHeader = session.lastRequest!.headers.where((h) => h.$1 == 'host').firstOrNull;
      expect(hostHeader, isNotNull);
      expect(hostHeader!.$2, 'example.com');
    });

    test('preserves caller-supplied host header', () async {
      final session = _FakeSession();
      final client = OhttpHttpClient(session: session);
      final request = Request('GET', Uri.parse('https://example.com/'));
      request.headers['host'] = 'custom-host';

      await client.send(request);

      final hostHeader = session.lastRequest!.headers.where((h) => h.$1 == 'host').firstOrNull;
      expect(hostHeader!.$2, 'custom-host');
    });

    test('omits default https port from authority and host', () async {
      final session = _FakeSession();
      final client = OhttpHttpClient(session: session);
      final request = Request('GET', Uri.parse('https://example.com:443/'));

      await client.send(request);

      expect(session.lastRequest!.authority, 'example.com');
      final hostHeader = session.lastRequest!.headers.where((h) => h.$1 == 'host').firstOrNull;
      expect(hostHeader!.$2, 'example.com');
    });

    test('omits default http port from authority and host', () async {
      final session = _FakeSession();
      final client = OhttpHttpClient(session: session);
      final request = Request('GET', Uri.parse('http://example.com:80/'));

      await client.send(request);

      expect(session.lastRequest!.authority, 'example.com');
      final hostHeader = session.lastRequest!.headers.where((h) => h.$1 == 'host').firstOrNull;
      expect(hostHeader!.$2, 'example.com');
    });

    test('includes non-default port in authority and host', () async {
      final session = _FakeSession();
      final client = OhttpHttpClient(session: session);
      final request = Request('GET', Uri.parse('https://example.com:8443/'));

      await client.send(request);

      expect(session.lastRequest!.authority, 'example.com:8443');
      final hostHeader = session.lastRequest!.headers.where((h) => h.$1 == 'host').firstOrNull;
      expect(hostHeader!.$2, 'example.com:8443');
    });

    test('closeWith propagates close', () {
      const localKeysUrl = 'http://localhost/ohttp/config';
      const localRelayUrl = 'http://localhost/ohttp/relay';
      final raw = _mockClient(localKeysUrl);
      final transport = HttpClientTransport.insecureForTesting(
        client: raw,
        keysUrl: Uri.parse(localKeysUrl),
        relayUrl: Uri.parse(localRelayUrl),
      );
      final session = OhttpSession.withTransport(transport: transport);
      final client = OhttpHttpClient(session: session, closeWith: raw);

      client.close();
    });
  });

  group('OhttpHttpClient.create', () {
    test('close() closes the underlying client', () {
      final raw = _CloseTrackingClient();
      final client = OhttpHttpClient.create(
        client: raw,
        keysUrl: Uri.parse(httpsKeysUrl),
        relayUrl: Uri.parse(httpsRelayUrl),
      );

      expect(raw.closeCallCount, 0);
      client.close();
      expect(raw.closeCallCount, 1);
    });

    test('wires transport, cache, and session into a working client', () async {
      var keysUrlHit = false;
      final mockClient = MockClient((req) async {
        if (req.url.toString() == httpsKeysUrl) {
          keysUrlHit = true;

          return Response.bytes(validKeyConfig(), 200);
        }

        return Response.bytes(Uint8List(0), 200);
      });

      final client = OhttpHttpClient.create(
        client: mockClient,
        keysUrl: Uri.parse(httpsKeysUrl),
        relayUrl: Uri.parse(httpsRelayUrl),
      );

      // Decapsulation will fail (fake relay response), but the key config
      // fetch proves the wiring is correct.
      await expectLater(
        client.send(Request('GET', Uri.parse('https://example.com/'))),
        throwsA(isA<OhttpException>()),
      );
      expect(keysUrlHit, isTrue);
    });
  });
}
