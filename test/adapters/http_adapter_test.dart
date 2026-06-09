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
  const httpsGatewayUrl = 'https://gateway.example.com/ohttp/gateway';

  group('HttpClientTransport URL validation', () {
    test('accepts https scheme for both URLs', () {
      final client = MockClient((request) async => Response.bytes(Uint8List(0), 200));

      expect(
        () => HttpClientTransport(
          client: client,
          keysUrl: Uri.parse(httpsKeysUrl),
          gatewayUrl: Uri.parse(httpsGatewayUrl),
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
          gatewayUrl: Uri.parse(httpsGatewayUrl),
        ),
        throwsA(isA<OhttpConfigException>()),
      );
    });

    test('rejects http scheme for gatewayUrl', () {
      final client = MockClient((request) async => Response.bytes(Uint8List(0), 200));

      expect(
        () => HttpClientTransport(
          client: client,
          keysUrl: Uri.parse(httpsKeysUrl),
          gatewayUrl: Uri.parse('http://gateway.example.com/ohttp/gateway'),
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
          gatewayUrl: Uri.parse(httpsGatewayUrl),
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
          gatewayUrl: Uri.parse(httpsGatewayUrl),
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
          gatewayUrl: Uri.parse('http://localhost/ohttp/gateway'),
        ),
        returnsNormally,
      );
    });
  });

  group('HttpClientTransport', () {
    const keysUrl = 'http://localhost/ohttp/config';
    const gatewayUrl = 'http://localhost/ohttp/gateway';

    test('fetchKeyConfig returns bytes on 200', () async {
      final client = _mockClient(keysUrl, body: validKeyConfig());
      final transport = HttpClientTransport.insecureForTesting(
        client: client,
        keysUrl: Uri.parse(keysUrl),
        gatewayUrl: Uri.parse(gatewayUrl),
      );

      final result = await transport.fetchKeyConfig();
      expect(result, validKeyConfig());
    });

    test('fetchKeyConfig throws OhttpGatewayException on non-2xx', () async {
      final client = _mockClient(keysUrl, statusCode: 500);
      final transport = HttpClientTransport.insecureForTesting(
        client: client,
        keysUrl: Uri.parse(keysUrl),
        gatewayUrl: Uri.parse(gatewayUrl),
      );

      await expectLater(
        transport.fetchKeyConfig(),
        throwsA(isA<OhttpGatewayException>().having((e) => e.statusCode, 'statusCode', 500)),
      );
    });

    test('postToGateway sends Content-Type message/ohttp-req', () async {
      final body = Uint8List.fromList([1, 2, 3]);
      final client = MockClient((request) async {
        expect(request.headers['content-type'], 'message/ohttp-req');
        expect(request.bodyBytes, body);

        return Response.bytes(Uint8List(4), 200);
      });

      final transport = HttpClientTransport.insecureForTesting(
        client: client,
        keysUrl: Uri.parse(keysUrl),
        gatewayUrl: Uri.parse(gatewayUrl),
      );

      await transport.postToGateway(body);
    });

    test('postToGateway throws OhttpGatewayException on non-2xx', () async {
      final client = _mockClient(gatewayUrl, statusCode: 502);
      final transport = HttpClientTransport.insecureForTesting(
        client: client,
        keysUrl: Uri.parse(keysUrl),
        gatewayUrl: Uri.parse(gatewayUrl),
      );

      await expectLater(
        transport.postToGateway(Uint8List(0)),
        throwsA(isA<OhttpGatewayException>().having((e) => e.statusCode, 'statusCode', 502)),
      );
    });

    test('wraps network errors in OhttpNetworkException during fetchKeyConfig', () async {
      final client = MockClient((request) async {
        throw ClientException('connection refused');
      });
      final transport = HttpClientTransport.insecureForTesting(
        client: client,
        keysUrl: Uri.parse(keysUrl),
        gatewayUrl: Uri.parse(gatewayUrl),
      );

      await expectLater(
        transport.fetchKeyConfig(),
        throwsA(
          isA<OhttpNetworkException>().having((e) => e.cause, 'cause', isA<ClientException>()),
        ),
      );
    });

    test('fetchKeyConfig throws OhttpNetworkException on timeout', () async {
      final client = MockClient((request) async {
        await Future<void>.delayed(const Duration(seconds: 2));

        return Response.bytes(Uint8List(0), 200);
      });
      final transport = HttpClientTransport.insecureForTesting(
        client: client,
        keysUrl: Uri.parse(keysUrl),
        gatewayUrl: Uri.parse(gatewayUrl),
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

    test('postToGateway throws OhttpTimeoutException on timeout', () async {
      final client = MockClient((request) async {
        await Future<void>.delayed(const Duration(seconds: 2));

        return Response.bytes(Uint8List(0), 200);
      });
      final transport = HttpClientTransport.insecureForTesting(
        client: client,
        keysUrl: Uri.parse(keysUrl),
        gatewayUrl: Uri.parse(gatewayUrl),
        postToGatewayTimeout: const Duration(milliseconds: 100),
      );

      await expectLater(
        transport.postToGateway(Uint8List(0)),
        throwsA(
          isA<OhttpTimeoutException>()
              .having((e) => e.timeout, 'timeout', const Duration(milliseconds: 100))
              .having((e) => e.url, 'url', Uri.parse(gatewayUrl)),
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
        gatewayUrl: Uri.parse(gatewayUrl),
        fetchKeyConfigTimeout: const Duration(milliseconds: 300),
      );

      // Should succeed with 300ms timeout
      final result = await transport.fetchKeyConfig();
      expect(result, isNotNull);
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
      const localGatewayUrl = 'http://localhost/ohttp/gateway';
      final raw = _mockClient(localKeysUrl);
      final transport = HttpClientTransport.insecureForTesting(
        client: raw,
        keysUrl: Uri.parse(localKeysUrl),
        gatewayUrl: Uri.parse(localGatewayUrl),
      );
      final session = OhttpSession.withTransport(transport: transport);
      final client = OhttpHttpClient(session: session, closeWith: raw);

      client.close();
    });
  });
}
