import 'dart:typed_data';

import 'package:ohttp_dart/ohttp_dart.dart';
import 'package:test/test.dart';

import 'test_utils.dart';

/// Fake transport that records calls and can be instructed to succeed or fail.
class _FakeTransport implements OhttpTransport {
  final Uint8List config;
  _FakeTransport([Uint8List? config]) : config = config ?? validKeyConfig();

  int fetchCount = 0;
  int postCount = 0;

  Uint8List? lastPostBody;

  /// When set, [postToGateway] throws this instead of succeeding.
  Object? postError;

  @override
  Future<Uint8List> fetchKeyConfig() async {
    fetchCount++;

    return config;
  }

  @override
  Future<Uint8List> postToGateway(Uint8List body) async {
    postCount++;
    lastPostBody = body;
    if (postError != null) {
      throw postError!;
    }

    // Return arbitrary bytes; the caller is expected to handle decap failure.
    return Uint8List(64);
  }
}

void main() {
  group('OhttpSession', () {
    late _FakeTransport transport;
    late OhttpSession session;

    final request = OhttpRequestData(
      method: 'GET',
      scheme: 'https',
      authority: 'example.com',
      path: '/',
    );

    setUp(() {
      transport = _FakeTransport();
      session = OhttpSession(
        transport: transport,
        cache: KeyConfigCache(transport: transport),
      );
    });

    test('reuses cached KeyConfig across sends', () async {
      // Send a request — will fail at decapsulation because the fake
      // transport returns arbitrary bytes, but KeyConfig is fetched.
      await expectLater(session.send(request), throwsA(anything));
      expect(transport.fetchCount, 1);

      // Second send — KeyConfig must come from cache, not from transport.
      await expectLater(session.send(request), throwsA(anything));
      expect(transport.fetchCount, 1);
    });

    test('invalidates cache on OhttpGatewayException', () async {
      // Seed the cache.
      await expectLater(session.send(request), throwsA(anything));
      expect(transport.fetchCount, 1);

      // Make postToGateway fail with a gateway error.
      transport.postError = const OhttpGatewayException(statusCode: 502, message: 'bad gateway');

      await expectLater(session.send(request), throwsA(isA<OhttpGatewayException>()));
      // The gateway error invalidated the cache; the next send must re-fetch.
      expect(transport.fetchCount, 1); // invalidation does not itself fetch

      transport.postError = null;
      await expectLater(session.send(request), throwsA(anything));
      expect(transport.fetchCount, 2); // re-fetch after invalidation
    });

    test('does not invalidate cache on non-gateway error', () async {
      await expectLater(session.send(request), throwsA(anything));
      expect(transport.fetchCount, 1);

      transport.postError = OhttpNetworkException(
        'Network error while posting to Gateway',
        cause: Exception('connection refused'),
      );

      await expectLater(
        session.send(request),
        throwsA(isA<OhttpNetworkException>()),
      );
      // Cache is NOT invalidated — fetchCount stays at 1.
      expect(transport.fetchCount, 1);
    });

    test('passes non-empty body to transport', () async {
      await expectLater(session.send(request), throwsA(anything));

      expect(transport.postCount, 1);
      expect(transport.lastPostBody, isNotNull);
      expect(transport.lastPostBody!.isNotEmpty, isTrue);
    });
  });

  group('OhttpRequestData authority validation', () {
    test('accepts valid host', () {
      expect(
        () => OhttpRequestData(
          method: 'GET',
          scheme: 'https',
          authority: 'host.example.com',
          path: '/',
        ),
        returnsNormally,
      );
    });

    test('accepts host with port', () {
      expect(
        () => OhttpRequestData(
          method: 'GET',
          scheme: 'https',
          authority: 'host.example.com:8443',
          path: '/',
        ),
        returnsNormally,
      );
    });

    test('rejects empty authority', () {
      expect(
        () => OhttpRequestData(
          method: 'GET',
          scheme: 'https',
          authority: '',
          path: '/',
        ),
        throwsA(isA<OhttpConfigException>()),
      );
    });

    test('rejects authority with scheme prefix', () {
      expect(
        () => OhttpRequestData(
          method: 'GET',
          scheme: 'https',
          authority: 'https://host.example.com',
          path: '/',
        ),
        throwsA(isA<OhttpConfigException>()),
      );
    });

    test('rejects authority with space', () {
      expect(
        () => OhttpRequestData(
          method: 'GET',
          scheme: 'https',
          authority: 'host.example.com /path',
          path: '/',
        ),
        throwsA(isA<OhttpConfigException>()),
      );
    });

    test('rejects authority with path', () {
      expect(
        () => OhttpRequestData(
          method: 'GET',
          scheme: 'https',
          authority: 'host.example.com/path',
          path: '/',
        ),
        throwsA(isA<OhttpConfigException>()),
      );
    });

    test('rejects authority with query', () {
      expect(
        () => OhttpRequestData(
          method: 'GET',
          scheme: 'https',
          authority: 'host.example.com?q=1',
          path: '/',
        ),
        throwsA(isA<OhttpConfigException>()),
      );
    });

    test('rejects authority with fragment', () {
      expect(
        () => OhttpRequestData(
          method: 'GET',
          scheme: 'https',
          authority: 'host.example.com#frag',
          path: '/',
        ),
        throwsA(isA<OhttpConfigException>()),
      );
    });
  });
}
