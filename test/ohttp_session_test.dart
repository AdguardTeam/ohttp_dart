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
  Uint8List? responseBody;

  Uint8List? lastPostBody;

  /// When set, [fetchKeyConfig] throws this instead of succeeding.
  Object? fetchError;

  /// When set, [postToGateway] throws this instead of succeeding.
  Object? postError;

  @override
  Future<KeyConfigFetchResult> fetchKeyConfig() async {
    fetchCount++;
    if (fetchError != null) {
      throw fetchError!;
    }

    return KeyConfigFetchResult(bytes: config);
  }

  @override
  Future<Uint8List> postToGateway(Uint8List body) async {
    postCount++;
    lastPostBody = body;
    if (postError != null) {
      throw postError!;
    }

    // Return configured response body or arbitrary bytes.
    return responseBody ?? Uint8List(64);
  }
}

/// Observer that records whether [onGatewayRetry] was called.
class _RetryObserver extends OhttpObserver {
  int retryCount = 0;

  @override
  void onGatewayRetry() => retryCount++;
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
      // Use a no-retry session so cache invalidation mechanics can be tested
      // in isolation without the automatic retry fetching a new key config.
      final noRetrySession = OhttpSession(
        transport: transport,
        cache: KeyConfigCache(transport: transport),
        retryOnGatewayError: false,
      );

      // Seed the cache.
      await expectLater(noRetrySession.send(request), throwsA(anything));
      expect(transport.fetchCount, 1);

      // Make postToGateway fail with a gateway error.
      transport.postError = const OhttpGatewayException(statusCode: 502, message: 'bad gateway');

      await expectLater(noRetrySession.send(request), throwsA(isA<OhttpGatewayException>()));
      // The gateway error invalidated the cache; the next send must re-fetch.
      expect(transport.fetchCount, 1); // invalidation does not itself fetch

      transport.postError = null;
      await expectLater(noRetrySession.send(request), throwsA(anything));
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

    test('throws OhttpSizeLimitException when response exceeds maxEncryptedResponseBytes', () async {
      // Configure transport to return a large response
      transport.responseBody = Uint8List(1000);

      final limitedSession = OhttpSession(
        transport: transport,
        cache: KeyConfigCache(transport: transport),
        maxEncryptedResponseBytes: 500, // Set limit below actual response size
      );

      await expectLater(
        limitedSession.send(request),
        throwsA(
          isA<OhttpSizeLimitException>()
              .having((e) => e.limit, 'limit', 500)
              .having((e) => e.actualSize, 'actualSize', 1000)
              .having((e) => e.message, 'message', contains('size exceeds limit')),
        ),
      );
    });

    test('accepts response within maxEncryptedResponseBytes limit', () async {
      transport.responseBody = Uint8List(500);

      final limitedSession = OhttpSession(
        transport: transport,
        cache: KeyConfigCache(transport: transport),
        maxEncryptedResponseBytes: 1000,
      );

      // Will fail at decapsulation (fake bytes), but should NOT throw
      // OhttpSizeLimitException
      await expectLater(
        limitedSession.send(request),
        throwsA(
          isNot(isA<OhttpSizeLimitException>()),
        ),
      );
    });

    test('accepts response exactly at maxEncryptedResponseBytes boundary', () async {
      const limit = 500;
      transport.responseBody = Uint8List(limit);

      final limitedSession = OhttpSession(
        transport: transport,
        cache: KeyConfigCache(transport: transport),
        maxEncryptedResponseBytes: limit,
      );

      // Will fail at decapsulation (fake bytes), but should NOT throw
      // OhttpSizeLimitException — size == limit is allowed
      await expectLater(
        limitedSession.send(request),
        throwsA(
          isNot(isA<OhttpSizeLimitException>()),
        ),
      );
    });

    test('throws OhttpSizeLimitException when response is one byte over maxEncryptedResponseBytes', () async {
      const limit = 500;
      transport.responseBody = Uint8List(limit + 1);

      final limitedSession = OhttpSession(
        transport: transport,
        cache: KeyConfigCache(transport: transport),
        maxEncryptedResponseBytes: limit,
      );

      await expectLater(
        limitedSession.send(request),
        throwsA(
          isA<OhttpSizeLimitException>()
              .having((e) => e.limit, 'limit', limit)
              .having((e) => e.actualSize, 'actualSize', limit + 1),
        ),
      );
    });

    test('uses default maxEncryptedResponseBytes of 16 MiB', () async {
      // Response larger than 16 MiB should fail
      transport.responseBody = Uint8List(17 * 1024 * 1024); // 17 MiB

      await expectLater(
        session.send(request),
        throwsA(isA<OhttpSizeLimitException>()),
      );
    });

    test('throws OhttpConfigException when maxEncryptedResponseBytes is zero', () {
      expect(
        () => OhttpSession(
          transport: transport,
          cache: KeyConfigCache(transport: transport),
          maxEncryptedResponseBytes: 0,
        ),
        throwsA(isA<OhttpConfigException>()),
      );
    });

    test('throws OhttpConfigException when maxEncryptedResponseBytes is negative', () {
      expect(
        () => OhttpSession(
          transport: transport,
          cache: KeyConfigCache(transport: transport),
          maxEncryptedResponseBytes: -1,
        ),
        throwsA(isA<OhttpConfigException>()),
      );
    });

    test('throws OhttpConfigException when decryptedResponseLimits.maxHeaderBytes is zero', () {
      expect(
        () => OhttpSession(
          transport: transport,
          cache: KeyConfigCache(transport: transport),
          decryptedResponseLimits: const BhttpResponseLimits(maxHeaderBytes: 0),
        ),
        throwsA(isA<OhttpConfigException>()),
      );
    });

    test('throws OhttpConfigException when decryptedResponseLimits.maxHeaderBytes is negative', () {
      expect(
        () => OhttpSession(
          transport: transport,
          cache: KeyConfigCache(transport: transport),
          decryptedResponseLimits: const BhttpResponseLimits(maxHeaderBytes: -1),
        ),
        throwsA(isA<OhttpConfigException>()),
      );
    });

    test('throws OhttpConfigException when decryptedResponseLimits.maxBodyBytes is zero', () {
      expect(
        () => OhttpSession(
          transport: transport,
          cache: KeyConfigCache(transport: transport),
          decryptedResponseLimits: const BhttpResponseLimits(maxBodyBytes: 0),
        ),
        throwsA(isA<OhttpConfigException>()),
      );
    });

    test('throws OhttpConfigException when decryptedResponseLimits.maxBodyBytes is negative', () {
      expect(
        () => OhttpSession(
          transport: transport,
          cache: KeyConfigCache(transport: transport),
          decryptedResponseLimits: const BhttpResponseLimits(maxBodyBytes: -1),
        ),
        throwsA(isA<OhttpConfigException>()),
      );
    });

    test('throws OhttpConfigException when withTransport has invalid decryptedResponseLimits', () {
      expect(
        () => OhttpSession.withTransport(
          transport: transport,
          decryptedResponseLimits: const BhttpResponseLimits(maxHeaderBytes: -1),
        ),
        throwsA(isA<OhttpConfigException>()),
      );
    });

    test('withTransport forwards keyConfigCacheTtl to cache', () async {
      final ttlSession = OhttpSession.withTransport(
        transport: transport,
        keyConfigCacheTtl: const Duration(milliseconds: 50),
      );

      // First send fetches the key config.
      await expectLater(ttlSession.send(request), throwsA(anything));
      expect(transport.fetchCount, 1);

      // Wait for the short TTL to expire
      await Future<void>.delayed(const Duration(milliseconds: 300));

      // Second send must re-fetch because the TTL has expired.
      await expectLater(ttlSession.send(request), throwsA(anything));
      expect(transport.fetchCount, 2);
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

  group('Retry on gateway error', () {
    late _FakeTransport transport;

    final request = OhttpRequestData(
      method: 'GET',
      scheme: 'https',
      authority: 'example.com',
      path: '/',
    );

    setUp(() => transport = _FakeTransport());

    OhttpSession makeSession({bool retry = true}) => OhttpSession(
      transport: transport,
      cache: KeyConfigCache(transport: transport),
      retryOnGatewayError: retry,
    );

    test('retries once on OhttpGatewayException', () async {
      transport.postError = const OhttpGatewayException(statusCode: 502, message: 'bad gateway');

      await expectLater(
        makeSession().send(request),
        throwsA(isA<OhttpGatewayException>()),
      );
      expect(transport.postCount, 2); // tried twice
      expect(transport.fetchCount, 2); // fetched fresh key for retry
    });

    test('does not retry when retryOnGatewayError is false', () async {
      transport.postError = const OhttpGatewayException(statusCode: 502, message: 'bad gateway');

      await expectLater(
        makeSession(retry: false).send(request),
        throwsA(isA<OhttpGatewayException>()),
      );
      expect(transport.postCount, 1);
      expect(transport.fetchCount, 1);
    });

    test('does not retry on non-gateway errors', () async {
      transport.postError = OhttpNetworkException(
        'network error',
        cause: Exception('connection refused'),
      );

      await expectLater(
        makeSession().send(request),
        throwsA(isA<OhttpNetworkException>()),
      );
      expect(transport.postCount, 1); // no retry for non-gateway errors
    });

    test('does not retry when keys endpoint returns an error', () async {
      // A failing key-config fetch (keys endpoint down) must NOT be treated
      // as a gateway POST error — no retry, no onGatewayRetry.
      transport.fetchError = const OhttpGatewayException(statusCode: 503, message: 'keys endpoint down');
      final observer = _RetryObserver();
      final s = OhttpSession(
        transport: transport,
        cache: KeyConfigCache(transport: transport),
        observer: observer,
      );

      await expectLater(
        s.send(request),
        throwsA(isA<OhttpGatewayException>()),
      );
      expect(transport.fetchCount, 1); // exactly one fetch attempt
      expect(transport.postCount, 0); // never reached the gateway
      expect(observer.retryCount, 0); // no retry fired
    });
  });

  group('OhttpResponseData header normalization', () {
    test('lowercases header names', () {
      final response = OhttpResponseData(
        statusCode: 200,
        headers: [
          ('Content-Type', 'application/json'),
          ('X-Custom-Header', 'value'),
          ('UPPERCASE', 'test'),
        ],
        body: Uint8List(0),
      );

      expect(response.headers[0].$1, 'content-type');
      expect(response.headers[1].$1, 'x-custom-header');
      expect(response.headers[2].$1, 'uppercase');
    });

    test('preserves header values unchanged', () {
      final response = OhttpResponseData(
        statusCode: 200,
        headers: [('Content-Type', 'Application/JSON')],
        body: Uint8List(0),
      );

      expect(response.headers[0].$1, 'content-type');
      expect(response.headers[0].$2, 'Application/JSON');
    });
  });
}
