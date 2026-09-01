import 'dart:typed_data';

import 'package:ohttp_dart/ohttp_dart.dart';
import 'package:test/test.dart';

import 'test_utils.dart';

/// Observer that records callback invocations.
class _RecordingObserver extends OhttpObserver {
  final List<String> events = [];
  Type? lastDecapsulationError;
  int? lastRelayError;
  Type? lastEncapsulationError;
  Duration? lastRoundTripElapsed;
  OhttpRequestStage? lastAbortStage;

  @override
  void onKeyConfigFetched() => events.add('fetched');

  @override
  void onKeyConfigCacheHit() => events.add('cacheHit');

  @override
  void onPostToRelay() => events.add('postToRelay');

  @override
  void onDecapsulationError(Type errorType) {
    events.add('decapsulationError');
    lastDecapsulationError = errorType;
  }

  @override
  void onRelayError(int statusCode) {
    events.add('relayError');
    lastRelayError = statusCode;
  }

  @override
  void onEncapsulationError(Type errorType) {
    events.add('encapsulationError');
    lastEncapsulationError = errorType;
  }

  @override
  void onCacheInvalidated() => events.add('cacheInvalidated');

  @override
  void onRelayRetry() => events.add('relayRetry');

  @override
  void onRoundTripCompleted(Duration elapsed) {
    events.add('roundTripCompleted');
    lastRoundTripElapsed = elapsed;
  }

  @override
  void onRequestAborted(OhttpRequestStage stage) {
    events.add('requestAborted');
    lastAbortStage = stage;
  }
}

/// Observer that throws from every callback.
class _ThrowingObserver extends OhttpObserver {
  @override
  void onKeyConfigFetched() => throw Exception('fail');

  @override
  void onKeyConfigCacheHit() => throw Exception('fail');

  @override
  void onPostToRelay() => throw Exception('fail');

  @override
  void onDecapsulationError(Type errorType) => throw Exception('fail');

  @override
  void onRelayError(int statusCode) => throw Exception('fail');

  @override
  void onCacheInvalidated() => throw Exception('fail');

  @override
  void onEncapsulationError(Type errorType) => throw Exception('fail');

  @override
  void onRelayRetry() => throw Exception('fail');

  @override
  void onRoundTripCompleted(Duration elapsed) => throw Exception('fail');

  @override
  void onRequestAborted(OhttpRequestStage stage) => throw Exception('fail');
}

/// KeyConfigCache subclass that returns a config with unsupported KDF/AEAD,
/// causing ohttpEncapsulate() to throw OhttpUnsupportedSuiteException.
class _FailingEncapsulationCache extends KeyConfigCache {
  _FailingEncapsulationCache({
    required super.transport,
    super.observer,
  });

  @override
  Future<OhttpKeyConfig> get() async => OhttpKeyConfig(
    keyId: 0x01,
    kemId: 0x0020,
    publicKey: Uint8List(32),
    kdfId: 0x0002, // NOT HKDF-SHA256 — unsupported
    aeadId: 0x0002, // NOT AES-128-GCM — unsupported
  );
}

/// Fake transport for session-level tests.
class _FakeTransport implements OhttpTransport {
  final Uint8List config;
  _FakeTransport([Uint8List? config]) : config = config ?? validKeyConfig();

  int fetchCount = 0;
  Object? fetchError;
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
  Future<Uint8List> postToRelay(Uint8List body) async {
    if (postError != null) {
      throw postError!;
    }

    return Uint8List(64);
  }
}

void main() {
  final request = OhttpRequestData(method: 'GET', scheme: 'https', authority: 'example.com', path: '/');
  group('OhttpSession with observer', () {
    late _FakeTransport transport;
    late _RecordingObserver observer;

    setUp(() {
      transport = _FakeTransport();
      observer = _RecordingObserver();
    });

    OhttpSession makeSession() => OhttpSession(
      transport: transport,
      cache: KeyConfigCache(transport: transport, observer: observer),
      observer: observer,
    );

    test('onKeyConfigFetched on first send', () async {
      await expectLater(makeSession().send(request), throwsA(anything));
      expect(observer.events, contains('fetched'));
    });

    test('onKeyConfigCacheHit on second send', () async {
      final s = makeSession();
      await expectLater(s.send(request), throwsA(anything));
      observer.events.clear();
      await expectLater(s.send(request), throwsA(anything));
      expect(observer.events, contains('cacheHit'));
    });

    test('onPostToRelay before POST', () async {
      await expectLater(makeSession().send(request), throwsA(anything));
      expect(observer.events, contains('postToRelay'));
    });

    test('onDecapsulationError on decryption failure', () async {
      await expectLater(makeSession().send(request), throwsA(isA<OhttpException>()));
      expect(observer.events, contains('decapsulationError'));
      expect(observer.lastDecapsulationError, isNotNull);
    });

    test('onRelayError on OhttpRelayException', () async {
      final s = makeSession();
      await expectLater(s.send(request), throwsA(anything)); // seed cache
      observer.events.clear();
      transport.postError = const OhttpRelayException(statusCode: 502, message: 'bad relay');

      await expectLater(s.send(request), throwsA(isA<OhttpRelayException>()));
      expect(observer.events, contains('relayError'));
      expect(observer.events, contains('cacheInvalidated'));
      expect(observer.lastRelayError, 502);
    });

    test('throwing observer does not break pipeline', () async {
      final t = _ThrowingObserver();
      final s = OhttpSession(
        transport: transport,
        cache: KeyConfigCache(transport: transport, observer: t),
        observer: t,
      );
      await expectLater(s.send(request), throwsA(isA<OhttpException>()));
    });

    test('onEncapsulationError on encapsulation failure', () async {
      final observer = _RecordingObserver();
      final transport = _FakeTransport();
      final s = OhttpSession(
        transport: transport,
        cache: _FailingEncapsulationCache(transport: transport, observer: observer),
        observer: observer,
      );

      await expectLater(s.send(request), throwsA(isA<OhttpUnsupportedSuiteException>()));
      expect(observer.events, contains('encapsulationError'));
      expect(observer.lastEncapsulationError, OhttpUnsupportedSuiteException);
    });

    test('onRelayRetry is called on retry', () async {
      final s = makeSession();
      transport.postError = const OhttpRelayException(statusCode: 502, message: 'bad relay');

      await expectLater(s.send(request), throwsA(isA<OhttpRelayException>()));
      expect(observer.events, contains('relayRetry'));
    });

    test('onRelayRetry is not called when retryOnRelayError is false', () async {
      final s = OhttpSession(
        transport: transport,
        cache: KeyConfigCache(transport: transport, observer: observer),
        observer: observer,
        retryOnRelayError: false,
      );
      transport.postError = const OhttpRelayException(statusCode: 502, message: 'bad relay');

      await expectLater(s.send(request), throwsA(isA<OhttpRelayException>()));
      expect(observer.events, isNot(contains('relayRetry')));
    });

    test('onRoundTripCompleted is not called when send fails', () async {
      // Fake transport returns garbage bytes → decapsulation fails.
      // onRoundTripCompleted must NOT fire on error paths.
      await expectLater(makeSession().send(request), throwsA(isA<OhttpException>()));
      expect(observer.events, isNot(contains('roundTripCompleted')));
    });

    test('onRequestAborted with keyConfigFetch stage on aborted config fetch', () async {
      transport.fetchError = const OhttpRequestAbortedException('aborted');

      await expectLater(makeSession().send(request), throwsA(isA<OhttpRequestAbortedException>()));
      expect(observer.events, contains('requestAborted'));
      expect(observer.lastAbortStage, OhttpRequestStage.keyConfigFetch);
      expect(observer.events, isNot(contains('relayRetry')));
      expect(observer.events, isNot(contains('cacheInvalidated')));
    });

    test('onRequestAborted with relayPost stage on aborted relay post', () async {
      final s = makeSession();
      await expectLater(s.send(request), throwsA(anything)); // seed cache
      observer.events.clear();
      transport.postError = const OhttpRequestAbortedException('aborted');

      await expectLater(s.send(request), throwsA(isA<OhttpRequestAbortedException>()));
      expect(observer.events, contains('requestAborted'));
      expect(observer.lastAbortStage, OhttpRequestStage.relayPost);
      expect(observer.events, isNot(contains('relayError')));
      expect(observer.events, isNot(contains('cacheInvalidated')));
      expect(observer.events, isNot(contains('relayRetry')));
      expect(observer.events, isNot(contains('roundTripCompleted')));
    });

    test('throwing observer does not break pipeline on abort', () async {
      transport.postError = const OhttpRequestAbortedException('aborted');
      final s = OhttpSession(
        transport: transport,
        cache: KeyConfigCache(transport: transport, observer: _ThrowingObserver()),
        observer: _ThrowingObserver(),
      );

      await expectLater(s.send(request), throwsA(isA<OhttpRequestAbortedException>()));
    });
  });
  group('KeyConfigCache with observer', () {
    test('onKeyConfigFetched on cold get', () async {
      final observer = _RecordingObserver();
      final cache = KeyConfigCache(transport: _FakeTransport(), observer: observer);
      await cache.get();
      expect(observer.events, contains('fetched'));
    });

    test('onKeyConfigCacheHit on warm get', () async {
      final observer = _RecordingObserver();
      final cache = KeyConfigCache(transport: _FakeTransport(), observer: observer);
      await cache.get();
      observer.events.clear();
      await cache.get();
      expect(observer.events, contains('cacheHit'));
    });

    test('throwing observer does not break cache', () async {
      final cache = KeyConfigCache(transport: _FakeTransport(), observer: _ThrowingObserver());
      final config = await cache.get();
      expect(config.keyId, 0x01);
      final config2 = await cache.get();
      expect(config2.keyId, 0x01);
    });

    test('onCacheInvalidated on direct invalidate', () async {
      final observer = _RecordingObserver();
      final cache = KeyConfigCache(transport: _FakeTransport(), observer: observer);
      await cache.get();
      observer.events.clear();

      cache.invalidate();
      expect(observer.events, contains('cacheInvalidated'));
    });
  });
}
