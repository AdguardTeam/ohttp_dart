import 'dart:typed_data';

import 'package:ohttp_dart/ohttp_dart.dart';
import 'package:test/test.dart';

import 'test_utils.dart';

/// Observer that records callback invocations.
class _RecordingObserver extends OhttpObserver {
  final List<String> events = [];
  Object? lastDecapsulationError;
  Object? lastGatewayError;

  @override
  void onKeyConfigFetched() => events.add('fetched');

  @override
  void onKeyConfigCacheHit() => events.add('cacheHit');

  @override
  void onPostToGateway() => events.add('postToGateway');

  @override
  void onDecapsulationError([Object? error]) {
    events.add('decapsulationError');
    lastDecapsulationError = error;
  }

  @override
  void onGatewayError([Object? error]) {
    events.add('gatewayError');
    lastGatewayError = error;
  }

  @override
  void onCacheInvalidated() => events.add('cacheInvalidated');
}

/// Observer that throws from every callback.
class _ThrowingObserver extends OhttpObserver {
  @override
  void onKeyConfigFetched() => throw Exception('fail');

  @override
  void onKeyConfigCacheHit() => throw Exception('fail');

  @override
  void onPostToGateway() => throw Exception('fail');

  @override
  void onDecapsulationError([Object? error]) => throw Exception('fail');

  @override
  void onGatewayError([Object? error]) => throw Exception('fail');

  @override
  void onCacheInvalidated() => throw Exception('fail');

  @override
  void onEncapsulationError([Object? error]) => throw Exception('fail');
}

/// Fake transport for session-level tests.
class _FakeTransport implements OhttpTransport {
  final Uint8List config;
  _FakeTransport([Uint8List? config]) : config = config ?? validKeyConfig();

  int fetchCount = 0;
  Object? postError;

  @override
  Future<Uint8List> fetchKeyConfig() async {
    fetchCount++;

    return config;
  }

  @override
  Future<Uint8List> postToGateway(Uint8List body) async {
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

    test('onPostToGateway before POST', () async {
      await expectLater(makeSession().send(request), throwsA(anything));
      expect(observer.events, contains('postToGateway'));
    });

    test('onDecapsulationError on decryption failure', () async {
      await expectLater(makeSession().send(request), throwsA(isA<OhttpException>()));
      expect(observer.events, contains('decapsulationError'));
      expect(observer.lastDecapsulationError, isA<OhttpException>());
    });

    test('onGatewayError on OhttpGatewayException', () async {
      final s = makeSession();
      await expectLater(s.send(request), throwsA(anything)); // seed cache
      observer.events.clear();
      transport.postError = const OhttpGatewayException(statusCode: 502, message: 'bad gateway');

      await expectLater(s.send(request), throwsA(isA<OhttpGatewayException>()));
      expect(observer.events, contains('gatewayError'));
      expect(observer.events, contains('cacheInvalidated'));
      expect(observer.lastGatewayError, isA<OhttpGatewayException>());
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
  });
  group('KeyConfigCache with observer', () {
    test('onKeyConfigFetched on cold get', () async {
      final o = _RecordingObserver();
      final c = KeyConfigCache(transport: _FakeTransport(), observer: o);
      await c.get();
      expect(o.events, contains('fetched'));
    });

    test('onKeyConfigCacheHit on warm get', () async {
      final o = _RecordingObserver();
      final c = KeyConfigCache(transport: _FakeTransport(), observer: o);
      await c.get();
      o.events.clear();
      await c.get();
      expect(o.events, contains('cacheHit'));
    });

    test('throwing observer does not break cache', () async {
      final c = KeyConfigCache(transport: _FakeTransport(), observer: _ThrowingObserver());
      final config = await c.get();
      expect(config.keyId, 0x01);
      final config2 = await c.get();
      expect(config2.keyId, 0x01);
    });
  });
}
