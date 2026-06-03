import 'dart:typed_data';

import 'package:ohttp_dart/ohttp_dart.dart';
import 'package:test/test.dart';

import 'test_utils.dart';

/// Fake transport that returns a config and counts fetch calls.
class _FakeTransport implements OhttpTransport {
  final Uint8List config;
  int fetchCount = 0;
  Object? fetchError;

  _FakeTransport([Uint8List? config]) : config = config ?? validKeyConfig();

  @override
  Future<Uint8List> fetchKeyConfig() async {
    fetchCount++;
    if (fetchError != null) throw fetchError!;
    return config;
  }

  @override
  Future<Uint8List> postToGateway(Uint8List body) async {
    throw UnimplementedError();
  }
}

void main() {
  group('KeyConfigCache', () {
    late _FakeTransport transport;

    setUp(() {
      transport = _FakeTransport();
    });

    test('cold get fetches from transport', () async {
      final cache = KeyConfigCache(transport: transport);

      final config = await cache.get();

      expect(config.keyId, 0x01);
      expect(transport.fetchCount, 1);
    });

    test('hot get returns cached value within TTL', () async {
      final cache = KeyConfigCache(transport: transport);

      await cache.get();
      final config = await cache.get();

      expect(config.keyId, 0x01);
      expect(transport.fetchCount, 1);
    });

    test('TTL expiry triggers re-fetch', () async {
      var now = DateTime.now();
      final cache = KeyConfigCache(transport: transport, now: () => now);

      await cache.get();
      expect(transport.fetchCount, 1);

      // Advance past TTL
      now = now.add(const Duration(hours: 2));
      await cache.get();

      expect(transport.fetchCount, 2);
    });

    test('invalidate forces re-fetch', () async {
      final cache = KeyConfigCache(transport: transport);

      await cache.get();
      expect(transport.fetchCount, 1);

      cache.invalidate();
      await cache.get();

      expect(transport.fetchCount, 2);
    });

    test('parallel stale calls share a single fetch', () async {
      var now = DateTime.now();
      final cache = KeyConfigCache(transport: transport, now: () => now);

      await cache.get();
      expect(transport.fetchCount, 1);

      // Advance past TTL, then issue concurrent calls
      now = now.add(const Duration(hours: 2));
      final results = await Future.wait([cache.get(), cache.get(), cache.get()]);

      expect(results.map((c) => c.keyId), everyElement(0x01));
      expect(transport.fetchCount, 2); // only one additional fetch
    });

    test('fetch error propagates without evicting stale cache', () async {
      var now = DateTime.now();
      final cache = KeyConfigCache(transport: transport, now: () => now);

      await cache.get();
      expect(transport.fetchCount, 1);

      // Advance past TTL and make transport fail
      now = now.add(const Duration(hours: 2));
      transport.fetchError = Exception('Network error');

      await expectLater(cache.get(), throwsA(isA<Exception>()));
      expect(transport.fetchCount, 2);

      // Fix transport, cache should still have stale value and re-fetch
      transport.fetchError = null;
      final config = await cache.get();

      expect(config.keyId, 0x01);
      expect(transport.fetchCount, 3);
    });
  });
}
