import 'dart:typed_data';

import 'package:ohttp_dart/ohttp_dart.dart';
import 'package:test/test.dart';

import 'test_utils.dart';

/// Fake transport that returns a config and counts fetch calls.
class _FakeTransport implements OhttpTransport {
  final Uint8List config;
  _FakeTransport([Uint8List? config]) : config = config ?? validKeyConfig();

  int fetchCount = 0;

  Object? fetchError;

  Duration? maxAge;

  @override
  Future<KeyConfigFetchResult> fetchKeyConfig() async {
    fetchCount++;
    if (fetchError != null) {
      throw fetchError!;
    }

    return KeyConfigFetchResult(bytes: config, maxAge: maxAge);
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

    group('TTL resolution', () {
      test('uses server max-age when ttl is null', () async {
        var now = DateTime(2026);
        transport.maxAge = const Duration(seconds: 120);
        final cache = KeyConfigCache(transport: transport, now: () => now);

        await cache.get();
        expect(transport.fetchCount, 1);

        // Advance 119 s — still cached
        now = now.add(const Duration(seconds: 119));
        await cache.get();
        expect(transport.fetchCount, 1);

        // Advance past 120 s — triggers re-fetch
        now = now.add(const Duration(seconds: 2));
        await cache.get();
        expect(transport.fetchCount, 2);
      });

      test('explicit ttl takes priority over server max-age', () async {
        var now = DateTime(2026);
        transport.maxAge = const Duration(seconds: 120);
        final cache = KeyConfigCache(
          transport: transport,
          now: () => now,
          ttl: const Duration(minutes: 10),
        );

        await cache.get();

        // Advance past server max-age but within explicit ttl
        now = now.add(const Duration(minutes: 5));
        await cache.get();
        expect(transport.fetchCount, 1, reason: 'explicit ttl wins over server max-age');

        // Advance past explicit ttl
        now = now.add(const Duration(minutes: 6));
        await cache.get();
        expect(transport.fetchCount, 2);
      });

      test('falls back to OhttpConstants.defaultKeyConfigCacheTtl when max-age is null', () async {
        var now = DateTime(2026);
        transport.maxAge = null;
        final cache = KeyConfigCache(transport: transport, now: () => now);

        await cache.get();

        // Advance to just before TTL expiry
        now = now.add(OhttpConstants.defaultKeyConfigCacheTtl - const Duration(minutes: 1));
        await cache.get();
        expect(transport.fetchCount, 1);

        // Advance past TTL
        now = now.add(const Duration(minutes: 2));
        await cache.get();
        expect(transport.fetchCount, 2);
      });

      test('max-age=0 causes re-fetch on every get', () async {
        var now = DateTime(2026);
        transport.maxAge = Duration.zero;
        final cache = KeyConfigCache(transport: transport, now: () => now);

        await cache.get();
        expect(transport.fetchCount, 1);

        await cache.get();
        expect(transport.fetchCount, 2);
      });

      test('re-fetch uses new max-age from fresh response', () async {
        var now = DateTime(2026);
        transport.maxAge = const Duration(seconds: 120);
        final cache = KeyConfigCache(transport: transport, now: () => now);

        await cache.get();
        expect(transport.fetchCount, 1);

        // Advance past old 120 s max-age to trigger re-fetch
        now = now.add(const Duration(seconds: 121));
        transport.maxAge = const Duration(seconds: 300);
        await cache.get();
        expect(transport.fetchCount, 2);

        // Advance 200 s — within new 300 s TTL
        now = now.add(const Duration(seconds: 200));
        await cache.get();
        expect(transport.fetchCount, 2, reason: 'new max-age of 300 s keeps entry cached');

        // Advance past new 300 s TTL
        now = now.add(const Duration(seconds: 101));
        await cache.get();
        expect(transport.fetchCount, 3);
      });
    });
  });
}
