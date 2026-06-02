import 'ohttp.dart';
import 'transport.dart';

/// A time-to-live cache for the gateway's parsed [OhttpKeyConfig].
///
/// Caches a fetched configuration up to the configured TTL. Concurrent
/// callers that find the cache stale share a single in-flight fetch
/// (single-flight deduplication). A fetch failure is propagated to callers
/// but does not evict a previously cached stale entry - use [invalidate]
/// for forced eviction.
///
/// The injectable [_now] parameter (defaults to [DateTime.now]) enables
/// deterministic TTL tests.
class KeyConfigCache {
  static const _defaultTtl = Duration(hours: 1);

  final OhttpTransport _transport;
  final Duration _ttl;
  final DateTime Function() _now;

  OhttpKeyConfig? _cached;
  DateTime _expiresAt = DateTime.fromMillisecondsSinceEpoch(0);
  Future<OhttpKeyConfig>? _pendingFetch;

  KeyConfigCache({
    required OhttpTransport transport,
    Duration ttl = _defaultTtl,
    DateTime Function()? now,
  }) : _transport = transport,
       _ttl = ttl,
       _now = now ?? (() => DateTime.now());

  /// Returns the parsed [OhttpKeyConfig], reusing a cached value while it
  /// is within the TTL. When the cache is cold or stale, a new fetch is
  /// issued; concurrent callers share a single in-flight fetch.
  Future<OhttpKeyConfig> get() async {
    if (_cached != null && _now().isBefore(_expiresAt)) {
      return _cached!;
    }

    if (_pendingFetch != null) {
      return _pendingFetch!;
    }

    final fetch = _fetch();
    _pendingFetch = fetch;
    try {
      final config = await fetch;
      _cached = config;
      _expiresAt = _now().add(_ttl);

      return config;
    } finally {
      _pendingFetch = null;
    }
  }

  /// Evicts the cached configuration so that the next [get] performs a
  /// fresh fetch unconditionally.
  void invalidate() => _cached = null;

  Future<OhttpKeyConfig> _fetch() async {
    final bytes = await _transport.fetchKeyConfig();
    final config = OhttpKeyConfig.parse(bytes);
    config.validate();

    return config;
  }
}
