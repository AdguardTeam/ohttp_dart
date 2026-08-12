import 'dart:typed_data';

/// Result of fetching a key config from the transport.
class KeyConfigFetchResult {
  /// Raw key config binary data.
  final Uint8List bytes;

  /// Server-provided TTL from `Cache-Control: max-age` in seconds, `null` if absent.
  final Duration? maxAge;

  /// Creates a [KeyConfigFetchResult]
  const KeyConfigFetchResult({
    required this.bytes,
    required this.maxAge,
  });
}
