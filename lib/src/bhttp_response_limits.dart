import 'exceptions.dart';

/// Configuration for BHTTP response size limits.
/// Controls maximum allowed sizes for response headers and body to prevent resource exhaustion.
class BhttpResponseLimits {
  static const int _defaultMaxHeaderBytes = 16384; // 16 KiB

  static const int _defaultMaxBodyBytes = 10 * 1024 * 1024; // 10 MiB

  /// Maximum total size of all response headers in bytes.
  final int maxHeaderBytes;

  /// Maximum size of response body in bytes.
  final int maxBodyBytes;

  /// Creates response limits with specified or default values.
  ///
  /// Throws [OhttpConfigException] if [maxHeaderBytes] or [maxBodyBytes] is not positive.
  const BhttpResponseLimits({
    this.maxHeaderBytes = _defaultMaxHeaderBytes,
    this.maxBodyBytes = _defaultMaxBodyBytes,
  });
}
