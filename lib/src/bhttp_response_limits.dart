import 'ohttp_constants.dart';

/// Configuration for BHTTP response size limits.
/// Controls maximum allowed sizes for response headers and body to prevent resource exhaustion.
class BhttpResponseLimits {
  /// Maximum total size of all response headers in bytes.
  final int maxHeaderBytes;

  /// Maximum size of response body in bytes.
  final int maxBodyBytes;

  /// Creates response limits with specified or default values.
  const BhttpResponseLimits({
    this.maxHeaderBytes = OhttpConstants.defaultMaxResponseHeaderBytes,
    this.maxBodyBytes = OhttpConstants.defaultMaxResponseBodyBytes,
  });
}
