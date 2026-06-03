/// Base exception class for all OHTTP library errors.
///
/// This provides a common type for catching any OHTTP-related exception
abstract class OhttpException implements Exception {
  final String message;

  const OhttpException(this.message);

  @override
  String toString() => '$runtimeType: $message';
}

/// Thrown when configuration parameters are invalid or missing.
class OhttpConfigException extends OhttpException {
  const OhttpConfigException(super.message);
}

/// Thrown by [OhttpTransport] implementations when the gateway returns
/// a non-2xx response.
class OhttpGatewayException extends OhttpException {
  final int statusCode;

  const OhttpGatewayException({
    required this.statusCode,
    required String message,
  }) : super(message);

  @override
  String toString() => 'OhttpGatewayException($statusCode): $message';
}
