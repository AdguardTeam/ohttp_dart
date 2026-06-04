// ignore_for_file: public_member_api_docs

/// Base exception class for all OHTTP library errors.
// ignore: prefer-match-file-name
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

/// Thrown when a cryptographic operation fails (AEAD authentication error,
/// HPKE nonce overflow, etc.).
class OhttpCryptoException extends OhttpException {
  /// The original error from the underlying cryptographic library, if any.
  final Object? cause;

  OhttpCryptoException(super.message, {this.cause});

  @override
  String toString() => cause != null ? '$runtimeType: $message (cause: $cause)' : super.toString();
}

/// Thrown when OHTTP response decapsulation fails (response too short,
/// ciphertext too short, or other structural issues).
class OhttpDecapsulationException extends OhttpException {
  const OhttpDecapsulationException(super.message);
}

/// Thrown when parsing of binary data (KeyConfig, BHTTP) fails
class OhttpFormatException extends OhttpException {
  const OhttpFormatException(super.message);
}

/// Thrown when a network-level error occurs during transport (DNS failure,
/// connection refused, timeout, etc.).
class OhttpNetworkException extends OhttpException {
  /// The original error from the underlying HTTP client or network stack, if any.
  final Object? cause;

  OhttpNetworkException(super.message, {this.cause});

  @override
  String toString() => cause != null ? '$runtimeType: $message (cause: $cause)' : super.toString();
}
