// ignore_for_file: public_member_api_docs

/// Base exception class for all OHTTP library errors.
// ignore: prefer-match-file-name
sealed class OhttpException implements Exception {
  final String message;

  const OhttpException(this.message);

  @override
  String toString() => '$runtimeType: $message';
}

/// Thrown when configuration parameters are invalid or missing (e.g. wrong URL scheme, null arguments).
class OhttpConfigException extends OhttpException {
  const OhttpConfigException(super.message);
}

/// Thrown when the gateway's [KeyConfig] announces only cipher suites
/// that this library does not implement, or when a specific KEM/KDF/AEAD
/// component is not supported.
class OhttpUnsupportedSuiteException extends OhttpException {
  const OhttpUnsupportedSuiteException(super.message);
}

/// Thrown when the binary [KeyConfig] payload fetched from the gateway
/// is structurally malformed — too short, wrong lengths, trailing data,
/// invalid symmetric algorithms section, etc.
class OhttpKeyConfigException extends OhttpException {
  const OhttpKeyConfigException(super.message);
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

  const OhttpCryptoException(super.message, {this.cause});

  @override
  String toString() => cause != null ? '$runtimeType: $message (cause: $cause)' : super.toString();
}

/// Thrown when OHTTP response decapsulation fails (response too short,
/// ciphertext too short, or other structural issues).
class OhttpDecapsulationException extends OhttpException {
  const OhttpDecapsulationException(super.message);
}

/// Thrown when parsing of Binary HTTP (BHTTP, RFC 9292) data fails —
/// wrong framing indicator, truncated fields, etc.
/// This covers parsing of decrypted response bodies (framing, headers, varints).
class OhttpFormatException extends OhttpException {
  const OhttpFormatException(super.message);
}

/// Thrown when a network-level error occurs during transport (DNS failure,
/// connection refused, timeout, etc.).
class OhttpNetworkException extends OhttpException {
  /// The original error from the underlying HTTP client or network stack, if any.
  final Object? cause;

  const OhttpNetworkException(super.message, {this.cause});

  @override
  String toString() => cause != null ? '$runtimeType: $message (cause: $cause)' : super.toString();
}
