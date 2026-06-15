// ignore_for_file: public_member_api_docs

/// Base exception class for all OHTTP library errors.
// ignore: prefer-match-file-name
sealed class OhttpException implements Exception {
  final String message;
  final StackTrace? stackTrace;

  const OhttpException(this.message, {this.stackTrace});

  /// The message without stack trace. Override to customize formatting
  String get baseMessage => '$runtimeType: $message';

  @override
  String toString() {
    final s = baseMessage;

    return stackTrace != null ? '$s\n$stackTrace' : s;
  }
}

/// Thrown when configuration parameters are invalid or missing (e.g. wrong URL scheme, null arguments).
class OhttpConfigException extends OhttpException {
  const OhttpConfigException(super.message, {super.stackTrace});
}

/// Thrown when the gateway's [KeyConfig] announces only cipher suites
/// that this library does not implement, or when a specific KEM/KDF/AEAD
/// component is not supported.
class OhttpUnsupportedSuiteException extends OhttpException {
  const OhttpUnsupportedSuiteException(super.message, {super.stackTrace});
}

/// Thrown when the binary [KeyConfig] payload fetched from the gateway
/// is structurally malformed — too short, wrong lengths, trailing data,
/// invalid symmetric algorithms section, etc.
class OhttpKeyConfigException extends OhttpException {
  const OhttpKeyConfigException(super.message, {super.stackTrace});
}

/// Thrown by [OhttpTransport] implementations when the gateway returns
/// a non-2xx response.
class OhttpGatewayException extends OhttpException {
  final int statusCode;

  const OhttpGatewayException({
    super.stackTrace,
    required this.statusCode,
    required String message,
  }) : super(message);

  @override
  String get baseMessage => 'OhttpGatewayException($statusCode): $message';
}

/// Thrown when a cryptographic operation fails (AEAD authentication error,
/// HPKE nonce overflow, etc.).
class OhttpCryptoException extends OhttpException {
  /// The original error from the underlying cryptographic library, if any.
  final Object? cause;

  const OhttpCryptoException(super.message, {super.stackTrace, this.cause});

  @override
  String get baseMessage => cause != null ? '$runtimeType: $message (cause: $cause)' : super.baseMessage;
}

/// Thrown when OHTTP response decapsulation fails (response too short,
/// ciphertext too short, or other structural issues).
class OhttpDecapsulationException extends OhttpException {
  const OhttpDecapsulationException(super.message, {super.stackTrace});
}

/// Thrown when parsing of Binary HTTP (BHTTP, RFC 9292) data fails —
/// wrong framing indicator, truncated fields, etc.
/// This covers parsing of decrypted response bodies (framing, headers, varints).
class OhttpFormatException extends OhttpException {
  const OhttpFormatException(super.message, {super.stackTrace});
}

/// Thrown when response data exceeds configured size limits.
class OhttpSizeLimitException extends OhttpException {
  /// The maximum allowed size in bytes.
  final int limit;

  /// The actual size in bytes that was received or attempted.
  final int actualSize;

  const OhttpSizeLimitException({
    super.stackTrace,
    required String message,
    required this.limit,
    required this.actualSize,
  }) : super(message);

  @override
  String get baseMessage => 'OhttpSizeLimitException: $message (limit: $limit bytes, actual: $actualSize bytes)';
}

/// Thrown when a network-level error occurs during transport (DNS failure,
/// connection refused, timeout, etc.).
class OhttpNetworkException extends OhttpException {
  /// The original error from the underlying HTTP client or network stack, if any.
  final Object? cause;

  const OhttpNetworkException(super.message, {super.stackTrace, this.cause});

  @override
  String get baseMessage => cause != null ? '$runtimeType: $message (cause: $cause)' : super.baseMessage;
}

/// Thrown when an HTTP request exceeds its configured timeout.
class OhttpTimeoutException extends OhttpNetworkException {
  /// The timeout duration that was exceeded.
  final Duration timeout;

  /// The URL that was being requested when the timeout occurred.
  final Uri? url;

  const OhttpTimeoutException({
    super.stackTrace,
    required String message,
    required this.timeout,
    this.url,
  }) : super(message);

  @override
  String get baseMessage {
    final urlPart = url != null ? ' for $url' : '';

    return 'OhttpTimeoutException: $message$urlPart (timeout: ${timeout.inSeconds}s)';
  }
}
