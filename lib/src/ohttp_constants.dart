/// Default values for the OHTTP library
abstract final class OhttpConstants {
  /// Fallback cache TTL for [KeyConfigCache]
  static const fallbackKeyConfigCacheTtl = Duration(hours: 1);

  /// Default timeout for fetching the key config from the gateway.
  static const defaultFetchKeyConfigTimeout = Duration(seconds: 30);

  /// Default timeout for posting an encapsulated request to the gateway.
  static const defaultPostToGatewayTimeout = Duration(seconds: 30);

  /// Default limit for raw encrypted response body from the gateway.
  ///
  /// Accounts for BHTTP body plus OHTTP/BHTTP overhead
  /// (nonce, AEAD tag, framing, headers).
  static const defaultMaxEncryptedResponseBytes = 16 * 1024 * 1024; // 16 MiB

  /// Default maximum total size of decrypted response headers.
  static const defaultMaxResponseHeaderBytes = 16384; // 16 KiB

  /// Default maximum size of decrypted response body.
  static const defaultMaxResponseBodyBytes = 10 * 1024 * 1024; // 10 MiB
}
