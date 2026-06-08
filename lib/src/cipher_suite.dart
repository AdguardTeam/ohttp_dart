/// Cipher suite identifiers for HPKE (RFC 9180).
class CipherSuite {
  /// KEM identifier: DHKEM(X25519, HKDF-SHA256) = `0x0020` (RFC 9180).
  static const int kemX25519Sha256 = 0x0020;

  /// KDF identifier: HKDF-SHA256 = `0x0001` (RFC 9180).
  static const int kdfHkdfSha256 = 0x0001;

  /// AEAD identifier: AES-128-GCM = `0x0001` (RFC 9180).
  static const int aeadAes128Gcm = 0x0001;

  // -- Algorithm parameters --

  /// X25519 shared secret length in bytes (RFC 9180 §4.1).
  static const int kemSharedSecretLength = 32;

  /// X25519 public key length in bytes (RFC 7748, RFC 9180 §7.1).
  static const int kemPublicKeyLength = 32;

  /// HKDF-SHA256 hash output length in bytes (RFC 5869).
  static const int kdfHashLength = 32;

  /// AES-128-GCM key length in bytes (RFC 9180 §4).
  static const int aeadKeyLength = 16;

  /// AES-128-GCM nonce length in bytes (RFC 9180 §4).
  static const int aeadNonceLength = 12;

  /// AES-128-GCM authentication tag length in bytes (NIST SP 800-38D).
  static const int aeadTagLength = 16;
}
