/// Cipher suite identifiers for HPKE (RFC 9180).
class CipherSuite {
  /// KEM identifier: DHKEM(X25519, HKDF-SHA256) = `0x0020` (RFC 9180).
  static const int kemX25519Sha256 = 0x0020;

  /// KDF identifier: HKDF-SHA256 = `0x0001` (RFC 9180).
  static const int kdfHkdfSha256 = 0x0001;

  /// AEAD identifier: AES-128-GCM = `0x0001` (RFC 9180).
  static const int aeadAes128Gcm = 0x0001;
}
