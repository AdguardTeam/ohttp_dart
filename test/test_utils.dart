import 'dart:typed_data';

/// A valid 41-byte KeyConfig for the supported cipher suite
/// (key_id=1, X25519, HKDF-SHA256, AES-128-GCM).
Uint8List validKeyConfig() => Uint8List.fromList([
  0x01,
  0x00,
  0x20,
  ...List.filled(32, 0xAB),
  0x00,
  0x04,
  0x00,
  0x01,
  0x00,
  0x01,
]);
