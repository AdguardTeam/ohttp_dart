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

/// Builds a KeyConfig with multiple symmetric algorithm suite pairs.
Uint8List multiSuiteKeyConfig({
  required List<(int, int)> suiteIds,
  List<int>? publicKey,
  int kemId = 0x0020,
  int keyId = 0x01,
}) {
  final buf = BytesBuilder();
  buf.addByte(keyId);
  buf.addByte((kemId >> 8) & 0xFF);
  buf.addByte(kemId & 0xFF);
  buf.add(publicKey ?? List.filled(32, 0xAB));

  final symLen = suiteIds.length * 4;
  buf.addByte((symLen >> 8) & 0xFF);
  buf.addByte(symLen & 0xFF);

  for (final (kdf, aead) in suiteIds) {
    buf.addByte((kdf >> 8) & 0xFF);
    buf.addByte(kdf & 0xFF);
    buf.addByte((aead >> 8) & 0xFF);
    buf.addByte(aead & 0xFF);
  }

  return Uint8List.fromList(buf.toBytes());
}
