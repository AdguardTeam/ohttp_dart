import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'hpke.dart';

// ---------------------------------------------------------------------------
// OHTTP KeyConfig (RFC 9458 §3)
// ---------------------------------------------------------------------------

/// Parsed OHTTP Key Configuration.
///
/// Format (41 bytes for our cipher suite):
///   key_id (1) || kem_id (2 BE) || public_key (32) ||
///   symmetric_algorithms_length (2 BE) || kdf_id (2 BE) || aead_id (2 BE)
class OhttpKeyConfig {
  final int keyId;
  final int kemId;
  final Uint8List publicKey;
  final int kdfId;
  final int aeadId;

  OhttpKeyConfig({
    required this.keyId,
    required this.kemId,
    required this.publicKey,
    required this.kdfId,
    required this.aeadId,
  });

  factory OhttpKeyConfig.parse(Uint8List data) {
    if (data.length < 7) {
      throw FormatException(
        'KeyConfig too short: ${data.length} bytes (min 7)',
      );
    }

    var offset = 0;
    final keyId = data[offset++];
    final kemId = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    // Public key length depends on KEM. For X25519 (0x0020) it's 32 bytes.
    final int pkLen;
    switch (kemId) {
      case 0x0020:
        pkLen = 32;
        break;
      default:
        throw FormatException('Unsupported KEM: 0x${kemId.toRadixString(16)}');
    }

    if (data.length < offset + pkLen + 2) {
      throw const FormatException('KeyConfig too short for public key');
    }
    final publicKey = Uint8List.fromList(data.sublist(offset, offset + pkLen));
    offset += pkLen;

    final symLen = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    if (symLen < 4 || data.length < offset + symLen) {
      throw const FormatException('Invalid symmetric algorithms section');
    }

    // Read first (and typically only) KDF+AEAD pair
    final kdfId = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    final aeadId = (data[offset] << 8) | data[offset + 1];

    return OhttpKeyConfig(
      keyId: keyId,
      kemId: kemId,
      publicKey: publicKey,
      kdfId: kdfId,
      aeadId: aeadId,
    );
  }

  void validate() {
    if (kemId != 0x0020) {
      throw UnsupportedError(
        'Unsupported KEM: 0x${kemId.toRadixString(16)} (expected X25519 0x0020)',
      );
    }
    if (kdfId != 0x0001) {
      throw UnsupportedError(
        'Unsupported KDF: 0x${kdfId.toRadixString(16)} (expected HKDF-SHA256 0x0001)',
      );
    }
    if (aeadId != 0x0001) {
      throw UnsupportedError(
        'Unsupported AEAD: 0x${aeadId.toRadixString(16)} (expected AES-128-GCM 0x0001)',
      );
    }
  }
}

// ---------------------------------------------------------------------------
// OHTTP Encapsulation / Decapsulation (RFC 9458)
// ---------------------------------------------------------------------------

/// Result of OHTTP request encapsulation.
class OhttpEncapsulateResult {
  /// The complete encapsulated request to POST to the gateway.
  final Uint8List encRequest;

  /// The 32-byte HPKE enc value (needed for response decapsulation).
  final Uint8List enc;

  /// The exported secret (needed for response decapsulation).
  final Uint8List exportedSecret;

  OhttpEncapsulateResult({
    required this.encRequest,
    required this.enc,
    required this.exportedSecret,
  });
}

// AES-128-GCM parameters
const int _nk = 16;
const int _nn = 12;
const int _responseNonceLen = 16; // max(Nn, Nk)

/// Encapsulate a BHTTP request via OHTTP (RFC 9458 §4.6.1).
///
/// Returns the encapsulated request bytes, the HPKE enc value,
/// and the exported secret for later response decapsulation.
Future<OhttpEncapsulateResult> ohttpEncapsulate(
  OhttpKeyConfig config,
  Uint8List binaryRequest, {
  SimpleKeyPairData? testKeyPair,
}) async {
  config.validate();

  // info = "message/bhttp request" || 0x00 || key_id || kem_id || kdf_id || aead_id
  final info = _buildHpkeInfo(config);

  // HPKE SetupBaseS
  final ctx = await HpkeSender.setupBaseS(
    config.publicKey,
    info,
    testKeyPair: testKeyPair,
  );

  // Seal with empty AAD (per reference Go implementation, not RFC header)
  final ct = await ctx.seal(Uint8List(0), binaryRequest);

  // Export secret for response decryption
  final responseContext = utf8.encode('message/bhttp response');
  final exportedSecret = await ctx.export(
    Uint8List.fromList(responseContext),
    _responseNonceLen,
  );

  // Assemble: header(7) || enc(32) || ciphertext
  final header = _buildRequestHeader(config);
  final encRequest = Uint8List.fromList([...header, ...ctx.enc, ...ct]);

  return OhttpEncapsulateResult(
    encRequest: encRequest,
    enc: ctx.enc,
    exportedSecret: exportedSecret,
  );
}

/// Decapsulate an OHTTP response (RFC 9458 §4.6.2).
///
/// Takes the HPKE enc and exported secret from encapsulation,
/// plus the raw encrypted response from the gateway.
/// Returns the decrypted BHTTP response bytes.
Future<Uint8List> ohttpDecapsulate(
  Uint8List enc,
  Uint8List exportedSecret,
  Uint8List encResponse,
) async {
  if (encResponse.length <= _responseNonceLen) {
    throw FormatException(
      'Encrypted response too short: ${encResponse.length} bytes',
    );
  }

  // response_nonce || ciphertext
  final responseNonce = encResponse.sublist(0, _responseNonceLen);
  final ciphertext = encResponse.sublist(_responseNonceLen);

  // salt = enc || response_nonce
  final salt = Uint8List.fromList([...enc, ...responseNonce]);

  // prk = HKDF-Extract(salt, secret) — plain HKDF, not labeled
  final prk = await HpkeSender.hkdfExtract(salt, exportedSecret);

  // key = HKDF-Expand(prk, "key", Nk)
  final aeadKey = await HpkeSender.hkdfExpand(
    prk,
    Uint8List.fromList(utf8.encode('key')),
    _nk,
  );

  // nonce = HKDF-Expand(prk, "nonce", Nn)
  final aeadNonce = await HpkeSender.hkdfExpand(
    prk,
    Uint8List.fromList(utf8.encode('nonce')),
    _nn,
  );

  // AES-128-GCM decrypt with empty AAD
  final tagLen = 16;
  if (ciphertext.length < tagLen) {
    throw const FormatException('Ciphertext too short for AES-GCM tag');
  }
  final ct = ciphertext.sublist(0, ciphertext.length - tagLen);
  final tag = ciphertext.sublist(ciphertext.length - tagLen);

  final aesGcm = AesGcm.with128bits();
  final secretBox = SecretBox(ct, nonce: aeadNonce, mac: Mac(tag));
  final plaintext = await aesGcm.decrypt(
    secretBox,
    secretKey: SecretKeyData(aeadKey),
    aad: [],
  );

  return Uint8List.fromList(plaintext);
}

// -- Helpers --

/// Build HPKE info per RFC 9458 §4.3:
/// "message/bhttp request" || 0x00 || key_id(1) || kem_id(2) || kdf_id(2) || aead_id(2)
Uint8List _buildHpkeInfo(OhttpKeyConfig config) {
  final label = utf8.encode('message/bhttp request');
  final buf = BytesBuilder();
  buf.add(label);
  buf.addByte(0x00);
  buf.addByte(config.keyId);
  buf.addByte((config.kemId >> 8) & 0xFF);
  buf.addByte(config.kemId & 0xFF);
  buf.addByte((config.kdfId >> 8) & 0xFF);
  buf.addByte(config.kdfId & 0xFF);
  buf.addByte((config.aeadId >> 8) & 0xFF);
  buf.addByte(config.aeadId & 0xFF);
  return buf.toBytes();
}

/// Build 7-byte OHTTP request header:
/// key_id(1) || kem_id(2 BE) || kdf_id(2 BE) || aead_id(2 BE)
Uint8List _buildRequestHeader(OhttpKeyConfig config) => Uint8List.fromList([
  config.keyId,
  (config.kemId >> 8) & 0xFF,
  config.kemId & 0xFF,
  (config.kdfId >> 8) & 0xFF,
  config.kdfId & 0xFF,
  (config.aeadId >> 8) & 0xFF,
  config.aeadId & 0xFF,
]);
