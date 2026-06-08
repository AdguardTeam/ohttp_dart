import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'cipher_suite.dart';
import 'exceptions.dart';
import 'hpke.dart';

// ---------------------------------------------------------------------------
// OHTTP KeyConfig (RFC 9458 §3)
// ---------------------------------------------------------------------------

/// Parsed OHTTP Key Configuration.
///
/// Format (41 bytes for our cipher suite):
///   key_id (1) || kem_id (2 BE) || public_key (32) ||
///   symmetric_algorithms_length (2 BE) || kdf_id (2 BE) || aead_id (2 BE)
// ignore: prefer-match-file-name
class OhttpKeyConfig {
  /// Key identifier (1 byte, RFC 9458 §3).
  final int keyId;

  /// KEM algorithm identifier.
  final int kemId;

  /// Recipient X25519 public key bytes.
  final Uint8List publicKey;

  /// KDF algorithm identifier.
  final int kdfId;

  /// AEAD algorithm identifier.
  final int aeadId;

  /// Creates an OHTTP key configuration.
  OhttpKeyConfig({
    required this.keyId,
    required this.kemId,
    required this.publicKey,
    required this.kdfId,
    required this.aeadId,
  });

  /// Parses a binary OHTTP key configuration per RFC 9458 §3.
  ///
  /// Throws [OhttpKeyConfigException] if [data] is structurally malformed.
  /// Throws [OhttpUnsupportedSuiteException] if no advertised cipher suite
  /// is supported by this library.
  factory OhttpKeyConfig.parse(Uint8List data) {
    if (data.length < 7) {
      throw OhttpKeyConfigException(
        'KeyConfig too short: ${data.length} bytes (min 7)',
      );
    }

    var offset = 0;
    final keyId = data[offset++];
    final kemId = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    // Public key length depends on KEM. For X25519 it's 32 bytes.
    final int pkLen;
    switch (kemId) {
      case CipherSuite.kemX25519Sha256:
        pkLen = CipherSuite.kemPublicKeyLength;
        break;
      default:
        throw OhttpUnsupportedSuiteException('Unsupported KEM: 0x${kemId.toRadixString(16)}');
    }

    if (data.length < offset + pkLen + 2) {
      throw const OhttpKeyConfigException('KeyConfig too short for public key');
    }
    final publicKey = Uint8List.fromList(data.sublist(offset, offset + pkLen));
    offset += pkLen;

    final symLen = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    // Validate: symLen must be >= 4, a multiple of 4 (each KDF+AEAD pair is 4 bytes),
    // and the data must contain exactly enough bytes for the section — no trailing
    // data is permitted after the symmetric algorithms section (RFC 9458 §3).
    if (symLen < 4 || symLen % 4 != 0 || data.length != offset + symLen) {
      throw OhttpKeyConfigException(
        'Invalid symmetric algorithms section: '
        'symLen=$symLen, data length ${data.length}, expected ${offset + symLen} '
        '(must be >= 4, a multiple of 4, and have no trailing data)',
      );
    }

    // Iterate through all KDF+AEAD pairs and select the first supported one.
    // RFC 9458 §4.1 allows a gateway to advertise multiple pairs.
    int? selectedKdfId;
    int? selectedAeadId;
    final symEnd = offset + symLen;

    while (offset < symEnd) {
      final pairKdfId = (data[offset] << 8) | data[offset + 1];
      offset += 2;
      final pairAeadId = (data[offset] << 8) | data[offset + 1];
      offset += 2;

      // Select first supported: HKDF-SHA256 + AES-128-GCM
      if (selectedKdfId == null && pairKdfId == CipherSuite.kdfHkdfSha256 && pairAeadId == CipherSuite.aeadAes128Gcm) {
        selectedKdfId = pairKdfId;
        selectedAeadId = pairAeadId;
        break;
      }
    }

    if (selectedKdfId == null || selectedAeadId == null) {
      throw OhttpUnsupportedSuiteException(
        'No supported cipher suite found in KeyConfig '
        '(expected KDF=HKDF-SHA256 0x${CipherSuite.kdfHkdfSha256.toRadixString(16)}, '
        'AEAD=AES-128-GCM 0x${CipherSuite.aeadAes128Gcm.toRadixString(16)})',
      );
    }

    return OhttpKeyConfig(
      keyId: keyId,
      kemId: kemId,
      publicKey: publicKey,
      kdfId: selectedKdfId,
      aeadId: selectedAeadId,
    );
  }

  /// Validates that the cipher suite is supported:
  /// X25519 (`0x0020`) + HKDF-SHA256 (`0x0001`) + AES-128-GCM (`0x0001`).
  ///
  /// Throws [OhttpUnsupportedSuiteException] if any component is not supported.
  void validate() {
    if (kemId != CipherSuite.kemX25519Sha256) {
      throw OhttpUnsupportedSuiteException(
        'Unsupported KEM: 0x${kemId.toRadixString(16)} '
        '(expected X25519 0x${CipherSuite.kemX25519Sha256.toRadixString(16)})',
      );
    }
    if (kdfId != CipherSuite.kdfHkdfSha256) {
      throw OhttpUnsupportedSuiteException(
        'Unsupported KDF: 0x${kdfId.toRadixString(16)} '
        '(expected HKDF-SHA256 0x${CipherSuite.kdfHkdfSha256.toRadixString(16)})',
      );
    }
    if (aeadId != CipherSuite.aeadAes128Gcm) {
      throw OhttpUnsupportedSuiteException(
        'Unsupported AEAD: 0x${aeadId.toRadixString(16)} '
        '(expected AES-128-GCM 0x${CipherSuite.aeadAes128Gcm.toRadixString(16)})',
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

  /// Creates an OHTTP encapsulation result.
  OhttpEncapsulateResult({
    required this.encRequest,
    required this.enc,
    required this.exportedSecret,
  });
}

// OHTTP response nonce length = max(Nn, Nk) per RFC 9458 §4.6.2.
// Derived from AEAD parameters: for AES-128-GCM, max(12, 16) = 16.
const _responseNonceLen = CipherSuite.aeadKeyLength > CipherSuite.aeadNonceLength
    ? CipherSuite.aeadKeyLength
    : CipherSuite.aeadNonceLength;

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
    throw OhttpDecapsulationException(
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
    CipherSuite.aeadKeyLength,
  );

  // nonce = HKDF-Expand(prk, "nonce", Nn)
  final aeadNonce = await HpkeSender.hkdfExpand(
    prk,
    Uint8List.fromList(utf8.encode('nonce')),
    CipherSuite.aeadNonceLength,
  );

  // AES-128-GCM decrypt with empty AAD
  const tagLen = CipherSuite.aeadTagLength;
  if (ciphertext.length < tagLen) {
    throw const OhttpDecapsulationException('Ciphertext too short for AES-GCM tag');
  }
  final ct = ciphertext.sublist(0, ciphertext.length - tagLen);
  final tag = ciphertext.sublist(ciphertext.length - tagLen);

  final aesGcm = AesGcm.with128bits();
  final secretBox = SecretBox(ct, nonce: aeadNonce, mac: Mac(tag));
  final List<int> plaintext;
  try {
    plaintext = await aesGcm.decrypt(
      secretBox,
      secretKey: SecretKeyData(aeadKey),
      aad: [],
    );
  } on Exception catch (e) {
    throw OhttpCryptoException('Failed to decrypt OHTTP response', cause: e);
  }

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
