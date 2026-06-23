// ignore_for_file: public_member_api_docs

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:ohttp_dart/ohttp_dart.dart';
import 'package:ohttp_dart/src/cipher_suite.dart';

/// Hard-coded X25519 private key bytes for the simulated gateway.
/// Generated offline; corresponds to [gatewayPublicKeyBytes].
/// Test-only: never referenced in production code.
const List<int> gatewayPrivateKeyBytes = [
  0x10,
  0x1c,
  0x5e,
  0xbd,
  0xfc,
  0x94,
  0xf2,
  0x7b,
  0x63,
  0x0a,
  0x08,
  0x8b,
  0x86,
  0xd8,
  0x50,
  0x7b,
  0x79,
  0xd1,
  0xe3,
  0x13,
  0x48,
  0x2b,
  0x6e,
  0x7e,
  0xb2,
  0x50,
  0x05,
  0xff,
  0x81,
  0xaf,
  0x42,
  0x79,
];

/// Hard-coded X25519 public key bytes for the simulated gateway.
/// Derived from [gatewayPrivateKeyBytes].
const List<int> gatewayPublicKeyBytes = [
  0xf1,
  0xad,
  0xd0,
  0x65,
  0xca,
  0xce,
  0x94,
  0xf1,
  0x6c,
  0xff,
  0x7b,
  0x67,
  0x91,
  0x21,
  0xff,
  0xfc,
  0x2e,
  0xd8,
  0x76,
  0xe6,
  0x18,
  0x81,
  0x61,
  0xdd,
  0xaf,
  0x78,
  0xd0,
  0x9c,
  0x19,
  0xe7,
  0x4d,
  0x21,
];

/// Response nonce length per RFC 9458 §4.6.2: max(Nn, Nk).
const int responseNonceLen = CipherSuite.aeadKeyLength > CipherSuite.aeadNonceLength
    ? CipherSuite.aeadKeyLength
    : CipherSuite.aeadNonceLength;

/// Builds an [OhttpKeyConfig] from the fixed [gatewayPublicKeyBytes].
///
/// Uses key_id=0x01, kem_id=0x0020 (DHKEM X25519), kdf_id=0x0001 (HKDF-SHA256),
/// aead_id=0x0001 (AES-128-GCM).
OhttpKeyConfig buildGatewayKeyConfig() => OhttpKeyConfig(
  keyId: 0x01,
  kemId: 0x0020,
  publicKey: Uint8List.fromList(gatewayPublicKeyBytes),
  kdfId: 0x0001,
  aeadId: 0x0001,
);

/// Derives response key material and AES-128-GCM-encrypts [bhttpResponse]
/// per RFC 9458 §4.6.2, using a zero-filled response_nonce for determinism.
///
/// Returns `response_nonce ‖ ciphertext ‖ GCM-tag`.
Future<Uint8List> sealBhttpResponse(
  Uint8List enc,
  Uint8List exportedSecret,
  Uint8List bhttpResponse,
) async {
  // response_nonce is zero-filled (length = max(Nk, Nn)); deterministic for tests.
  final responseNonce = Uint8List(responseNonceLen);

  // salt = enc || response_nonce
  final salt = Uint8List(enc.length + responseNonceLen)
    ..setAll(0, enc)
    ..setAll(enc.length, responseNonce);

  // prk = HKDF-Extract(salt, exported_secret)
  final prk = await HpkeSender.hkdfExtract(salt, exportedSecret);

  // key = HKDF-Expand(prk, "key", Nk)
  final responseKey = await HpkeSender.hkdfExpand(
    prk,
    Uint8List.fromList(utf8.encode('key')),
    CipherSuite.aeadKeyLength,
  );

  // nonce = HKDF-Expand(prk, "nonce", Nn)
  final responseAeadNonce = await HpkeSender.hkdfExpand(
    prk,
    Uint8List.fromList(utf8.encode('nonce')),
    CipherSuite.aeadNonceLength,
  );

  // AES-128-GCM encrypt with empty AAD.
  final secretBox = await AesGcm.with128bits().encrypt(
    bhttpResponse,
    secretKey: SecretKeyData(responseKey),
    nonce: responseAeadNonce,
    aad: [],
  );

  // encResponse = response_nonce || ciphertext || tag
  return Uint8List.fromList([
    ...responseNonce,
    ...secretBox.cipherText,
    ...secretBox.mac.bytes,
  ]);
}
