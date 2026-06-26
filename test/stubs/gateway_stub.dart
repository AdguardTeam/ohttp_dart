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

/// OHTTP request header length: key_id(1) + kem_id(2) + kdf_id(2) + aead_id(2) = 7 bytes.
/// Per RFC 9458 §4.3.
const int ohttpHeaderLen = 7;

// KEM suite ID for DHKEM(X25519): "KEM" || I2OSP(0x0020, 2).
// Per RFC 9180 §5.1.
final _kemSuiteId = Uint8List.fromList([0x4B, 0x45, 0x4D, 0x00, 0x20]);

// HPKE suite ID: "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2).
// Per RFC 9180 §4 (fixed to kem=0x0020, kdf=0x0001, aead=0x0001).
final _hpkeSuiteId = Uint8List.fromList([
  0x48, 0x50, 0x4B, 0x45, // "HPKE"
  0x00, 0x20, //              kem_id  = DHKEM(X25519, HKDF-SHA256)
  0x00, 0x01, //              kdf_id  = HKDF-SHA256
  0x00, 0x01, //              aead_id = AES-128-GCM
]);

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

/// Derives the OHTTP exported secret from a raw encapsulated request body,
/// using the fixed [gatewayPrivateKeyBytes] to perform HPKE KEM Decap
/// (RFC 9180 §4.1 receiver side, DHKEM(X25519, HKDF-SHA256)).
///
/// [encRequest] layout: header(7) ‖ enc(32) ‖ ciphertext
///
/// Returns the exported secret that [sealBhttpResponse] expects, matching
/// the value produced by `ohttpEncapsulate` on the sender side.
///
/// Mirrors `lib/src/hpke.dart` (HpkeSender / ohttpEncapsulate) and
/// `lib/src/cipher_suite.dart` — update if the production cipher suite or
/// export context changes.
Future<Uint8List> decapExportedSecret(Uint8List encRequest) async {
  // Extract enc (ephemeral sender public key) from the encapsulated request.
  final enc = encRequest.sublist(ohttpHeaderLen, ohttpHeaderLen + CipherSuite.kemPublicKeyLength);

  // Reconstruct the HPKE info string from the 7-byte OHTTP request header.
  // Per RFC 9458 §4.3: info = "message/bhttp request" || 0x00 || header_bytes.
  final info = Uint8List.fromList([
    ...utf8.encode('message/bhttp request'),
    0x00,
    ...encRequest.sublist(0, ohttpHeaderLen),
  ]);

  // DH(gatewayPrivateKey, enc) — X25519 KEM Decap (RFC 9180 §7.1.2).
  final x25519 = X25519();
  final privKey = SimpleKeyPairData(
    gatewayPrivateKeyBytes,
    publicKey: SimplePublicKey(gatewayPublicKeyBytes, type: KeyPairType.x25519),
    type: KeyPairType.x25519,
  );
  final ephPubKey = SimplePublicKey(enc, type: KeyPairType.x25519);
  final dhResult = await x25519.sharedSecretKey(keyPair: privKey, remotePublicKey: ephPubKey);
  final dh = Uint8List.fromList(await dhResult.extractBytes());

  // kem_context = enc || gatewayPublicKey (RFC 9180 §7.1.2 Decap).
  final kemContext = Uint8List.fromList([...enc, ...gatewayPublicKeyBytes]);

  // sharedSecret = ExtractAndExpand(dh, kem_context) (RFC 9180 §4.1).
  final eaePrk = await _labeledExtract(_kemSuiteId, Uint8List(0), utf8.encode('eae_prk'), dh);
  final sharedSecret = await _labeledExpand(
    _kemSuiteId,
    eaePrk,
    utf8.encode('shared_secret'),
    kemContext,
    CipherSuite.kemSharedSecretLength,
  );

  // KeySchedule(sharedSecret, info) → exporterSecret (RFC 9180 §5.1, base mode).
  final pskIdHash = await _labeledExtract(_hpkeSuiteId, Uint8List(0), utf8.encode('psk_id_hash'), Uint8List(0));
  final infoHash = await _labeledExtract(_hpkeSuiteId, Uint8List(0), utf8.encode('info_hash'), info);
  // ks_context = I2OSP(mode=0, 1) || psk_id_hash || info_hash
  final ksContext = Uint8List.fromList([0x00, ...pskIdHash, ...infoHash]);
  final secret = await _labeledExtract(_hpkeSuiteId, sharedSecret, utf8.encode('secret'), Uint8List(0));
  final exporterSecret = await _labeledExpand(
    _hpkeSuiteId,
    secret,
    utf8.encode('exp'),
    ksContext,
    CipherSuite.kdfHashLength,
  );

  // HPKE export: exportedSecret = LabeledExpand(exporterSecret, "sec", exporter_context, L)
  // Per RFC 9180 §5.3 and ohttpEncapsulate: context = "message/bhttp response", L = responseNonceLen.
  return _labeledExpand(
    _hpkeSuiteId,
    exporterSecret,
    utf8.encode('sec'),
    Uint8List.fromList(utf8.encode('message/bhttp response')),
    responseNonceLen,
  );
}

/// Opens an encapsulated OHTTP request and returns the raw BHTTP request bytes.
///
/// Runs the same KEM Decap + HPKE key schedule as [decapExportedSecret],
/// then derives the request AEAD key and nonce per RFC 9180 §5.2 and
/// decrypts the ciphertext with AES-128-GCM using **empty AAD**
/// (per RFC 9458 §4.3: `ct = sctxt.Seal("", request)` — the header is
/// bound through the HPKE info string, not through the AEAD AAD).
///
/// Mirrors `lib/src/hpke.dart` (HpkeSender.seal) and
/// `lib/src/cipher_suite.dart` — update if the production cipher suite changes.
Future<Uint8List> openEncapsulatedRequest(Uint8List encRequest) async {
  // Parse layout: header(7) | enc(32) | ciphertext || tag
  final header = encRequest.sublist(0, ohttpHeaderLen);
  final enc = encRequest.sublist(ohttpHeaderLen, ohttpHeaderLen + CipherSuite.kemPublicKeyLength);
  final ctWithTag = encRequest.sublist(ohttpHeaderLen + CipherSuite.kemPublicKeyLength);

  // Reconstruct HPKE info (identical to decapExportedSecret).
  final info = Uint8List.fromList([
    ...utf8.encode('message/bhttp request'),
    0x00,
    ...header,
  ]);

  // KEM Decap (identical to decapExportedSecret).
  final x25519 = X25519();
  final privKey = SimpleKeyPairData(
    gatewayPrivateKeyBytes,
    publicKey: SimplePublicKey(gatewayPublicKeyBytes, type: KeyPairType.x25519),
    type: KeyPairType.x25519,
  );
  final ephPubKey = SimplePublicKey(enc, type: KeyPairType.x25519);
  final dhResult = await x25519.sharedSecretKey(keyPair: privKey, remotePublicKey: ephPubKey);
  final dh = Uint8List.fromList(await dhResult.extractBytes());

  final kemContext = Uint8List.fromList([...enc, ...gatewayPublicKeyBytes]);
  final eaePrk = await _labeledExtract(_kemSuiteId, Uint8List(0), utf8.encode('eae_prk'), dh);
  final sharedSecret = await _labeledExpand(
    _kemSuiteId,
    eaePrk,
    utf8.encode('shared_secret'),
    kemContext,
    CipherSuite.kemSharedSecretLength,
  );

  // Key schedule — identical to decapExportedSecret, but stopping at `secret`
  // rather than computing the exporter secret.
  final pskIdHash = await _labeledExtract(
    _hpkeSuiteId,
    Uint8List(0),
    utf8.encode('psk_id_hash'),
    Uint8List(0),
  );
  final infoHash = await _labeledExtract(
    _hpkeSuiteId,
    Uint8List(0),
    utf8.encode('info_hash'),
    info,
  );
  final ksContext = Uint8List.fromList([0x00, ...pskIdHash, ...infoHash]);
  final secret = await _labeledExtract(
    _hpkeSuiteId,
    sharedSecret,
    utf8.encode('secret'),
    Uint8List(0),
  );

  // Derive request AEAD key and base nonce (RFC 9180 §5.2).
  final key = await _labeledExpand(
    _hpkeSuiteId,
    secret,
    utf8.encode('key'),
    ksContext,
    CipherSuite.aeadKeyLength,
  );
  final baseNonce = await _labeledExpand(
    _hpkeSuiteId,
    secret,
    utf8.encode('base_nonce'),
    ksContext,
    CipherSuite.aeadNonceLength,
  );

  // AES-128-GCM decrypt (seq=0, so request nonce = baseNonce; AAD = empty per RFC 9458 §4.3).
  final cipherText = ctWithTag.sublist(0, ctWithTag.length - CipherSuite.aeadTagLength);
  final tag = ctWithTag.sublist(ctWithTag.length - CipherSuite.aeadTagLength);
  final plaintext = await AesGcm.with128bits().decrypt(
    SecretBox(cipherText, nonce: baseNonce, mac: Mac(tag)),
    secretKey: SecretKeyData(key),
  );

  return Uint8List.fromList(plaintext);
}

// -- Labeled HKDF helpers (mirrors HpkeSender private methods, RFC 9180 §4) --

// LabeledExtract(salt, label, ikm) = HKDF-Extract(salt, "HPKE-v1" || suite_id || label || ikm)
Future<Uint8List> _labeledExtract(
  Uint8List suiteId,
  Uint8List salt,
  List<int> label,
  Uint8List ikm,
) {
  final labeled = Uint8List.fromList([...utf8.encode('HPKE-v1'), ...suiteId, ...label, ...ikm]);

  return HpkeSender.hkdfExtract(salt, labeled);
}

// LabeledExpand(prk, label, info, L) =
//   HKDF-Expand(prk, I2OSP(L,2) || "HPKE-v1" || suite_id || label || info, L)
Future<Uint8List> _labeledExpand(
  Uint8List suiteId,
  Uint8List prk,
  List<int> label,
  Uint8List info,
  int length,
) {
  final labeledInfo = Uint8List.fromList([
    (length >> 8) & 0xFF,
    length & 0xFF,
    ...utf8.encode('HPKE-v1'),
    ...suiteId,
    ...label,
    ...info,
  ]);

  return HpkeSender.hkdfExpand(prk, labeledInfo, length);
}
