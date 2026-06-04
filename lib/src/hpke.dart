import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'exceptions.dart';

/// HPKE Base Mode Sender (RFC 9180) for the cipher suite:
///   KEM = DHKEM(X25519, HKDF-SHA256) (0x0020)
///   KDF = HKDF-SHA256 (0x0001)
///   AEAD = AES-128-GCM (0x0001)
///
/// Implements only the sender side needed for OHTTP client.
// ignore: prefer-match-file-name
class HpkeSender {
  /// KEM identifier: DHKEM(X25519, HKDF-SHA256) = `0x0020` (RFC 9180).
  static const int kemId = 0x0020;

  /// KDF identifier: HKDF-SHA256 = `0x0001` (RFC 9180).
  static const int kdfId = 0x0001;

  /// AEAD identifier: AES-128-GCM = `0x0001` (RFC 9180).
  static const int aeadId = 0x0001;

  static const int _nk = 16; // AEAD key length
  static const int _nn = 12; // AEAD nonce length
  static const int _nh = 32; // Hash output length
  static const int _nSecret = 32; // KEM shared secret length

  // "KEM" || I2OSP(0x0020, 2)
  static final _kemSuiteId = Uint8List.fromList([
    0x4B, 0x45, 0x4D, // "KEM"
    0x00, 0x20, //        kem_id
  ]);

  // "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)
  static final _hpkeSuiteId = Uint8List.fromList([
    0x48, 0x50, 0x4B, 0x45, // "HPKE"
    0x00, 0x20, //              kem_id
    0x00, 0x01, //              kdf_id
    0x00, 0x01, //              aead_id
  ]);

  static final _x25519 = X25519();
  static final _aesGcm = AesGcm.with128bits();
  static final _hmac = Hmac.sha256();

  /// SetupBaseS — create a sender context (RFC 9180 §5.1).
  ///
  /// [recipientPublicKey] is the 32-byte X25519 public key of the recipient.
  /// [info] is the application-supplied info string.
  /// [testKeyPair] is an optional ephemeral keypair for deterministic testing.
  static Future<HpkeSenderContext> setupBaseS(
    Uint8List recipientPublicKey,
    Uint8List info, {
    SimpleKeyPairData? testKeyPair,
  }) async {
    final (sharedSecret, enc) = await _kemEncap(
      recipientPublicKey,
      testKeyPair: testKeyPair,
    );
    final (key, baseNonce, exporterSecret) = await _keySchedule(
      sharedSecret,
      info,
    );

    return HpkeSenderContext._(
      enc: enc,
      key: key,
      baseNonce: baseNonce,
      exporterSecret: exporterSecret,
    );
  }

  // -- Raw HKDF operations (RFC 5869) --

  /// HKDF-Extract(salt, ikm) = HMAC-SHA256(key=salt, data=ikm)
  static Future<Uint8List> hkdfExtract(Uint8List salt, Uint8List ikm) async {
    final effectiveSalt = salt.isEmpty ? Uint8List(32) : salt;
    try {
      final mac = await _hmac.calculateMac(
        ikm,
        secretKey: SecretKeyData(effectiveSalt),
      );

      return Uint8List.fromList(mac.bytes);
    } catch (e) {
      throw OhttpCryptoException('HKDF-Extract failed', cause: e);
    }
  }

  /// HKDF-Expand(prk, info, length)
  static Future<Uint8List> hkdfExpand(
    Uint8List prk,
    Uint8List info,
    int length,
  ) async {
    try {
      final hashLen = 32; // SHA-256
      final n = (length + hashLen - 1) ~/ hashLen;
      var t = Uint8List(0);
      final okm = BytesBuilder();
      for (var i = 1; i <= n; i++) {
        final input = Uint8List.fromList([...t, ...info, i]);
        final mac = await _hmac.calculateMac(
          input,
          secretKey: SecretKeyData(prk),
        );
        t = Uint8List.fromList(mac.bytes);
        okm.add(t);
      }

      return Uint8List.sublistView(Uint8List.fromList(okm.toBytes()), 0, length);
    } catch (e) {
      throw OhttpCryptoException('HKDF-Expand failed', cause: e);
    }
  }

  // -- KEM Encap (RFC 9180 §4.1) --

  static Future<(Uint8List sharedSecret, Uint8List enc)> _kemEncap(
    Uint8List recipientPkBytes, {
    SimpleKeyPairData? testKeyPair,
  }) async {
    try {
      // Ephemeral keypair
      final KeyPair ephKp;
      if (testKeyPair != null) {
        ephKp = testKeyPair;
      } else {
        ephKp = await _x25519.newKeyPair();
      }

      final ephKpData = await ephKp.extract();
      final enc = Uint8List.fromList(
        (ephKpData.publicKey as SimplePublicKey).bytes,
      );

      // DH(skE, pkR)
      final recipientPk = SimplePublicKey(
        recipientPkBytes,
        type: KeyPairType.x25519,
      );
      final dhResult = await _x25519.sharedSecretKey(
        keyPair: ephKp,
        remotePublicKey: recipientPk,
      );
      final dh = Uint8List.fromList(await dhResult.extractBytes());

      // kem_context = enc || pkR
      final kemContext = Uint8List.fromList([...enc, ...recipientPkBytes]);

      // shared_secret = ExtractAndExpand(dh, kem_context)
      final sharedSecret = await _extractAndExpand(dh, kemContext);

      return (sharedSecret, enc);
    } catch (e) {
      throw OhttpCryptoException('HPKE KEM encap failed', cause: e);
    }
  }

  static Future<Uint8List> _extractAndExpand(
    Uint8List dh,
    Uint8List kemContext,
  ) async {
    final prk = await _labeledExtract(
      _kemSuiteId,
      Uint8List(0),
      utf8.encode('eae_prk'),
      dh,
    );

    return _labeledExpand(
      _kemSuiteId,
      prk,
      utf8.encode('shared_secret'),
      kemContext,
      _nSecret,
    );
  }

  // -- Key Schedule (RFC 9180 §5.1, base mode) --

  static Future<(Uint8List key, Uint8List baseNonce, Uint8List exporterSecret)> _keySchedule(
    Uint8List sharedSecret,
    Uint8List info,
  ) async {
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

    // ks_context = I2OSP(mode=0, 1) || psk_id_hash || info_hash
    final ksContext = Uint8List.fromList([0x00, ...pskIdHash, ...infoHash]);

    // secret = LabeledExtract(shared_secret, "secret", psk="")
    final secret = await _labeledExtract(
      _hpkeSuiteId,
      sharedSecret,
      utf8.encode('secret'),
      Uint8List(0),
    );

    final key = await _labeledExpand(
      _hpkeSuiteId,
      secret,
      utf8.encode('key'),
      ksContext,
      _nk,
    );

    final baseNonce = await _labeledExpand(
      _hpkeSuiteId,
      secret,
      utf8.encode('base_nonce'),
      ksContext,
      _nn,
    );

    final exporterSecret = await _labeledExpand(
      _hpkeSuiteId,
      secret,
      utf8.encode('exp'),
      ksContext,
      _nh,
    );

    return (key, baseNonce, exporterSecret);
  }

  // -- Labeled HKDF operations (RFC 9180 §4) --

  /// LabeledExtract(salt, label, ikm) =
  ///   HKDF-Extract(salt, "HPKE-v1" || suite_id || label || ikm)
  static Future<Uint8List> _labeledExtract(
    Uint8List suiteId,
    Uint8List salt,
    List<int> label,
    Uint8List ikm,
  ) {
    final labeledIkm = Uint8List.fromList([
      ...utf8.encode('HPKE-v1'),
      ...suiteId,
      ...label,
      ...ikm,
    ]);

    return hkdfExtract(salt, labeledIkm);
  }

  /// LabeledExpand(prk, label, info, L) =
  ///   HKDF-Expand(prk, I2OSP(L,2) || "HPKE-v1" || suite_id || label || info, L)
  static Future<Uint8List> _labeledExpand(
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

    return hkdfExpand(prk, labeledInfo, length);
  }
}

/// Sender context returned by [HpkeSender.setupBaseS].
class HpkeSenderContext {
  /// Encapsulated public key (`enc`) sent to the recipient.
  final Uint8List enc;

  /// AEAD encryption key derived by HPKE key schedule.
  final Uint8List key;

  /// AEAD base nonce derived by HPKE key schedule.
  final Uint8List baseNonce;

  /// Exporter secret for further key derivation (RFC 9180 §5.1).
  final Uint8List exporterSecret;

  HpkeSenderContext._({
    required this.enc,
    required this.key,
    required this.baseNonce,
    required this.exporterSecret,
  });

  int _seq = 0;

  /// Seal (encrypt) a plaintext with AAD.
  /// Returns ciphertext || 16-byte auth tag.
  /// Each call increments the internal sequence counter (RFC 9180 §5.2).
  Future<Uint8List> seal(Uint8List aad, Uint8List plaintext) async {
    final nonce = _computeNonce();
    try {
      final secretBox = await HpkeSender._aesGcm.encrypt(
        plaintext,
        secretKey: SecretKeyData(key),
        nonce: nonce,
        aad: aad,
      );

      return Uint8List.fromList([
        ...secretBox.cipherText,
        ...secretBox.mac.bytes,
      ]);
    } catch (e) {
      throw OhttpCryptoException('HPKE seal failed', cause: e);
    }
  }

  /// Export a secret from this HPKE context (RFC 9180 §5.3).
  Future<Uint8List> export(Uint8List exporterContext, int length) => HpkeSender._labeledExpand(
    HpkeSender._hpkeSuiteId,
    exporterSecret,
    utf8.encode('sec'),
    exporterContext,
    length,
  );

  /// Computes nonce = base_nonce XOR I2OSP(seq, Nn) and increments seq.
  /// Matches BouncyCastle AEAD.computeNonce() (RFC 9180 §5.2).
  Uint8List _computeNonce() {
    if (_seq >= (1 << 32)) {
      throw OhttpCryptoException('HPKE message limit reached');
    }
    final nonce = Uint8List.fromList(baseNonce);
    // XOR seq (as big-endian) into the last bytes of nonce
    final s = _seq++;
    nonce[nonce.length - 1] ^= s & 0xFF;
    nonce[nonce.length - 2] ^= (s >> 8) & 0xFF;
    nonce[nonce.length - 3] ^= (s >> 16) & 0xFF;
    nonce[nonce.length - 4] ^= (s >> 24) & 0xFF;

    return nonce;
  }
}
