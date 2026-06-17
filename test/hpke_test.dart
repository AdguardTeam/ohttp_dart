import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:kiri_check/kiri_check.dart';
import 'package:ohttp_dart/ohttp_dart.dart';
import 'package:ohttp_dart/src/cipher_suite.dart';
import 'package:test/test.dart';

/// Helper: hex string → Uint8List.
Uint8List _hex(String hex) {
  final bytes = <int>[];
  for (var i = 0; i < hex.length; i += 2) {
    bytes.add(int.parse(hex.substring(i, i + 2), radix: 16));
  }

  return Uint8List.fromList(bytes);
}

/// Helper: Uint8List → hex string.
String _toHex(Uint8List bytes) => bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  // Diagnostic: verify X25519 DH works with the cryptography package
  group('X25519 DH diagnostic', () {
    test('RFC 7748 Section 6.1 test vector', () async {
      final aliceSk = _hex(
        '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
      );
      final alicePk = _hex(
        '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
      );
      final bobPk = _hex(
        'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
      );
      const expectedShared = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';

      final x = X25519();
      final kp = SimpleKeyPairData(
        aliceSk,
        publicKey: SimplePublicKey(alicePk, type: KeyPairType.x25519),
        type: KeyPairType.x25519,
      );
      final dh = await x.sharedSecretKey(
        keyPair: kp,
        remotePublicKey: SimplePublicKey(bobPk, type: KeyPairType.x25519),
      );
      final dhBytes = Uint8List.fromList(await dh.extractBytes());
      expect(_toHex(dhBytes), expectedShared);
    });
  });

  // RFC 9180 Appendix A.1 — DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
  // Mode: Base (0x00)
  group('HPKE RFC 9180 Appendix A.1 test vectors', () {
    // Test vector values
    final skEm = _hex(
      '52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736',
    );
    final pkEm = _hex(
      '37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431',
    );
    final pkRm = _hex(
      '3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d',
    );
    final info = _hex('4f6465206f6e2061204772656369616e2055726e');

    const expectedKey = '4531685d41d65f03dc48f6b8302c05b0';
    const expectedBaseNonce = '56d890e5accaaf011cff4b7d';
    const expectedExporterSecret = '45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8';

    // Encryption test vector (seq=0)
    final sealPlaintext = _hex(
      '4265617574792069732074727574682c20747275746820626561757479',
    );
    final sealAad = _hex('436f756e742d30');
    const expectedCiphertext =
        'f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a';

    // Export test vector
    final exportContext = _hex('00');
    const exportLength = CipherSuite.kdfHashLength;
    const expectedExportValue = '2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5';

    test(
      'SetupBaseS produces correct key, base_nonce, exporter_secret',
      () async {
        final testKeyPair = SimpleKeyPairData(
          skEm,
          publicKey: SimplePublicKey(pkEm, type: KeyPairType.x25519),
          type: KeyPairType.x25519,
        );

        final ctx = await HpkeSender.setupBaseS(
          pkRm,
          info,
          testKeyPair: testKeyPair,
        );

        expect(_toHex(ctx.enc), _toHex(pkEm));
        expect(_toHex(ctx.key.bytes), expectedKey);
        expect(_toHex(ctx.baseNonce.bytes), expectedBaseNonce);
        expect(_toHex(ctx.exporterSecret.bytes), expectedExporterSecret);
      },
    );

    test('seal produces correct ciphertext for seq=0', () async {
      final testKeyPair = SimpleKeyPairData(
        skEm,
        publicKey: SimplePublicKey(pkEm, type: KeyPairType.x25519),
        type: KeyPairType.x25519,
      );

      final ctx = await HpkeSender.setupBaseS(
        pkRm,
        info,
        testKeyPair: testKeyPair,
      );

      final ct = await ctx.seal(sealAad, sealPlaintext);
      expect(_toHex(ct), expectedCiphertext);
    });

    test('export produces correct value', () async {
      final testKeyPair = SimpleKeyPairData(
        skEm,
        publicKey: SimplePublicKey(pkEm, type: KeyPairType.x25519),
        type: KeyPairType.x25519,
      );

      final ctx = await HpkeSender.setupBaseS(
        pkRm,
        info,
        testKeyPair: testKeyPair,
      );

      final exportValue = await ctx.export(exportContext, exportLength);
      expect(_toHex(exportValue), expectedExportValue);
    });

    test('shared_secret intermediate value matches RFC', () async {
      const expectedSharedSecret = 'fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc';

      final x = X25519();
      final testKeyPair = SimpleKeyPairData(
        skEm,
        publicKey: SimplePublicKey(pkEm, type: KeyPairType.x25519),
        type: KeyPairType.x25519,
      );

      final dh = await x.sharedSecretKey(
        keyPair: testKeyPair,
        remotePublicKey: SimplePublicKey(pkRm, type: KeyPairType.x25519),
      );
      final dhBytes = Uint8List.fromList(await dh.extractBytes());

      final kemSuiteId = Uint8List.fromList([0x4B, 0x45, 0x4D, 0x00, 0x20]);
      final kemContext = Uint8List.fromList([...pkEm, ...pkRm]);

      final labeledIkm = Uint8List.fromList([
        ...utf8.encode('HPKE-v1'),
        ...kemSuiteId,
        ...utf8.encode('eae_prk'),
        ...dhBytes,
      ]);
      final prk = await HpkeSender.hkdfExtract(Uint8List(0), labeledIkm);

      final labeledInfo = Uint8List.fromList([
        0x00,
        0x20,
        ...utf8.encode('HPKE-v1'),
        ...kemSuiteId,
        ...utf8.encode('shared_secret'),
        ...kemContext,
      ]);
      final sharedSecret = await HpkeSender.hkdfExpand(prk, labeledInfo, CipherSuite.kdfHashLength);
      expect(_toHex(sharedSecret), expectedSharedSecret);
    });

    test('seal seq=1 produces correct ciphertext (nonce increment)', () async {
      final testKeyPair = SimpleKeyPairData(
        skEm,
        publicKey: SimplePublicKey(pkEm, type: KeyPairType.x25519),
        type: KeyPairType.x25519,
      );

      final ctx = await HpkeSender.setupBaseS(
        pkRm,
        info,
        testKeyPair: testKeyPair,
      );

      // seq=0
      await ctx.seal(sealAad, sealPlaintext);

      // seq=1
      final aad1 = _hex('436f756e742d31');
      final ct1 = await ctx.seal(aad1, sealPlaintext);
      expect(
        _toHex(ct1),
        'af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84',
      );
    });

    test('export with empty context produces correct value', () async {
      final testKeyPair = SimpleKeyPairData(
        skEm,
        publicKey: SimplePublicKey(pkEm, type: KeyPairType.x25519),
        type: KeyPairType.x25519,
      );

      final ctx = await HpkeSender.setupBaseS(
        pkRm,
        info,
        testKeyPair: testKeyPair,
      );

      final exportValue = await ctx.export(Uint8List(0), CipherSuite.kdfHashLength);
      expect(
        _toHex(exportValue),
        '3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee',
      );
    });

    test('export with "TestContext" produces correct value', () async {
      final testKeyPair = SimpleKeyPairData(
        skEm,
        publicKey: SimplePublicKey(pkEm, type: KeyPairType.x25519),
        type: KeyPairType.x25519,
      );

      final ctx = await HpkeSender.setupBaseS(
        pkRm,
        info,
        testKeyPair: testKeyPair,
      );

      final exportCtx = _hex('54657374436f6e74657874');
      final exportValue = await ctx.export(exportCtx, CipherSuite.kdfHashLength);
      expect(
        _toHex(exportValue),
        'e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931',
      );
    });

    // Sizes are constants of the ciphersuite, independent of info (RFC 9180 §4, §5.1).
    property('enc=32B, key=16B, base_nonce=12B, exporter_secret=32B for any info', () {
      forAll(
        list(integer(min: 0, max: 255)),
        (infoList) async {
          final x = X25519();
          final kp = await x.newKeyPair();
          final pk = await kp.extractPublicKey();
          final ctx = await HpkeSender.setupBaseS(
            Uint8List.fromList(pk.bytes),
            Uint8List.fromList(infoList),
          );
          expect(ctx.enc.length, CipherSuite.kemPublicKeyLength);
          expect(ctx.key.bytes.length, CipherSuite.aeadKeyLength);
          expect(ctx.baseNonce.bytes.length, CipherSuite.aeadNonceLength);
          expect(ctx.exporterSecret.bytes.length, CipherSuite.kdfHashLength);
        },
      );
    });
  });

  group('HKDF RFC 5869 test vectors', () {
    test('Test Case 1', () async {
      final ikm = _hex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
      final salt = _hex('000102030405060708090a0b0c');
      final info = _hex('f0f1f2f3f4f5f6f7f8f9');

      const expectedPrk = '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5';
      const expectedOkm = '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865';

      final prk = await HpkeSender.hkdfExtract(salt, ikm);
      expect(_toHex(prk), expectedPrk);

      final okm = await HpkeSender.hkdfExpand(prk, info, 42);
      expect(_toHex(okm), expectedOkm);
    });
  });

  group('HKDF utilities', () {
    test('hkdfExtract with empty salt uses zero-filled salt', () async {
      final result = await HpkeSender.hkdfExtract(
        Uint8List(0),
        Uint8List.fromList(utf8.encode('test')),
      );
      expect(result.length, CipherSuite.kdfHashLength);
    });

    test('hkdfExpand produces correct length', () async {
      final prk = await HpkeSender.hkdfExtract(
        Uint8List.fromList(utf8.encode('salt')),
        Uint8List.fromList(utf8.encode('ikm')),
      );
      final okm = await HpkeSender.hkdfExpand(
        prk,
        Uint8List.fromList(utf8.encode('info')),
        CipherSuite.kdfHashLength,
      );
      expect(okm.length, CipherSuite.kdfHashLength);
    });

    test('hkdfExpand for 32 bytes', () async {
      final prk = await HpkeSender.hkdfExtract(
        Uint8List.fromList(utf8.encode('salt')),
        Uint8List.fromList(utf8.encode('ikm')),
      );
      final okm = await HpkeSender.hkdfExpand(
        prk,
        Uint8List.fromList(utf8.encode('info')),
        32,
      );
      expect(okm.length, 32);
    });

    // RFC 5869 §2.2: PRK is always HashLen octets, regardless of input sizes.
    property('output is always Nh=32 bytes for any salt and ikm', () {
      forAll(
        combine2(
          list(integer(min: 0, max: 255)),
          list(integer(min: 0, max: 255)),
        ),
        (args) async {
          final (saltList, ikmList) = args;
          final prk = await HpkeSender.hkdfExtract(
            Uint8List.fromList(saltList),
            Uint8List.fromList(ikmList),
          );
          expect(prk.length, CipherSuite.kdfHashLength);
        },
      );
    });

    // RFC 5869 §2.2: PRK = HMAC-Hash(salt, IKM) is a pure function of its inputs.
    property('same (salt, ikm) always produces the same PRK (determinism)', () {
      forAll(
        combine2(
          list(integer(min: 0, max: 255)),
          list(integer(min: 0, max: 255)),
        ),
        (args) async {
          final (saltList, ikmList) = args;
          final salt = Uint8List.fromList(saltList);
          final ikm = Uint8List.fromList(ikmList);
          final prk1 = await HpkeSender.hkdfExtract(salt, ikm);
          final prk2 = await HpkeSender.hkdfExtract(salt, ikm);
          expect(prk1, equals(prk2));
        },
      );
    });

    // RFC 5869 §2.3: L ≤ 255*HashLen and OKM is "of L octets".
    property('output length equals requested L for any valid L and any info', () {
      forAll(
        combine2(
          list(integer(min: 0, max: 255)),
          integer(min: 1, max: 255 * CipherSuite.kdfHashLength),
        ),
        (args) async {
          final (infoList, l) = args;
          final prk = Uint8List(CipherSuite.kdfHashLength);
          final okm = await HpkeSender.hkdfExpand(
            prk,
            Uint8List.fromList(infoList),
            l,
          );
          expect(okm.length, l);
        },
      );
    });

    // RFC 5869 §2.3: OKM = first L octets of (T(1) || T(2) || ...).
    property('shorter output is a prefix of longer output for the same PRK and info', () {
      forAll(
        combine3(
          list(integer(min: 0, max: 255)),
          integer(min: 1, max: 254),
          integer(min: 1, max: 254),
        ),
        (args) async {
          final (infoList, l1Raw, l2Raw) = args;
          if (l1Raw == l2Raw) {
            return;
          }
          final l1 = l1Raw < l2Raw ? l1Raw : l2Raw;
          final l2 = l1Raw < l2Raw ? l2Raw : l1Raw;
          final prk = Uint8List(CipherSuite.kdfHashLength);
          final info = Uint8List.fromList(infoList);
          final short = await HpkeSender.hkdfExpand(prk, info, l1);
          final long = await HpkeSender.hkdfExpand(prk, info, l2);
          expect(long.sublist(0, l1), equals(short));
        },
      );
    });
  });

  group('HpkeSenderContext.dispose', () {
    test('zeroes key, baseNonce, exporterSecret', () async {
      final x = X25519();
      final kp = await x.newKeyPair();
      final pk = await kp.extractPublicKey();

      final ctx = await HpkeSender.setupBaseS(
        Uint8List.fromList(pk.bytes),
        Uint8List.fromList(utf8.encode('test')),
      );

      // Verify data is non-zero before dispose
      expect(ctx.key.bytes.any((b) => b != 0), isTrue);
      expect(ctx.baseNonce.bytes.any((b) => b != 0), isTrue);
      expect(ctx.exporterSecret.bytes.any((b) => b != 0), isTrue);

      ctx.dispose();

      // Verify fields are erased — accessing bytes throws StateError
      expect(() => ctx.key.bytes, throwsStateError);
      expect(() => ctx.baseNonce.bytes, throwsStateError);
      expect(() => ctx.exporterSecret.bytes, throwsStateError);
    });

    test('does not zero enc (public key)', () async {
      final x = X25519();
      final kp = await x.newKeyPair();
      final pk = await kp.extractPublicKey();

      final ctx = await HpkeSender.setupBaseS(
        Uint8List.fromList(pk.bytes),
        Uint8List.fromList(utf8.encode('test')),
      );

      final encBefore = Uint8List.fromList(ctx.enc);

      ctx.dispose();

      // enc must remain unchanged
      expect(ctx.enc, encBefore);
    });
  });

  group('sequence number overflow in seal', () {
    // RFC 9180 §5.2: sequence number must not exceed 2^Nn - 1.
    // Our implementation uses a 32-bit Dart int and throws at seq >= 2^32.

    test('seal throws OhttpCryptoException when seq == 2^32 (limit reached)', () async {
      final x = X25519();
      final kp = await x.newKeyPair();
      final pk = await kp.extractPublicKey();

      final ctx = await HpkeSender.setupBaseS(
        Uint8List.fromList(pk.bytes),
        Uint8List.fromList(utf8.encode('overflow-test')),
      );

      ctx.seqForTesting = 1 << 32;

      expect(
        () => ctx.seal(Uint8List(0), Uint8List.fromList([0x01])),
        throwsA(isA<OhttpCryptoException>()),
      );
    });

    test('seal throws OhttpCryptoException when seq > 2^32 (already overflowed)', () async {
      final x = X25519();
      final kp = await x.newKeyPair();
      final pk = await kp.extractPublicKey();

      final ctx = await HpkeSender.setupBaseS(
        Uint8List.fromList(pk.bytes),
        Uint8List.fromList(utf8.encode('overflow-test-2')),
      );

      ctx.seqForTesting = (1 << 32) + 1;

      expect(
        () => ctx.seal(Uint8List(0), Uint8List.fromList([0x01])),
        throwsA(isA<OhttpCryptoException>()),
      );
    });

    test('seal succeeds at seq == 2^32 - 1 (last valid call)', () async {
      final x = X25519();
      final kp = await x.newKeyPair();
      final pk = await kp.extractPublicKey();

      final ctx = await HpkeSender.setupBaseS(
        Uint8List.fromList(pk.bytes),
        Uint8List.fromList(utf8.encode('overflow-boundary')),
      );

      ctx.seqForTesting = (1 << 32) - 1;

      final ct = await ctx.seal(Uint8List(0), Uint8List.fromList([0xAA]));
      expect(ct.length, greaterThan(0));

      // The very next call must fail because seq is now 1 << 32.
      expect(
        () => ctx.seal(Uint8List(0), Uint8List.fromList([0xBB])),
        throwsA(isA<OhttpCryptoException>()),
      );
    });

    // RFC 9180 §5.2: ciphertext = Seal(key, nonce, aad, pt), length is pt.length + Nt.
    property('ciphertext length equals plaintext.length + Nt=16 for any plaintext', () {
      forAll(
        list(integer(min: 0, max: 255)),
        (ptList) async {
          final x = X25519();
          final kp = await x.newKeyPair();
          final pk = await kp.extractPublicKey();
          final ctx = await HpkeSender.setupBaseS(
            Uint8List.fromList(pk.bytes),
            Uint8List.fromList(utf8.encode('seal-length-prop')),
          );
          final ct = await ctx.seal(Uint8List(0), Uint8List.fromList(ptList));
          expect(ct.length, ptList.length + CipherSuite.aeadTagLength);
        },
      );
    });

    // RFC 9180 §5.2: nonce = base_nonce XOR seq, and seq is incremented on every Seal call.
    property('K sequential seal calls with equal plaintext/AAD produce K distinct ciphertexts', () {
      forAll(
        integer(min: 2, max: 15),
        (k) async {
          final x = X25519();
          final kp = await x.newKeyPair();
          final pk = await kp.extractPublicKey();
          final ctx = await HpkeSender.setupBaseS(
            Uint8List.fromList(pk.bytes),
            Uint8List.fromList(utf8.encode('seal-uniqueness-prop')),
          );
          final pt = Uint8List.fromList([0xAB, 0xCD]);
          final aad = Uint8List(0);
          final seen = <String>{};
          for (var i = 0; i < k; i++) {
            final ct = await ctx.seal(aad, pt);
            seen.add(_toHex(ct));
          }
          expect(seen.length, k, reason: 'all $k ciphertexts must be distinct');
        },
      );
    });
  });

  // RFC 9180 §7.1.4 + RFC 7748 §6.1: the DH result MUST NOT be the all-zero value.
  // All small-subgroup (low-order) X25519 points produce an all-zero DH output
  // due to cofactor-8 scalar clamping, so setupBaseS must reject them.
  //
  // Points verified experimentally with package:cryptography 2.9.0.
  // Sources: RFC 7748, libsodium rejection list, Curve25519 torsion subgroup.
  group('setupBaseS rejects low-order X25519 public keys (RFC 9180 §4.3)', () {
    // Each entry: (description, 64-char little-endian hex u-coordinate).
    const lowOrderPoints = <(String, String)>[
      // u = 0: the point at infinity / identity element.
      ('zero key (u=0)', '0000000000000000000000000000000000000000000000000000000000000000'),
      // u = 1: first non-trivial torsion point (order 8).
      ('u=1', '0100000000000000000000000000000000000000000000000000000000000000'),
      // Order-8 torsion point from the libsodium / Bernstein rejection list.
      ('order-8 torsion point (e0eb…b800)', 'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800'),
      // Order-4 torsion point.
      ('order-4 torsion point (5f9c…1157)', '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157'),
      // u = p − 1 (= −1 in GF(2²⁵⁵−19)): order-2 point.
      ('u = p−1 (order-2, ec…7f)', 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'),
      // u = p (≡ 0 mod p): same equivalence class as u=0.
      ('u = p (≡ 0 mod p, ed…7f)', 'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'),
      // u = p + 1 (≡ 1 mod p): same equivalence class as u=1.
      ('u = p+1 (≡ 1 mod p, ee…7f)', 'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'),
    ];

    for (final (description, hex) in lowOrderPoints) {
      test('throws OhttpCryptoException for $description', () async {
        await expectLater(
          () => HpkeSender.setupBaseS(
            _hex(hex),
            Uint8List.fromList(utf8.encode('test-info')),
          ),
          throwsA(isA<OhttpCryptoException>()),
        );
      });
    }
  });

  // RFC 9180 §5.3: L must be in [1, 255*Nh]. For HKDF-SHA256: Nh=32, max=8160.
  group('HpkeSenderContext.export invalid length (RFC 9180 §5.3)', () {
    Future<HpkeSenderContext> makeCtx() async {
      final x = X25519();
      final kp = await x.newKeyPair();
      final pk = await kp.extractPublicKey();

      return HpkeSender.setupBaseS(
        Uint8List.fromList(pk.bytes),
        Uint8List.fromList(utf8.encode('export-length-test')),
      );
    }

    test('throws OhttpCryptoException for length == 0', () async {
      final ctx = await makeCtx();
      expect(
        () => ctx.export(Uint8List(0), 0),
        throwsA(isA<OhttpCryptoException>()),
      );
    });

    test('throws OhttpCryptoException for length == -1', () async {
      final ctx = await makeCtx();
      expect(
        () => ctx.export(Uint8List(0), -1),
        throwsA(isA<OhttpCryptoException>()),
      );
    });

    test('throws OhttpCryptoException for length > 255*Nh (8161)', () async {
      final ctx = await makeCtx();
      // 255 * 32 = 8160 is the max; 8161 must be rejected.
      expect(
        () => ctx.export(Uint8List(0), 255 * CipherSuite.kdfHashLength + 1),
        throwsA(isA<OhttpCryptoException>()),
      );
    });

    test('succeeds for length == 1 (minimum valid)', () async {
      final ctx = await makeCtx();
      final result = await ctx.export(Uint8List(0), 1);
      expect(result.length, 1);
    });

    test('succeeds for length == 255*Nh (maximum valid)', () async {
      final ctx = await makeCtx();
      final result = await ctx.export(Uint8List(0), 255 * CipherSuite.kdfHashLength);
      expect(result.length, 255 * CipherSuite.kdfHashLength);
    });

    // RFC 9180 §5.3: Export delegates to LabeledExpand(exporter_secret, "sec", ctx, L),
    // which forwards L to HKDF-Expand (RFC 5869 §2.3).
    property('output length equals requested L for any exporter context and valid L', () {
      forAll(
        combine2(
          list(integer(min: 0, max: 255)),
          integer(min: 1, max: 255 * CipherSuite.kdfHashLength),
        ),
        (args) async {
          final (exportCtxList, l) = args;
          final x = X25519();
          final kp = await x.newKeyPair();
          final pk = await kp.extractPublicKey();
          final senderCtx = await HpkeSender.setupBaseS(
            Uint8List.fromList(pk.bytes),
            Uint8List.fromList(utf8.encode('export-length-prop')),
          );
          final exported = await senderCtx.export(Uint8List.fromList(exportCtxList), l);
          expect(exported.length, l);
        },
      );
    });
  });
}
