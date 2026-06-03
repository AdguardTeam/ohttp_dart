import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:ohttp_dart/ohttp_dart.dart';
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
    const exportLength = 32;
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
        expect(_toHex(ctx.key), expectedKey);
        expect(_toHex(ctx.baseNonce), expectedBaseNonce);
        expect(_toHex(ctx.exporterSecret), expectedExporterSecret);
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
      final sharedSecret = await HpkeSender.hkdfExpand(prk, labeledInfo, 32);
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

      final exportValue = await ctx.export(Uint8List(0), 32);
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
      final exportValue = await ctx.export(exportCtx, 32);
      expect(
        _toHex(exportValue),
        'e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931',
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
      expect(result.length, 32);
    });

    test('hkdfExpand produces correct length', () async {
      final prk = await HpkeSender.hkdfExtract(
        Uint8List.fromList(utf8.encode('salt')),
        Uint8List.fromList(utf8.encode('ikm')),
      );
      final okm = await HpkeSender.hkdfExpand(
        prk,
        Uint8List.fromList(utf8.encode('info')),
        16,
      );
      expect(okm.length, 16);
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
  });
}
