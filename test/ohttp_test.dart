import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:ohttp_dart/ohttp_dart.dart';
import 'package:test/test.dart';

import 'test_utils.dart';

void main() {
  group('OhttpKeyConfig.parse', () {
    test('parses valid 41-byte config', () {
      final buf = BytesBuilder();
      buf.addByte(0x01); // key_id
      buf.add([0x00, 0x20]); // kem_id = X25519
      buf.add(List.filled(32, 0xAB)); // public_key (32 bytes)
      buf.add([0x00, 0x04]); // sym_len = 4
      buf.add([0x00, 0x01]); // kdf_id = HKDF-SHA256
      buf.add([0x00, 0x01]); // aead_id = AES-128-GCM

      final config = OhttpKeyConfig.parse(Uint8List.fromList(buf.toBytes()));

      expect(config.keyId, 0x01);
      expect(config.kemId, 0x0020);
      expect(config.publicKey.length, 32);
      expect(config.publicKey[0], 0xAB);
      expect(config.kdfId, 0x0001);
      expect(config.aeadId, 0x0001);
    });

    test('throws OhttpFormatException on too-short data', () {
      expect(
        () => OhttpKeyConfig.parse(Uint8List.fromList([0x01, 0x00])),
        throwsA(isA<OhttpFormatException>()),
      );
    });

    test('throws OhttpConfigException on unsupported KEM', () {
      final buf = BytesBuilder();
      buf.addByte(0x01);
      buf.add([0x00, 0x10]); // unsupported KEM
      buf.add(List.filled(32, 0x00));
      buf.add([0x00, 0x04]);
      buf.add([0x00, 0x01]);
      buf.add([0x00, 0x01]);

      expect(
        () => OhttpKeyConfig.parse(Uint8List.fromList(buf.toBytes())),
        throwsA(isA<OhttpConfigException>()),
      );
    });

    test('throws OhttpFormatException on short symmetric section', () {
      final buf = BytesBuilder();
      buf.addByte(0x01);
      buf.add([0x00, 0x20]);
      buf.add(List.filled(32, 0x00));
      buf.add([0x00, 0x02]); // sym_len = 2 (too short, need 4)
      buf.add([0x00, 0x01]); // only 2 bytes, no room for aead_id

      expect(
        () => OhttpKeyConfig.parse(Uint8List.fromList(buf.toBytes())),
        throwsA(isA<OhttpFormatException>()),
      );
    });

    test('throws OhttpFormatException when data has trailing bytes after symmetric section', () {
      final buf = BytesBuilder();
      buf.addByte(0x01);
      buf.add([0x00, 0x20]);
      buf.add(List.filled(32, 0x00));
      buf.add([0x00, 0x04]); // symLen = 4
      buf.add([0x00, 0x01]); // supported KDF
      buf.add([0x00, 0x01]); // supported AEAD
      buf.add([0xFF, 0xFF]); // trailing bytes

      expect(
        () => OhttpKeyConfig.parse(Uint8List.fromList(buf.toBytes())),
        throwsA(
          isA<OhttpFormatException>().having(
            (e) => e.message,
            'message',
            contains('trailing data'),
          ),
        ),
      );
    });

    test('parses multi-suite: unsupported first, supported second', () {
      // Gateway advertises unsupported KDF+AEAD first, then supported.
      final config = multiSuiteKeyConfig(
        suiteIds: [
          (0x0002, 0x0002), // unsupported (HKDF-SHA384, AES-256-GCM)
          (0x0001, 0x0001), // supported   (HKDF-SHA256, AES-128-GCM)
        ],
      );

      final parsed = OhttpKeyConfig.parse(config);
      expect(parsed.kdfId, 0x0001);
      expect(parsed.aeadId, 0x0001);
    });

    test('parses multi-suite: three suites, supported is last', () {
      final config = multiSuiteKeyConfig(
        suiteIds: [
          (0x0003, 0x0003), // unsupported
          (0x0002, 0x0002), // unsupported
          (0x0001, 0x0001), // supported
        ],
      );

      final parsed = OhttpKeyConfig.parse(config);
      expect(parsed.kdfId, 0x0001);
      expect(parsed.aeadId, 0x0001);
    });

    test('selects first supported suite when multiple supported exist', () {
      final config = multiSuiteKeyConfig(
        suiteIds: [
          (0x0001, 0x0001), // supported — should be selected
          (0x0001, 0x0001), // also supported, but first wins
        ],
      );

      final parsed = OhttpKeyConfig.parse(config);
      expect(parsed.kdfId, 0x0001);
      expect(parsed.aeadId, 0x0001);
    });

    test('throws OhttpConfigException when no suite is supported', () {
      final config = multiSuiteKeyConfig(
        suiteIds: [
          (0x0002, 0x0002), // unsupported
          (0x0003, 0x0003), // unsupported
        ],
      );

      expect(
        () => OhttpKeyConfig.parse(config),
        throwsA(
          isA<OhttpConfigException>().having(
            (e) => e.message,
            'message',
            contains('No supported cipher suite'),
          ),
        ),
      );
    });

    test('throws OhttpFormatException when symLen is not a multiple of 4', () {
      final buf = BytesBuilder();
      buf.addByte(0x01);
      buf.add([0x00, 0x20]);
      buf.add(List.filled(32, 0x00));
      buf.add([0x00, 0x05]); // sym_len = 5 (not multiple of 4)
      buf.add(List.filled(5, 0x00)); // 5 bytes of suite data

      expect(
        () => OhttpKeyConfig.parse(Uint8List.fromList(buf.toBytes())),
        throwsA(
          isA<OhttpFormatException>().having(
            (e) => e.message,
            'message',
            contains('Invalid symmetric algorithms section'),
          ),
        ),
      );
    });

    test('throws OhttpFormatException when symLen is 0', () {
      final buf = BytesBuilder();
      buf.addByte(0x01);
      buf.add([0x00, 0x20]);
      buf.add(List.filled(32, 0x00));
      buf.add([0x00, 0x00]); // sym_len = 0

      expect(
        () => OhttpKeyConfig.parse(Uint8List.fromList(buf.toBytes())),
        throwsA(isA<OhttpFormatException>()),
      );
    });

    test('throws OhttpFormatException when data is shorter than symLen claims', () {
      final buf = BytesBuilder();
      buf.addByte(0x01);
      buf.add([0x00, 0x20]);
      buf.add(List.filled(32, 0x00));
      buf.add([0x00, 0x08]); // sym_len = 8 (claims 8 bytes)
      buf.add([0x00, 0x01]); // only 4 bytes available
      buf.add([0x00, 0x01]);

      expect(
        () => OhttpKeyConfig.parse(Uint8List.fromList(buf.toBytes())),
        throwsA(isA<OhttpFormatException>()),
      );
    });
  });

  group('OhttpKeyConfig.validate', () {
    test('accepts supported cipher suite', () {
      final config = OhttpKeyConfig(
        keyId: 1,
        kemId: 0x0020,
        publicKey: Uint8List(32),
        kdfId: 0x0001,
        aeadId: 0x0001,
      );
      config.validate();
    });

    test('rejects unsupported KEM with OhttpConfigException', () {
      final config = OhttpKeyConfig(
        keyId: 1,
        kemId: 0x0010,
        publicKey: Uint8List(32),
        kdfId: 0x0001,
        aeadId: 0x0001,
      );
      expect(() => config.validate(), throwsA(isA<OhttpConfigException>()));
    });

    test('rejects unsupported KDF with OhttpConfigException', () {
      final config = OhttpKeyConfig(
        keyId: 1,
        kemId: 0x0020,
        publicKey: Uint8List(32),
        kdfId: 0x0002,
        aeadId: 0x0001,
      );
      expect(() => config.validate(), throwsA(isA<OhttpConfigException>()));
    });

    test('rejects unsupported AEAD with OhttpConfigException', () {
      final config = OhttpKeyConfig(
        keyId: 1,
        kemId: 0x0020,
        publicKey: Uint8List(32),
        kdfId: 0x0001,
        aeadId: 0x0002,
      );
      expect(() => config.validate(), throwsA(isA<OhttpConfigException>()));
    });
  });

  group('ohttpEncapsulate', () {
    test('produces correctly structured output', () async {
      final x25519 = X25519();
      final kp = await x25519.newKeyPair();
      final pk = await kp.extractPublicKey();

      final config = OhttpKeyConfig(
        keyId: 0x01,
        kemId: 0x0020,
        publicKey: Uint8List.fromList(pk.bytes),
        kdfId: 0x0001,
        aeadId: 0x0001,
      );

      final binaryRequest = Uint8List.fromList([1, 2, 3, 4, 5]);
      final result = await ohttpEncapsulate(config, binaryRequest);

      // encRequest = header(7) || enc(32) || ciphertext
      expect(result.encRequest.length, greaterThan(7 + 32));

      // Header: key_id(1) || kem_id(2) || kdf_id(2) || aead_id(2)
      expect(result.encRequest[0], 0x01);
      expect(result.encRequest[1], 0x00);
      expect(result.encRequest[2], 0x20);
      expect(result.encRequest[3], 0x00);
      expect(result.encRequest[4], 0x01);
      expect(result.encRequest[5], 0x00);
      expect(result.encRequest[6], 0x01);

      expect(result.enc.length, 32);
      expect(result.exportedSecret.length, 16);

      // Ciphertext = plaintext(5) + AES-GCM tag(16) = 21 bytes
      final ctLen = result.encRequest.length - 7 - 32;
      expect(ctLen, 5 + 16);
    });
  });

  group('ohttpDecapsulate', () {
    test('rejects too-short response with OhttpDecapsulationException', () {
      expect(
        () => ohttpDecapsulate(Uint8List(32), Uint8List(16), Uint8List(16)),
        throwsA(isA<OhttpDecapsulationException>()),
      );
    });

    test('rejects response with only nonce and no valid ciphertext', () {
      expect(
        () => ohttpDecapsulate(Uint8List(32), Uint8List(16), Uint8List(17)),
        throwsA(
          isA<OhttpDecapsulationException>().having(
            (e) => e.message,
            'message',
            contains('Ciphertext too short'),
          ),
        ),
      );
    });

    test('throws OhttpCryptoException on authentication failure', () async {
      // Build a fake encapsulated response with correct length but garbage ciphertext.
      // response nonce (16) + ciphertext(8) + tag(16) = 40 bytes
      final encResponse = Uint8List(40);
      // fill with non-zero to avoid accidental decryption
      encResponse.fillRange(0, encResponse.length, 0xFF);

      await expectLater(
        ohttpDecapsulate(Uint8List(32), Uint8List(16), encResponse),
        throwsA(isA<OhttpCryptoException>()),
      );
    });
  });
}
