import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:ohttp_dart/ohttp_dart.dart';
import 'package:ohttp_dart/src/cipher_suite.dart';
import 'package:test/test.dart';

import 'stubs/gateway_stub.dart';
import 'test_utils.dart';

void main() {
  group('OhttpKeyConfig.parse', () {
    test('parses valid 41-byte config', () {
      final buf = BytesBuilder();
      buf.addByte(0x01); // key_id
      buf.add([0x00, 0x20]); // kem_id = X25519
      buf.add(List.filled(CipherSuite.kemPublicKeyLength, 0xAB)); // public_key
      buf.add([0x00, 0x04]); // sym_len = 4
      buf.add([0x00, 0x01]); // kdf_id = HKDF-SHA256
      buf.add([0x00, 0x01]); // aead_id = AES-128-GCM

      final config = OhttpKeyConfig.parse(Uint8List.fromList(buf.toBytes()));

      expect(config.keyId, 0x01);
      expect(config.kemId, 0x0020);
      expect(config.publicKey.length, CipherSuite.kemPublicKeyLength);
      expect(config.publicKey[0], 0xAB);
      expect(config.kdfId, 0x0001);
      expect(config.aeadId, 0x0001);
    });

    test('throws OhttpKeyConfigException on too-short data', () {
      expect(
        () => OhttpKeyConfig.parse(Uint8List.fromList([0x01, 0x00])),
        throwsA(isA<OhttpKeyConfigException>()),
      );
    });

    test('throws OhttpUnsupportedSuiteException on unsupported KEM', () {
      final buf = BytesBuilder();
      buf.addByte(0x01);
      buf.add([0x00, 0x10]); // unsupported KEM
      buf.add(List.filled(CipherSuite.kemPublicKeyLength, 0x00));
      buf.add([0x00, 0x04]);
      buf.add([0x00, 0x01]);
      buf.add([0x00, 0x01]);

      expect(
        () => OhttpKeyConfig.parse(Uint8List.fromList(buf.toBytes())),
        throwsA(isA<OhttpUnsupportedSuiteException>()),
      );
    });

    test('throws OhttpKeyConfigException when data is too short for public key', () {
      // Passes the initial length check (>= 7) and the KEM check (0x0020 is supported),
      // but does not contain enough bytes for the 32-byte public key + 2-byte sym_len.
      final buf = BytesBuilder();
      buf.addByte(0x01); // key_id
      buf.add([0x00, 0x20]); // kem_id = X25519 (supported)
      buf.add(List.filled(10, 0x00)); // only 10 bytes instead of 32 + 2

      expect(
        () => OhttpKeyConfig.parse(Uint8List.fromList(buf.toBytes())),
        throwsA(isA<OhttpKeyConfigException>()),
      );
    });

    test('throws OhttpKeyConfigException on short symmetric section', () {
      final buf = BytesBuilder();
      buf.addByte(0x01);
      buf.add([0x00, 0x20]);
      buf.add(List.filled(CipherSuite.kemPublicKeyLength, 0x00));
      buf.add([0x00, 0x02]); // sym_len = 2 (too short, need 4)
      buf.add([0x00, 0x01]); // only 2 bytes, no room for aead_id

      expect(
        () => OhttpKeyConfig.parse(Uint8List.fromList(buf.toBytes())),
        throwsA(isA<OhttpKeyConfigException>()),
      );
    });

    test('throws OhttpKeyConfigException when data has trailing bytes after symmetric section', () {
      final buf = BytesBuilder();
      buf.addByte(0x01);
      buf.add([0x00, 0x20]);
      buf.add(List.filled(CipherSuite.kemPublicKeyLength, 0x00));
      buf.add([0x00, 0x04]); // symLen = 4
      buf.add([0x00, 0x01]); // supported KDF
      buf.add([0x00, 0x01]); // supported AEAD
      buf.add([0xFF, 0xFF]); // trailing bytes

      expect(
        () => OhttpKeyConfig.parse(Uint8List.fromList(buf.toBytes())),
        throwsA(
          isA<OhttpKeyConfigException>().having(
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

    test('throws OhttpUnsupportedSuiteException when no suite is supported', () {
      final config = multiSuiteKeyConfig(
        suiteIds: [
          (0x0002, 0x0002), // unsupported
          (0x0003, 0x0003), // unsupported
        ],
      );

      expect(
        () => OhttpKeyConfig.parse(config),
        throwsA(
          isA<OhttpUnsupportedSuiteException>().having(
            (e) => e.message,
            'message',
            contains('No supported cipher suite'),
          ),
        ),
      );
    });

    test('throws OhttpKeyConfigException when symLen is not a multiple of 4', () {
      final buf = BytesBuilder();
      buf.addByte(0x01);
      buf.add([0x00, 0x20]);
      buf.add(List.filled(CipherSuite.kemPublicKeyLength, 0x00));
      buf.add([0x00, 0x05]); // sym_len = 5 (not multiple of 4)
      buf.add(List.filled(5, 0x00)); // 5 bytes of suite data

      expect(
        () => OhttpKeyConfig.parse(Uint8List.fromList(buf.toBytes())),
        throwsA(
          isA<OhttpKeyConfigException>().having(
            (e) => e.message,
            'message',
            contains('Invalid symmetric algorithms section'),
          ),
        ),
      );
    });

    test('throws OhttpKeyConfigException when symLen is 0', () {
      final buf = BytesBuilder();
      buf.addByte(0x01);
      buf.add([0x00, 0x20]);
      buf.add(List.filled(CipherSuite.kemPublicKeyLength, 0x00));
      buf.add([0x00, 0x00]); // sym_len = 0

      expect(
        () => OhttpKeyConfig.parse(Uint8List.fromList(buf.toBytes())),
        throwsA(isA<OhttpKeyConfigException>()),
      );
    });

    test('throws OhttpKeyConfigException when data is shorter than symLen claims', () {
      final buf = BytesBuilder();
      buf.addByte(0x01);
      buf.add([0x00, 0x20]);
      buf.add(List.filled(CipherSuite.kemPublicKeyLength, 0x00));
      buf.add([0x00, 0x08]); // sym_len = 8 (claims 8 bytes)
      buf.add([0x00, 0x01]); // only 4 bytes available
      buf.add([0x00, 0x01]);

      expect(
        () => OhttpKeyConfig.parse(Uint8List.fromList(buf.toBytes())),
        throwsA(isA<OhttpKeyConfigException>()),
      );
    });
  });

  group('OhttpKeyConfig.validate', () {
    test('accepts supported cipher suite', () {
      final config = OhttpKeyConfig(
        keyId: 1,
        kemId: 0x0020,
        publicKey: Uint8List(CipherSuite.kemPublicKeyLength),
        kdfId: 0x0001,
        aeadId: 0x0001,
      );
      config.validate();
    });

    test('rejects unsupported KEM with OhttpUnsupportedSuiteException', () {
      final config = OhttpKeyConfig(
        keyId: 1,
        kemId: 0x0010,
        publicKey: Uint8List(CipherSuite.kemPublicKeyLength),
        kdfId: 0x0001,
        aeadId: 0x0001,
      );
      expect(() => config.validate(), throwsA(isA<OhttpUnsupportedSuiteException>()));
    });

    test('rejects unsupported KDF with OhttpUnsupportedSuiteException', () {
      final config = OhttpKeyConfig(
        keyId: 1,
        kemId: 0x0020,
        publicKey: Uint8List(CipherSuite.kemPublicKeyLength),
        kdfId: 0x0002,
        aeadId: 0x0001,
      );
      expect(() => config.validate(), throwsA(isA<OhttpUnsupportedSuiteException>()));
    });

    test('rejects unsupported AEAD with OhttpUnsupportedSuiteException', () {
      final config = OhttpKeyConfig(
        keyId: 1,
        kemId: 0x0020,
        publicKey: Uint8List(CipherSuite.kemPublicKeyLength),
        kdfId: 0x0001,
        aeadId: 0x0002,
      );
      expect(() => config.validate(), throwsA(isA<OhttpUnsupportedSuiteException>()));
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
      expect(result.encRequest.length, greaterThan(7 + CipherSuite.kemPublicKeyLength));

      // Header: key_id(1) || kem_id(2) || kdf_id(2) || aead_id(2)
      expect(result.encRequest[0], 0x01);
      expect(result.encRequest[1], 0x00);
      expect(result.encRequest[2], 0x20);
      expect(result.encRequest[3], 0x00);
      expect(result.encRequest[4], 0x01);
      expect(result.encRequest[5], 0x00);
      expect(result.encRequest[6], 0x01);

      expect(result.enc.bytes.length, CipherSuite.kemPublicKeyLength);
      expect(result.exportedSecret.bytes.length, 16);

      // Ciphertext = plaintext(5) + AES-GCM tag(16) = 21 bytes
      final ctLen = result.encRequest.length - 7 - CipherSuite.kemPublicKeyLength;
      expect(ctLen, 5 + 16);
    });

    test('encapsulates empty binaryRequest without error', () async {
      final kp = await X25519().newKeyPair();
      final pk = await kp.extractPublicKey();
      final config = OhttpKeyConfig(
        keyId: 0x01,
        kemId: 0x0020,
        publicKey: Uint8List.fromList(pk.bytes),
        kdfId: 0x0001,
        aeadId: 0x0001,
      );

      final result = await ohttpEncapsulate(config, Uint8List(0));

      // header(7) + enc(32) + ciphertext(0 plaintext + 16 tag) = 55 bytes
      expect(
        result.encRequest.length,
        7 + CipherSuite.kemPublicKeyLength + CipherSuite.aeadTagLength,
      );
      expect(result.enc.bytes.length, CipherSuite.kemPublicKeyLength);
      expect(result.exportedSecret.bytes.length, CipherSuite.aeadKeyLength);

      result.dispose();
    });
  });

  group('ohttpDecapsulate', () {
    test('rejects too-short response with OhttpDecapsulationException', () {
      expect(
        () => ohttpDecapsulate(
          Uint8List(CipherSuite.kemPublicKeyLength),
          Uint8List(CipherSuite.aeadKeyLength),
          Uint8List(CipherSuite.aeadNonceLength),
        ),
        throwsA(isA<OhttpDecapsulationException>()),
      );
    });

    test('rejects response exactly at responseNonceLen boundary with OhttpDecapsulationException', () {
      // encResponse.length == responseNonceLen (16) satisfies length <= _responseNonceLen,
      // so it must be rejected — there are no ciphertext bytes after the nonce.
      expect(
        () => ohttpDecapsulate(
          Uint8List(CipherSuite.kemPublicKeyLength),
          Uint8List(CipherSuite.aeadKeyLength),
          Uint8List(responseNonceLen),
        ),
        throwsA(isA<OhttpDecapsulationException>()),
      );
    });

    test('rejects response with only nonce and no valid ciphertext', () {
      expect(
        () => ohttpDecapsulate(
          Uint8List(CipherSuite.kemPublicKeyLength),
          Uint8List(CipherSuite.aeadKeyLength),
          Uint8List(responseNonceLen + 1),
        ),
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
      // response nonce (responseNonceLen) + ciphertext(8) + tag(aeadTagLength)
      final encResponse = Uint8List(responseNonceLen + 8 + CipherSuite.aeadTagLength);
      // fill with non-zero to avoid accidental decryption
      encResponse.fillRange(0, encResponse.length, 0xFF);

      await expectLater(
        ohttpDecapsulate(
          Uint8List(CipherSuite.kemPublicKeyLength),
          Uint8List(CipherSuite.aeadKeyLength),
          encResponse,
        ),
        throwsA(isA<OhttpCryptoException>()),
      );
    });
  });

  group('OHTTP encapsulate / decapsulate roundtrip (RFC 9458 §4.3, §4.4)', () {
    test('decrypts to original response after simulated gateway encryption', () async {
      // 1. Build the fixed gateway key config.
      final config = buildGatewayKeyConfig();

      // 2. Client: encapsulate a binary BHTTP request.
      final binaryRequest = Uint8List.fromList([10, 20, 30, 40, 50]);
      final result = await ohttpEncapsulate(config, binaryRequest);

      // 3. Gateway: seal a BHTTP response per RFC 9458 §4.6.2.
      final binaryResponse = Uint8List.fromList([100, 101, 102, 103, 104]);
      final encResponse = await sealBhttpResponse(
        result.enc.bytes,
        result.exportedSecret.bytes,
        binaryResponse,
      );

      // 4. Client: decapsulate the gateway's encrypted response.
      final decrypted = await ohttpDecapsulate(
        result.enc.bytes,
        result.exportedSecret.bytes,
        encResponse,
      );

      // 5. Verify the recovered plaintext equals the original BHTTP response.
      expect(decrypted, equals(binaryResponse));

      result.dispose();
    });

    test('decapsulates empty response payload to empty list', () async {
      // 1. Build the fixed gateway key config.
      final config = buildGatewayKeyConfig();

      // 2. Client: encapsulate an empty binary BHTTP request.
      final result = await ohttpEncapsulate(config, Uint8List(0));

      // 3. Gateway: seal an empty BHTTP response per RFC 9458 §4.6.2.
      final encResponse = await sealBhttpResponse(
        result.enc.bytes,
        result.exportedSecret.bytes,
        Uint8List(0),
      );

      // 4. Client: decapsulate — result must be an empty list.
      final decrypted = await ohttpDecapsulate(
        result.enc.bytes,
        result.exportedSecret.bytes,
        encResponse,
      );

      expect(decrypted, isEmpty);

      result.dispose();
    });

    test('throws OhttpCryptoException when one ciphertext byte is flipped (AEAD auth failure)', () async {
      // 1. Build the fixed gateway key config.
      final config = buildGatewayKeyConfig();

      // 2. Client: encapsulate a binary BHTTP request.
      final binaryRequest = Uint8List.fromList([10, 20, 30, 40, 50]);
      final result = await ohttpEncapsulate(config, binaryRequest);

      // 3. Gateway: seal a BHTTP response per RFC 9458 §4.6.2.
      final binaryResponse = Uint8List.fromList([100, 101, 102, 103, 104]);
      final encResponse = await sealBhttpResponse(
        result.enc.bytes,
        result.exportedSecret.bytes,
        binaryResponse,
      );

      // 4. Corrupt the first ciphertext byte to break AEAD authentication.
      //    encResponse = response_nonce || ciphertext || tag
      encResponse[responseNonceLen] ^= 0xFF; // flip all bits in first ciphertext byte

      // 5. Client: ohttpDecapsulate must detect the tampered ciphertext and throw.
      await expectLater(
        ohttpDecapsulate(result.enc.bytes, result.exportedSecret.bytes, encResponse),
        throwsA(isA<OhttpCryptoException>()),
      );

      result.dispose();
    });
  });

  group('OhttpEncapsulateResult.dispose', () {
    test('zeroes enc and exportedSecret', () {
      final result = OhttpEncapsulateResult(
        encRequest: Uint8List.fromList([1, 2, 3, 4]),
        enc: ErasableByteArray(Uint8List.fromList([5, 6, 7, 8])),
        exportedSecret: ErasableByteArray(Uint8List.fromList([9, 10, 11, 12])),
      );

      // Verify data is non-zero before dispose
      expect(result.enc.bytes.any((b) => b != 0), isTrue);
      expect(result.exportedSecret.bytes.any((b) => b != 0), isTrue);
      expect(result.encRequest.any((b) => b != 0), isTrue);

      result.dispose();

      // enc and exportedSecret must be erased — accessing bytes throws StateError
      expect(() => result.enc.bytes, throwsStateError);
      expect(() => result.exportedSecret.bytes, throwsStateError);

      // encRequest must NOT be zeroed (already sent over the network)
      expect(result.encRequest, Uint8List.fromList([1, 2, 3, 4]));
      expect(result.encRequest.any((b) => b != 0), isTrue);
    });
  });
}
