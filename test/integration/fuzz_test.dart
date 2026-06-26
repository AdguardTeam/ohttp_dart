import 'dart:typed_data';

import 'package:kiri_check/kiri_check.dart';
import 'package:ohttp_dart/ohttp_dart.dart';
import 'package:test/test.dart';

void main() {
  group('Fuzz — property-based tests', () {
    property('varint encode → decode is identity on [0, 2^62)', () {
      forAll(
        integer(min: 0, max: 0x3FFFFFFFFFFFFFFF),
        (v) {
          final encoded = encodeVarint(v);
          final (decoded, _) = decodeVarint(encoded, 0);
          expect(decoded, equals(v));
          // RFC 9000 §16 defines four ranges with fixed byte widths.
          final expectedLen = switch (v) {
            < 0x40 => 1,
            < 0x4000 => 2,
            < 0x40000000 => 4,
            _ => 8,
          };
          expect(encoded.length, equals(expectedLen));
        },
        seed: 42,
      );
    });

    test('encodeVarint throws OhttpFormatException for negative values', () {
      expect(() => encodeVarint(-1), throwsA(isA<OhttpFormatException>()));
    });

    test('encodeVarint throws OhttpFormatException for values above 2^62-1', () {
      expect(
        () => encodeVarint(0x4000000000000000),
        throwsA(isA<OhttpFormatException>()),
      );
    });

    // decodeVarint either succeeds or throws OhttpFormatException on arbitrary input.
    // RangeError on truncated bytes is caught in bhttp.dart:86 and rethrown as
    // OhttpFormatException; the switch(prefix) arms cover all 4 values of first>>6.
    property(
      'decodeVarint on arbitrary bytes only throws OhttpFormatException',
      () {
        forAll(
          binary(),
          (bytes) {
            try {
              decodeVarint(Uint8List.fromList(bytes), 0);
            } on OhttpFormatException {
              // accepted
            }
          },
          seed: 42,
        );
      },
    );

    // parseResponse is safe on arbitrary bytes: its outer body is wrapped with
    // `on FormatException` and `on RangeError` catch arms that rethrow as
    // OhttpFormatException; OhttpSizeLimitException is raised inside the same
    // try block and propagates unchanged. No other exception type can escape.
    property(
      'parseResponse on random bytes only throws OhttpFormatException or OhttpSizeLimitException',
      () {
        forAll(
          binary(),
          (bytes) {
            try {
              parseResponse(Uint8List.fromList(bytes), limits: const BhttpResponseLimits());
            } on OhttpFormatException {
              // accepted
            } on OhttpSizeLimitException {
              // accepted
            }
          },
          seed: 42,
        );
      },
    );

    // OhttpKeyConfig.parse guards all byte-array accesses with explicit length
    // checks and throws OhttpKeyConfigException for structural errors and
    // OhttpUnsupportedSuiteException for unrecognized KEM/KDF/AEAD ids.
    // Random bytes that happen to parse successfully are also an accepted outcome.
    property(
      'OhttpKeyConfig.parse on random bytes only throws typed library exceptions',
      () {
        forAll(
          binary(),
          (bytes) {
            try {
              OhttpKeyConfig.parse(Uint8List.fromList(bytes));
            } on OhttpKeyConfigException {
              // accepted
            } on OhttpUnsupportedSuiteException {
              // accepted
            }
          },
          seed: 42,
        );
      },
    );
  });
}
