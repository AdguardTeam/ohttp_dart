// ignore_for_file: public_member_api_docs

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
        },
        seed: 42,
      );
    });

    // parseResponse is safe on arbitrary bytes: the outer catch blocks in
    // bhttp.dart (on FormatException at line 256, on RangeError at line 261)
    // both rethrow as OhttpFormatException, and OhttpSizeLimitException is
    // thrown inside the same try block and propagates unchanged. No other
    // exception type can escape the function.
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
