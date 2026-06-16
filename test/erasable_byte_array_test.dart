import 'dart:typed_data';

import 'package:ohttp_dart/src/erasable_byte_array.dart';
import 'package:test/test.dart';

void main() {
  group('ErasableByteArray', () {
    test('bytes returns the wrapped data', () {
      final data = Uint8List.fromList([1, 2, 3, 4]);
      final arr = ErasableByteArray(data);
      expect(arr.bytes, data);
    });

    test('erase zeroes the underlying buffer', () {
      final data = Uint8List.fromList(List.filled(32, 0x42));
      ErasableByteArray(data).erase();
      expect(data.every((b) => b == 0), isTrue);
    });

    test('bytes throws StateError after erase', () {
      final arr = ErasableByteArray(Uint8List.fromList(List.filled(4, 0xAA)));
      arr.erase();
      expect(() => arr.bytes, throwsA(isA<StateError>()));
    });
  });
}
