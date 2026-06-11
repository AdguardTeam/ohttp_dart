import 'dart:typed_data';

/// Extension on [Uint8List] for secure memory operations.
extension WipeBytesExtension on Uint8List {
  /// Zeroes out the contents of this byte array in-place.
  void wipeBytes() => fillRange(0, length, 0);
}
