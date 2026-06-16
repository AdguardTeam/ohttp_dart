import 'dart:typed_data';

/// Wraps a byte array with a guard against accidental reads after [erase].
///
/// Calling [erase] zeroes the data; subsequent access to [bytes] throws.
class ErasableByteArray {
  /// Creates an [ErasableByteArray] wrapping [bytes].
  ErasableByteArray(Uint8List bytes) : _bytes = bytes;

  bool _erased = false;

  Uint8List? _bytes;

  /// Returns the bytes; throws [StateError] after [erase].
  Uint8List get bytes {
    if (_erased) {
      throw StateError('ErasableByteArray has been erased');
    }

    return _bytes!;
  }

  /// Zeroes the buffer and disallows further reads (idempotent).
  void erase() {
    if (_erased) {
      return;
    }

    _erased = true;

    final b = _bytes;
    if (b != null) {
      b.fillRange(0, b.length, 0);
      _bytes = null;
    }
  }
}
