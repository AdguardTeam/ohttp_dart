/// Pure Dart OHTTP client (RFC 9458).
///
/// Provides Oblivious HTTP encapsulation/decapsulation with:
/// - HPKE Base Mode Sender (RFC 9180)
/// - Binary HTTP serialization (RFC 9292)
/// - High-level OhttpClient for gateway communication
library;

export 'src/bhttp.dart';
export 'src/hpke.dart';
export 'src/ohttp.dart';
export 'src/ohttp_client.dart';
