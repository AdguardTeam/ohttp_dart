/// Pure Dart OHTTP client (RFC 9458).
///
/// Core library providing:
/// - OHTTP encapsulation / decapsulation (RFC 9458)
/// - HPKE Base Mode Sender (RFC 9180)
/// - Binary HTTP serialization (RFC 9292)
/// - Transport abstraction and session orchestration
library;

export 'src/bhttp.dart';
export 'src/bhttp_response_limits.dart';
export 'src/erasable_byte_array.dart';
export 'src/exceptions.dart';
export 'src/hpke.dart';
export 'src/key_config_cache.dart';
export 'src/ohttp.dart';
export 'src/ohttp_data.dart';
export 'src/ohttp_observer.dart';
export 'src/ohttp_session.dart';
export 'src/ohttp_transport.dart';
