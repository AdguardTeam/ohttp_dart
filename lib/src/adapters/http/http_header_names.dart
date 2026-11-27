/// Field names of HTTP messages exchanged by the `package:http` adapter.
///
/// Field names are case-insensitive
/// ([RFC 9110 §5.1](https://www.rfc-editor.org/rfc/rfc9110#section-5.1)).
abstract final class HttpHeaderNames {
  /// The `cache-control` field name, which carries the key config cache
  /// directives.
  static const cacheControl = 'cache-control';

  /// The `content-encoding` field name, which lists the codings applied to the
  /// inner response body.
  static const contentEncoding = 'content-encoding';

  /// The `content-length` field name, which describes the size of the coded
  /// inner response body.
  static const contentLength = 'content-length';

  /// The `content-type` field name, which identifies the encapsulated request
  /// as the `message/ohttp-req` media type.
  static const contentType = 'content-type';

  /// The `host` field name, which carries the authority of the inner request.
  static const host = 'host';
}
