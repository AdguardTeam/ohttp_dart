import 'dart:typed_data';
import 'exceptions.dart';

/// HTTP-client-neutral request data.
///
/// The [authority] field holds the inner target host that the gateway
/// forwards to; the gateway URL itself is the transport's concern.
///
/// Headers stored as a list to preserve insertion order and duplicate
/// names (e.g. Set-Cookie). Collapsing to a map is deferred to adapters
/// that require it.
// ignore: prefer-match-file-name
class OhttpRequestData {
  /// Matches a URI scheme prefix like `http://`, `https://`, `ftp://`.
  static final _schemePrefix = RegExp(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://');

  /// Characters forbidden in an authority component per RFC 3986 §3.2:
  /// any whitespace, path separator (`/`), query (`?`), or fragment (`#`).
  static final _invalidAuthorityChars = RegExp(r'[\s/?#]');

  final String method;
  final String scheme;

  /// Inner target host the gateway forwards to, not the gateway URL.
  ///
  /// The authority MUST be a host or host:port pair without scheme, path,
  /// query, fragment, or spaces. Per [RFC 3986 §3.2](https://www.rfc-editor.org/rfc/rfc3986#section-3.2),
  /// the authority component is defined as: `[userinfo@]host[:port]`.
  ///
  /// Valid examples:
  /// - `example.com`
  /// - `example.com:8443`
  /// - `192.168.1.1:8080`
  final String authority;

  final String path;
  final List<(String, String)> headers;
  final Uint8List body;

  /// Creates HTTP request data for OHTTP encapsulation.
  ///
  /// Throws [OhttpConfigException] if [authority] is empty, contains a scheme
  /// prefix, spaces, path, query, or fragment.
  OhttpRequestData({
    required this.method,
    required this.scheme,
    required this.authority,
    required this.path,
    List<(String, String)>? headers,
    Uint8List? body,
  }) : headers = headers ?? [],
       body = body ?? Uint8List(0) {
    _validateAuthority(authority);
  }

  void _validateAuthority(String authority) {
    if (authority.isEmpty) {
      throw const OhttpConfigException(
        'authority must not be empty per RFC 3986 §3.2',
      );
    }

    if (_schemePrefix.hasMatch(authority)) {
      throw OhttpConfigException(
        'authority must not contain scheme prefix per RFC 3986 §3.2. '
        'Got: "$authority"',
      );
    }

    if (_invalidAuthorityChars.hasMatch(authority)) {
      throw OhttpConfigException(
        'authority must not contain path, query, fragment, or whitespace '
        'per RFC 3986 §3.2. Got: "$authority"',
      );
    }
  }
}

/// HTTP-client-neutral response data.
class OhttpResponseData {
  final int statusCode;
  final List<(String, String)> headers;
  final Uint8List body;

  OhttpResponseData({
    required this.body,
    required this.statusCode,
    this.headers = const [],
  });
}
