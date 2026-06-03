import 'dart:typed_data';

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
  final String method;
  final String scheme;

  /// Inner target host the gateway forwards to, not the gateway URL.
  final String authority;

  final String path;
  final List<(String, String)> headers;
  final Uint8List body;

  OhttpRequestData({
    required this.method,
    required this.scheme,
    required this.authority,
    required this.path,
    List<(String, String)>? headers,
    Uint8List? body,
  }) : headers = headers ?? [],
       body = body ?? Uint8List(0);
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
