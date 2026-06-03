import 'package:http/http.dart';

import 'package:ohttp_dart/src/ohttp_data.dart';
import 'package:ohttp_dart/src/ohttp_session.dart';

/// An [Client] that tunnels requests through an OHTTP gateway.
///
/// Translates each [BaseRequest] into an [OhttpRequestData] and passes it
/// to [OhttpSession.send]. The response is converted back to a
/// [StreamedResponse] so that existing code written against the
/// [Client] interface can use OHTTP without modification.
///
/// The method, scheme, authority, and path are taken from [BaseRequest.url].
/// If the caller omits the `host` header it is synthesized from the URL;
/// an explicit `host` is passed through unchanged. Default ports (80 for
/// http, 443 for https) are omitted from the authority.
///
/// When [_closeWith] is supplied, [close] delegates to that client;
/// otherwise [close] is a no-op, leaving lifecycle management to the
/// caller's DI layer.
class OhttpHttpClient extends BaseClient {
  static const _defaultHttpPort = 80;
  static const _defaultHttpsPort = 443;
  static const _hostHeader = 'host';

  final OhttpSession _session;
  final Client? _closeWith;

  OhttpHttpClient({
    required OhttpSession session,
    Client? closeWith,
  }) : _session = session,
       _closeWith = closeWith;

  @override
  Future<StreamedResponse> send(BaseRequest request) async {
    final url = request.url;

    final headers = <(String, String)>[];
    final host = _buildHost(url);

    var hasHost = false;
    request.headers.forEach((name, value) {
      headers.add((name, value));

      // `dart:io` injects `host` at the transport layer, which the encrypted
      // inner request never reaches. Fall back to the URL when it is missing.
      if (name.toLowerCase() == _hostHeader) {
        hasHost = true;
      }
    });

    if (!hasHost) {
      headers.add((_hostHeader, host));
    }

    final body = await request.finalize().toBytes();

    final requestData = OhttpRequestData(
      method: request.method,
      scheme: url.scheme,
      authority: host,
      path: _buildPath(url),
      headers: headers,
      body: body,
    );

    final responseData = await _session.send(requestData);

    final streamedResponse = StreamedResponse(
      ByteStream.fromBytes(responseData.body),
      responseData.statusCode,
      contentLength: responseData.body.length,
    );
    for (final (name, value) in responseData.headers) {
      streamedResponse.headers[name] = value;
    }

    return streamedResponse;
  }

  @override
  void close() {
    _closeWith?.close();
  }

  String _buildHost(Uri url) {
    if (url.hasPort && !_isDefaultPort(url.scheme, url.port)) {
      return '${url.host}:${url.port}';
    }

    return url.host;
  }

  bool _isDefaultPort(String scheme, int port) =>
      (scheme == 'http' && port == _defaultHttpPort) || (scheme == 'https' && port == _defaultHttpsPort);

  String _buildPath(Uri url) {
    final path = url.path.isEmpty ? '/' : url.path;
    if (url.hasQuery) {
      return '$path?${url.query}';
    }

    return path;
  }
}
