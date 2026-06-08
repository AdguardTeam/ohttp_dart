import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:meta/meta.dart';
import 'package:ohttp_dart/src/exceptions.dart';
import 'package:ohttp_dart/src/ohttp_transport.dart';

/// An [OhttpTransport] that delegates HTTP calls to an injected [http.Client].
///
/// [fetchKeyConfig] issues a GET to [_keysUrl]; [postToGateway] issues a
/// POST to [_gatewayUrl] with Content-Type 'message/ohttp-req'. Any non-2xx
/// response from either endpoint throws [OhttpGatewayException]. The caller
/// retains ownership of the [http.Client].
class HttpClientTransport implements OhttpTransport {
  static const _ohttpMediaType = 'message/ohttp-req';

  final http.Client _client;
  final Uri _keysUrl;
  final Uri _gatewayUrl;

  /// Creates an HTTP client transport for OHTTP.
  ///
  /// Throws [OhttpConfigException] if [keysUrl] or [gatewayUrl] do not use
  /// the HTTPS scheme.
  ///
  /// ## Security Warning
  ///
  /// Per [RFC 9458 §1](https://www.rfc-editor.org/rfc/rfc9458#section-1),
  /// the connection between the client and the relay/gateway MUST be protected
  /// with TLS. Only HTTPS URLs are accepted.
  HttpClientTransport({
    required http.Client client,
    required Uri keysUrl,
    required Uri gatewayUrl,
  }) : _client = client,
       _keysUrl = keysUrl,
       _gatewayUrl = gatewayUrl {
    _validateHttpsScheme(keysUrl, 'keysUrl');
    _validateHttpsScheme(gatewayUrl, 'gatewayUrl');
  }

  /// Creates an HTTP client transport without HTTPS scheme validation.
  ///
  /// This constructor is intended **exclusively for testing scenarios**
  /// (e.g., MockClient with http://localhost). Production code MUST NOT use it.
  @visibleForTesting
  HttpClientTransport.insecureForTesting({
    required http.Client client,
    required Uri keysUrl,
    required Uri gatewayUrl,
  }) : _client = client,
       _keysUrl = keysUrl,
       _gatewayUrl = gatewayUrl;

  @override
  Future<Uint8List> fetchKeyConfig() async {
    final http.Response response;
    try {
      response = await _client.get(_keysUrl);
    } on OhttpException {
      rethrow;
    } on Exception catch (e) {
      throw OhttpNetworkException(
        'Network error while fetching KeyConfig from $_keysUrl',
        cause: e,
      );
    }

    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw OhttpGatewayException(
        statusCode: response.statusCode,
        message: 'Failed to fetch KeyConfig from $_keysUrl',
      );
    }

    return response.bodyBytes;
  }

  @override
  Future<Uint8List> postToGateway(Uint8List body) async {
    final http.Response response;
    try {
      response = await _client.post(
        _gatewayUrl,
        headers: {
          'content-type': _ohttpMediaType,
        },
        body: body,
      );
    } on OhttpException {
      rethrow;
    } on Exception catch (e) {
      throw OhttpNetworkException(
        'Network error while posting to Gateway $_gatewayUrl',
        cause: e,
      );
    }

    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw OhttpGatewayException(
        statusCode: response.statusCode,
        message: 'Failed to POST to Gateway $_gatewayUrl',
      );
    }

    return response.bodyBytes;
  }

  void _validateHttpsScheme(Uri uri, String parameterName) {
    if (uri.scheme != 'https') {
      throw OhttpConfigException(
        '$parameterName must use HTTPS scheme per RFC 9458 §1. '
        'Got scheme: "${uri.scheme}"',
      );
    }
  }
}
