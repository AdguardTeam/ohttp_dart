import 'dart:typed_data';
import 'package:http/http.dart' as http;
import 'package:ohttp_dart/src/transport.dart';

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

  HttpClientTransport({
    required http.Client client,
    required Uri keysUrl,
    required Uri gatewayUrl,
  }) : _client = client,
       _keysUrl = keysUrl,
       _gatewayUrl = gatewayUrl;

  @override
  Future<Uint8List> fetchKeyConfig() async {
    final response = await _client.get(_keysUrl);

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
    final response = await _client.post(
      _gatewayUrl,
      headers: {
        'content-type': _ohttpMediaType,
      },
      body: body,
    );

    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw OhttpGatewayException(
        statusCode: response.statusCode,
        message: 'Failed to POST to Gateway $_gatewayUrl',
      );
    }

    return response.bodyBytes;
  }
}
