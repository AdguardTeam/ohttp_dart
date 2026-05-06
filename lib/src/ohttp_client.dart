import 'dart:typed_data';

import 'package:http/http.dart' as http;

import 'bhttp.dart' as bhttp;
import 'ohttp.dart';

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

class OhttpHeader {
  final String name;
  final String value;

  OhttpHeader({required this.name, required this.value});
}

class OhttpResponse {
  final int statusCode;
  final List<OhttpHeader> headers;
  final Uint8List body;

  OhttpResponse({
    required this.statusCode,
    required this.headers,
    required this.body,
  });
}

// ---------------------------------------------------------------------------
// Gateway configuration
// ---------------------------------------------------------------------------

class OhttpGatewayConfig {
  final String gatewayBaseUrl;
  final String configPath;
  final String requestPath;
  final String targetAuthority;
  final String targetScheme;
  final String? directBaseUrl;

  const OhttpGatewayConfig({
    required this.gatewayBaseUrl,
    required this.configPath,
    required this.requestPath,
    required this.targetAuthority,
    this.targetScheme = 'https',
    this.directBaseUrl,
  });

  String get effectiveDirectBaseUrl => directBaseUrl ?? gatewayBaseUrl;
}

// ---------------------------------------------------------------------------
// OHTTP Client — pure Dart
// ---------------------------------------------------------------------------

class OhttpClient {
  final http.Client _httpClient;
  final OhttpGatewayConfig gateway;

  OhttpClient({
    http.Client? httpClient,
    required this.gateway,
  }) : _httpClient = httpClient ?? http.Client();

  /// Send an HTTP request through OHTTP (pure Dart implementation).
  Future<OhttpResponse> send({
    required String method,
    required String path,
    Map<String, String>? headers,
    Uint8List? body,
    void Function(String message)? onLog,
  }) async {
    onLog?.call(
      'Fetching OHTTP KeyConfig from ${gateway.gatewayBaseUrl}${gateway.configPath}...',
    );

    // 1. Get the gateway's KeyConfig
    final configResponse = await _httpClient.get(
      Uri.parse('${gateway.gatewayBaseUrl}${gateway.configPath}'),
    );
    if (configResponse.statusCode != 200) {
      throw Exception(
        'Failed to fetch KeyConfig: HTTP ${configResponse.statusCode}',
      );
    }
    final config = OhttpKeyConfig.parse(configResponse.bodyBytes);
    onLog?.call(
      'KeyConfig received (${configResponse.bodyBytes.length} bytes, '
      'keyId=${config.keyId})',
    );

    // 2. Serialize inner request to BHTTP
    onLog?.call('Serializing request to BHTTP...');
    final binaryRequest = bhttp.serializeRequest(
      method: method,
      scheme: gateway.targetScheme,
      authority: gateway.targetAuthority,
      path: path,
      headers: headers ?? {},
      body: body ?? Uint8List(0),
    );

    // 3. Encapsulate via OHTTP (pure Dart HPKE)
    onLog?.call('Encapsulating request via OHTTP...');
    final encResult = await ohttpEncapsulate(config, binaryRequest);
    onLog?.call('Request encapsulated (${encResult.encRequest.length} bytes)');

    // 4. Send to gateway
    onLog?.call(
      'Sending to OHTTP gateway ${gateway.gatewayBaseUrl}${gateway.requestPath}...',
    );
    final gatewayResponse = await _httpClient.post(
      Uri.parse('${gateway.gatewayBaseUrl}${gateway.requestPath}'),
      headers: {'Content-Type': 'message/ohttp-req'},
      body: encResult.encRequest,
    );
    if (gatewayResponse.statusCode != 200) {
      throw Exception('Gateway error: HTTP ${gatewayResponse.statusCode}');
    }
    onLog?.call(
      'Gateway responded (${gatewayResponse.bodyBytes.length} bytes)',
    );

    // 5. Decapsulate response (pure Dart)
    onLog?.call('Decapsulating response...');
    final binaryResponse = await ohttpDecapsulate(
      encResult.enc,
      encResult.exportedSecret,
      gatewayResponse.bodyBytes,
    );

    // 6. Parse BHTTP response
    final bhttpResp = bhttp.parseResponse(binaryResponse);
    final response = OhttpResponse(
      statusCode: bhttpResp.statusCode,
      headers: bhttpResp.headers.map((h) => OhttpHeader(name: h.$1, value: h.$2)).toList(),
      body: bhttpResp.body,
    );
    onLog?.call('Response decapsulated: HTTP ${response.statusCode}');

    return response;
  }

  /// Send a direct HTTP request (for comparison).
  Future<OhttpResponse> sendDirect({
    required String method,
    required String path,
    Map<String, String>? headers,
    Uint8List? body,
  }) async {
    final uri = Uri.parse('${gateway.effectiveDirectBaseUrl}$path');
    final request = http.Request(method, uri);
    if (headers != null) {
      request.headers.addAll(headers);
    }
    if (body != null) {
      request.bodyBytes = body;
    }

    final streamedResponse = await _httpClient.send(request);
    final responseBody = await streamedResponse.stream.toBytes();

    return OhttpResponse(
      statusCode: streamedResponse.statusCode,
      headers: streamedResponse.headers.entries.map((e) => OhttpHeader(name: e.key, value: e.value)).toList(),
      body: Uint8List.fromList(responseBody),
    );
  }

  void dispose() {
    _httpClient.close();
  }
}
