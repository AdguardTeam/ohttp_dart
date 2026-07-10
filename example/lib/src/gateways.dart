import 'package:http/http.dart' as http;
import 'package:ohttp_dart/http.dart';

/// Configuration for the httpbin gateway.
///
/// Provides key config at `/ohttp/config` and gateway at `/ohttp/gateway`.
HttpClientTransport httpbinTransport(http.Client client) {
  return HttpClientTransport(
    client: client,
    keysUrl: Uri.parse('https://httpbin.agrd.workers.dev/ohttp/config'),
    gatewayUrl: Uri.parse('https://httpbin.agrd.workers.dev/ohttp/gateway'),
  );
}

/// Configuration for the PIR Gateway.
///
/// Provides key config at `/ohttp-configs` and gateway at `/ohttp-request`.
HttpClientTransport pirGatewayTransport(http.Client client) {
  return HttpClientTransport(
    client: client,
    keysUrl: Uri.parse('https://pir-gateway.adtidy.org/ohttp-configs'),
    gatewayUrl: Uri.parse('https://pir-gateway.adtidy.org/ohttp-request'),
  );
}

/// Authority (host) for the httpbin gateway.
const httpbinAuthority = 'httpbin.agrd.workers.dev';

/// Authority (host) for the PIR Gateway.
const pirGatewayAuthority = 'pir-gateway.adtidy.org';
