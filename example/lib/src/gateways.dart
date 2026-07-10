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

/// Authority (host) for the httpbin gateway.
const httpbinAuthority = 'httpbin.agrd.workers.dev';
