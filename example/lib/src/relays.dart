import 'package:http/http.dart' as http;
import 'package:ohttp_dart/http.dart';

/// Authority (host) for the httpbin relay.
const httpbinAuthority = 'httpbin.agrd.workers.dev';

// Injected via --dart-define-from-file=config/dev_local_ohttp.env.
const _localRelayUrl = String.fromEnvironment('OHTTP_RELAY_URL');
const _localKeyConfigUrl = String.fromEnvironment('OHTTP_KEY_CONFIG_URL');

/// True when local relay URLs are provided at compile time.
const localRelayEnabled = _localRelayUrl != '' && _localKeyConfigUrl != '';

/// Configuration for the httpbin relay.
///
/// Provides key config at `/ohttp/config` and relay at `/ohttp/gateway`.
HttpClientTransport httpbinTransport(http.Client client) {
  return HttpClientTransport(
    client: client,
    keysUrl: Uri.parse('https://httpbin.agrd.workers.dev/ohttp/config'),
    relayUrl: Uri.parse('https://httpbin.agrd.workers.dev/ohttp/gateway'),
  );
}

HttpClientTransport localRelayTransport(http.Client client) =>
    HttpClientTransport(
      client: client,
      keysUrl: Uri.parse(_localKeyConfigUrl),
      relayUrl: Uri.parse(_localRelayUrl),
    );
