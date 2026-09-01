import 'dart:typed_data';
import 'data/key_config_fetch_result.dart';

/// Transport abstraction — the bytes-in / bytes-out seam between
/// OHTTP orchestration and any HTTP client.
///
/// Implementations MUST throw [OhttpGatewayException] when the key config
/// endpoint returns a non-2xx response, and [OhttpRelayException] when the
/// relay returns a non-2xx response, so that [OhttpSession] can invalidate
/// the KeyConfig cache and retry only for relay errors.
abstract interface class OhttpTransport {
  /// Fetch the raw OHTTP KeyConfig from the gateway.
  /// Returns raw bytes and an optional max-age TTL from the gateway.
  Future<KeyConfigFetchResult> fetchKeyConfig();

  /// POST the encapsulated OHTTP request to the relay.
  ///
  /// Implementations must set Content-Type: message/ohttp-req.
  Future<Uint8List> postToRelay(Uint8List body);
}
