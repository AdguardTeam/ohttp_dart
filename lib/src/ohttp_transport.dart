import 'dart:typed_data';

/// Transport abstraction — the bytes-in / bytes-out seam between
/// OHTTP orchestration and any HTTP client.
///
/// Implementations MUST throw [OhttpGatewayException] on non-2xx responses
/// so that [OhttpSession] can invalidate the KeyConfig cache.
abstract interface class OhttpTransport {
  /// Fetch the raw OHTTP KeyConfig from the gateway.
  Future<Uint8List> fetchKeyConfig();

  /// POST the encapsulated OHTTP request to the gateway.
  ///
  /// Implementations must set Content-Type: message/ohttp-req.
  Future<Uint8List> postToGateway(Uint8List body);
}
