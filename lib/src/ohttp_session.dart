import 'dart:typed_data';

import 'bhttp.dart' as bhttp;
import 'exceptions.dart';
import 'key_config_cache.dart';
import 'ohttp.dart';
import 'ohttp_data.dart';
import 'transport.dart';

/// Orchestrates a complete OHTTP request-response round trip.
///
/// Owns a [KeyConfigCache] and an [OhttpTransport] and wires together
/// the full pipeline: cache lookup, BHTTP serialization, OHTTP
/// encapsulation, transport call, decapsulation, and BHTTP parsing.
///
/// When the transport throws [OhttpGatewayException] the cached
/// [OhttpKeyConfig] is invalidated before the exception is re-thrown.
/// Other exceptions (network errors, decapsulation failures) are
/// propagated without invalidating the cache.
class OhttpSession {
  final OhttpTransport _transport;
  final KeyConfigCache _cache;

  /// The [cache] must be backed by the same [transport] instance so that
  /// cache invalidation and gateway requests target the same gateway.
  OhttpSession({
    required OhttpTransport transport,
    required KeyConfigCache cache,
  }) : _transport = transport,
       _cache = cache;

  /// Shortcut that creates a [KeyConfigCache] over [transport] with the
  /// default TTL.
  OhttpSession.withTransport({required OhttpTransport transport})
    : _transport = transport,
      _cache = KeyConfigCache(transport: transport);

  /// Executes a full OHTTP round trip for [request].
  Future<OhttpResponseData> send(OhttpRequestData request) async {
    final config = await _cache.get();

    final binaryRequest = bhttp.serializeRequest(
      method: request.method,
      scheme: request.scheme,
      authority: request.authority,
      path: request.path,
      headers: request.headers,
      body: request.body,
    );

    final encapsulated = await ohttpEncapsulate(config, binaryRequest);

    final Uint8List encResponse;
    try {
      encResponse = await _transport.postToGateway(encapsulated.encRequest);
    } on OhttpGatewayException {
      _cache.invalidate();
      rethrow;
    }

    final binaryResponse = await ohttpDecapsulate(
      encapsulated.enc,
      encapsulated.exportedSecret,
      encResponse,
    );

    final parsed = bhttp.parseResponse(binaryResponse);

    return OhttpResponseData(
      statusCode: parsed.statusCode,
      headers: parsed.headers,
      body: parsed.body,
    );
  }
}
