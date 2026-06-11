import 'dart:typed_data';

import 'bhttp.dart' as bhttp;
import 'bhttp_response_limits.dart';
import 'exceptions.dart';
import 'key_config_cache.dart';
import 'ohttp.dart';
import 'ohttp_data.dart';
import 'ohttp_transport.dart';

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
///
/// [maxEncryptedResponseBytes] limits the maximum size of raw encrypted
/// responses accepted from the gateway. Defaults to 16 MiB (higher than
/// the max decrypted body size to account for OHTTP and BHTTP overhead).
/// Throws [OhttpSizeLimitException] if the response exceeds this limit.
///
/// [decryptedResponseLimits] control size validation for BHTTP response
/// message components (headers, body) after decryption.
///
class OhttpSession {
  /// Default limit for raw encrypted response from the gateway.
  /// Set to 16 MiB — max BHTTP body (10 MiB) plus OHTTP/BHTTP overhead
  /// (nonce, AEAD tag, framing, headers).
  static const _defaultMaxEncryptedResponseBytes = 16 * 1024 * 1024; // 16 MiB

  static int _validateMaxEncryptedResponseBytes(int value) {
    if (value <= 0) {
      throw OhttpConfigException(
        'maxEncryptedResponseBytes must be positive, got $value',
      );
    }

    return value;
  }

  static BhttpResponseLimits _validateDecryptedResponseLimits(BhttpResponseLimits limits) {
    if (limits.maxHeaderBytes <= 0) {
      throw OhttpConfigException(
        'decryptedResponseLimits.maxHeaderBytes must be positive, got ${limits.maxHeaderBytes}',
      );
    }
    if (limits.maxBodyBytes <= 0) {
      throw OhttpConfigException(
        'decryptedResponseLimits.maxBodyBytes must be positive, got ${limits.maxBodyBytes}',
      );
    }

    return limits;
  }

  final OhttpTransport _transport;
  final KeyConfigCache _cache;
  final int _maxEncryptedResponseBytes;
  final BhttpResponseLimits _decryptedResponseLimits;

  /// The [cache] must be backed by the same [transport] instance so that
  /// cache invalidation and gateway requests target the same gateway.
  OhttpSession({
    required OhttpTransport transport,
    required KeyConfigCache cache,
    int maxEncryptedResponseBytes = _defaultMaxEncryptedResponseBytes,
    BhttpResponseLimits decryptedResponseLimits = const BhttpResponseLimits(),
  }) : _transport = transport,
       _cache = cache,
       _maxEncryptedResponseBytes = _validateMaxEncryptedResponseBytes(maxEncryptedResponseBytes),
       _decryptedResponseLimits = _validateDecryptedResponseLimits(decryptedResponseLimits);

  /// Shortcut that creates a [KeyConfigCache] over [transport] with the
  /// default TTL.
  OhttpSession.withTransport({
    required OhttpTransport transport,
    int maxEncryptedResponseBytes = _defaultMaxEncryptedResponseBytes,
    BhttpResponseLimits decryptedResponseLimits = const BhttpResponseLimits(),
  }) : _transport = transport,
       _cache = KeyConfigCache(transport: transport),
       _maxEncryptedResponseBytes = _validateMaxEncryptedResponseBytes(maxEncryptedResponseBytes),
       _decryptedResponseLimits = _validateDecryptedResponseLimits(decryptedResponseLimits);

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

    if (encResponse.length > _maxEncryptedResponseBytes) {
      throw OhttpSizeLimitException(
        message: 'Gateway response size exceeds limit',
        limit: _maxEncryptedResponseBytes,
        actualSize: encResponse.length,
      );
    }

    final binaryResponse = await ohttpDecapsulate(
      encapsulated.enc,
      encapsulated.exportedSecret,
      encResponse,
    );

    final parsed = bhttp.parseResponse(
      binaryResponse,
      limits: _decryptedResponseLimits,
    );

    return OhttpResponseData(
      statusCode: parsed.statusCode,
      headers: parsed.headers,
      body: parsed.body,
    );
  }
}
