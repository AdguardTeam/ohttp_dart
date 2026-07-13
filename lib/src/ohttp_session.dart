import 'dart:typed_data';

import 'bhttp.dart' as bhttp;
import 'bhttp_response_limits.dart';
import 'exceptions.dart';
import 'key_config_cache.dart';
import 'ohttp.dart';
import 'ohttp_constants.dart';
import 'ohttp_data.dart';
import 'ohttp_observer.dart';
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
/// When [retryOnGatewayError] is `true` (the default), a single automatic
/// retry is performed after an [OhttpGatewayException]: the cache is
/// invalidated, a fresh config is fetched, and the request is re-sent once.
/// If the retry also fails, the exception is propagated.
///
/// [maxEncryptedResponseBytes] limits the maximum size of raw encrypted
/// responses accepted from the gateway. Defaults to 16 MiB (higher than
/// the max decrypted body size to account for OHTTP and BHTTP overhead).
/// Throws [OhttpSizeLimitException] if the response exceeds this limit.
///
/// [decryptedResponseLimits] control size validation for BHTTP response
/// message components (headers, body) after decryption.
///
/// [observer] receives lifecycle event notifications.
///
class OhttpSession {
  static int _validateMaxEncryptedResponseBytes(int value) {
    if (value <= 0) {
      throw OhttpConfigException(
        'maxEncryptedResponseBytes must be positive, got $value',
        stackTrace: StackTrace.current,
      );
    }

    return value;
  }

  static BhttpResponseLimits _validateDecryptedResponseLimits(BhttpResponseLimits limits) {
    if (limits.maxHeaderBytes <= 0) {
      throw OhttpConfigException(
        'decryptedResponseLimits.maxHeaderBytes must be positive, got ${limits.maxHeaderBytes}',
        stackTrace: StackTrace.current,
      );
    }
    if (limits.maxBodyBytes <= 0) {
      throw OhttpConfigException(
        'decryptedResponseLimits.maxBodyBytes must be positive, got ${limits.maxBodyBytes}',
        stackTrace: StackTrace.current,
      );
    }

    return limits;
  }

  final OhttpTransport _transport;
  final KeyConfigCache _cache;
  final int _maxEncryptedResponseBytes;
  final BhttpResponseLimits _decryptedResponseLimits;
  final OhttpObserver? _observer;
  final bool _retryOnGatewayError;

  /// The [cache] must be backed by the same [transport] instance so that
  /// cache invalidation and gateway requests target the same gateway.
  OhttpSession({
    required OhttpTransport transport,
    required KeyConfigCache cache,
    OhttpObserver? observer,
    bool retryOnGatewayError = true,
    int maxEncryptedResponseBytes = OhttpConstants.defaultMaxEncryptedResponseBytes,
    BhttpResponseLimits decryptedResponseLimits = const BhttpResponseLimits(),
  }) : _transport = transport,
       _cache = cache,
       _maxEncryptedResponseBytes = _validateMaxEncryptedResponseBytes(maxEncryptedResponseBytes),
       _decryptedResponseLimits = _validateDecryptedResponseLimits(decryptedResponseLimits),
       _observer = observer,
       _retryOnGatewayError = retryOnGatewayError;

  /// Shortcut that creates a [KeyConfigCache] over [transport] with the
  /// default TTL.
  OhttpSession.withTransport({
    required OhttpTransport transport,
    OhttpObserver? observer,
    bool retryOnGatewayError = true,
    int maxEncryptedResponseBytes = OhttpConstants.defaultMaxEncryptedResponseBytes,
    BhttpResponseLimits decryptedResponseLimits = const BhttpResponseLimits(),
  }) : _transport = transport,
       _cache = KeyConfigCache(transport: transport, observer: observer),
       _maxEncryptedResponseBytes = _validateMaxEncryptedResponseBytes(maxEncryptedResponseBytes),
       _decryptedResponseLimits = _validateDecryptedResponseLimits(decryptedResponseLimits),
       _observer = observer,
       _retryOnGatewayError = retryOnGatewayError;

  /// Executes a full OHTTP round trip for [request].
  ///
  /// When [retryOnGatewayError] is `true`, a [OhttpGatewayException] triggers
  /// a single retry with a freshly fetched key config.
  Future<OhttpResponseData> send(OhttpRequestData request) async {
    final binaryRequest = bhttp.serializeRequest(
      method: request.method,
      scheme: request.scheme,
      authority: request.authority,
      path: request.path,
      headers: request.headers,
      body: request.body,
    );

    final stopwatch = Stopwatch()..start();

    OhttpResponseData result;
    try {
      result = await _encapsulateAndSend(binaryRequest);
    } on OhttpGatewayException {
      if (!_retryOnGatewayError) {
        rethrow;
      }
      _observer?.notifySafe((o) => o.onGatewayRetry());
      result = await _encapsulateAndSend(binaryRequest);
    }

    stopwatch.stop();
    _observer?.notifySafe((o) => o.onRoundTripCompleted(stopwatch.elapsed));

    return result;
  }

  /// Encapsulates, posts, decapsulates, and parses one round-trip;
  /// on gateway error invalidates cache and rethrows.
  Future<OhttpResponseData> _encapsulateAndSend(Uint8List binaryRequest) async {
    final config = await _cache.get();

    OhttpEncapsulateResult encapsulated;
    try {
      encapsulated = await ohttpEncapsulate(config, binaryRequest);
    } on OhttpException catch (e) {
      _observer?.notifySafe((o) => o.onEncapsulationError(e.runtimeType));
      rethrow;
    }

    try {
      final Uint8List encResponse;
      try {
        _observer?.notifySafe((o) => o.onPostToGateway());
        encResponse = await _transport.postToGateway(encapsulated.encRequest);
      } on OhttpGatewayException catch (e) {
        _observer?.notifySafe((o) => o.onGatewayError(e.statusCode));
        _cache.invalidate();
        rethrow;
      }

      if (encResponse.length > _maxEncryptedResponseBytes) {
        throw OhttpSizeLimitException(
          'Gateway response size exceeds limit',
          limit: _maxEncryptedResponseBytes,
          actualSize: encResponse.length,
        );
      }

      final Uint8List binaryResponse;
      try {
        binaryResponse = await ohttpDecapsulate(
          encapsulated.enc.bytes,
          encapsulated.exportedSecret.bytes,
          encResponse,
        );
      } on OhttpException catch (e) {
        _observer?.notifySafe((o) => o.onDecapsulationError(e.runtimeType));
        rethrow;
      }

      final parsed = bhttp.parseResponse(
        binaryResponse,
        limits: _decryptedResponseLimits,
      );

      return OhttpResponseData(
        statusCode: parsed.statusCode,
        headers: parsed.headers,
        body: parsed.body,
      );
    } finally {
      encapsulated.dispose();
    }
  }
}
