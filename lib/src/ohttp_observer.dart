import 'dart:developer' as developer;

/// Observer for OHTTP request lifecycle events.
abstract class OhttpObserver {
  /// Called when a [KeyConfig] was successfully fetched from the gateway.
  void onKeyConfigFetched() {}

  /// Called when a cached [KeyConfig] was reused (no network request).
  void onKeyConfigCacheHit() {}

  /// Called right before posting the encapsulated request to the gateway.
  void onPostToGateway() {}

  /// Called when response decapsulation fails.
  /// [errorType] is the runtime type of the exception (e.g. [OhttpDecapsulationException]).
  void onDecapsulationError(Type errorType) {}

  /// Called when the gateway returns an error response (non-2xx status).
  /// The cache is invalidated automatically after this event.
  /// [statusCode] is the HTTP status code returned by the gateway.
  void onGatewayError(int statusCode) {}

  /// Called when the cached [KeyConfig] is invalidated due to a gateway error.
  /// This event is always fired immediately after [onGatewayError].
  void onCacheInvalidated() {}

  /// Called when request encapsulation fails (before posting to the gateway).
  /// [errorType] is the runtime type of the exception (e.g. [OhttpUnsupportedSuiteException]).
  void onEncapsulationError(Type errorType) {}

  /// Calls [callback] with this observer and suppresses any errors.
  void notifySafe(void Function(OhttpObserver) callback) {
    try {
      callback(this);
    } catch (e, st) {
      // Observer errors must not affect the OHTTP pipeline.
      developer.log(
        'Observer callback error suppressed',
        error: e,
        stackTrace: st,
      );
    }
  }
}
