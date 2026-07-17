import 'dart:developer' as developer;

/// Observer for OHTTP request lifecycle events.
abstract class OhttpObserver {
  /// Called when an [OhttpKeyConfig] was successfully fetched from the gateway.
  void onKeyConfigFetched() {}

  /// Called when a cached [OhttpKeyConfig] was reused (no network request).
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

  /// Called when the cached [OhttpKeyConfig] is invalidated due to a gateway error.
  /// This event is always fired immediately after [onGatewayError].
  void onCacheInvalidated() {}

  /// Called when request encapsulation fails (before posting to the gateway).
  /// [errorType] is the runtime type of the exception (e.g. [OhttpUnsupportedSuiteException]).
  void onEncapsulationError(Type errorType) {}

  /// Called when a gateway error triggers an automatic retry with a refreshed
  /// key config. Fired after [onGatewayError] and [onCacheInvalidated], before the second attempt.
  void onGatewayRetry() {}

  /// Called after a successful round trip, just before the response is returned.
  ///
  /// [elapsed] covers the full [OhttpSession.send] call: BHTTP serialisation,
  /// encapsulation, gateway POST (plus retry if it happened), decapsulation,
  /// and BHTTP parsing. Not fired when [OhttpSession.send] throws.
  void onRoundTripCompleted(Duration elapsed) {}

  /// Called when an in-flight request is aborted client-side
  /// (the transport threw [OhttpRequestAbortedException]).
  ///
  /// [stage] identifies which transport operation was in flight. Fired just
  /// before the exception propagates to the caller; no retry or cache
  /// invalidation follows.
  void onRequestAborted(OhttpRequestStage stage) {}

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

/// Pipeline stage at which a transport operation was in flight.
enum OhttpRequestStage {
  /// The key-config fetch ([OhttpTransport.fetchKeyConfig]) was in flight.
  keyConfigFetch,

  /// The encapsulated POST ([OhttpTransport.postToGateway]) was in flight.
  gatewayPost,
}
