/// Observer for OHTTP request lifecycle events.
abstract class OhttpObserver {
  /// Called when a [KeyConfig] was successfully fetched from the gateway.
  void onKeyConfigFetched() {}

  /// Called when a cached [KeyConfig] was reused (no network request).
  void onKeyConfigCacheHit() {}

  /// Called right before posting the encapsulated request to the gateway.
  void onPostToGateway() {}

  /// Called when response decapsulation fails with [OhttpDecapsulationException].
  /// [error] is the exception that caused the failure.
  void onDecapsulationError([Object? error]) {}

  /// Called when the gateway returns an error response (non-2xx status).
  /// The cache is invalidated automatically after this event.
  /// [error] is the [OhttpGatewayException] that was thrown.
  void onGatewayError([Object? error]) {}

  /// Called when the cached [KeyConfig] is invalidated due to a gateway error.
  /// This event is always fired immediately after [onGatewayError].
  void onCacheInvalidated() {}

  /// Called when request encapsulation fails (before posting to the gateway).
  /// [error] is the exception that caused the failure.
  void onEncapsulationError([Object? error]) {}

  /// Calls [callback] with this observer and suppresses any errors.
  void notifySafe(void Function(OhttpObserver) callback) {
    try {
      callback(this);
    } catch (_) {
      // Observer errors must not affect the OHTTP pipeline.
    }
  }
}
