import 'package:ohttp_dart/ohttp_dart.dart';

/// An [OhttpObserver] that appends human-readable lifecycle events to a log.
///
/// Overrides all nine [OhttpObserver] callbacks, appending one line per
/// pipeline event to the shared [log] list for display in the UI.
class LogObserver extends OhttpObserver {
  final List<String> log;

  LogObserver(this.log);

  @override
  void onKeyConfigFetched() {
    log.add('KeyConfig received');
  }

  @override
  void onKeyConfigCacheHit() {
    log.add('Using cached KeyConfig');
  }

  @override
  void onPostToGateway() {
    log.add('Sending to OHTTP gateway');
  }

  @override
  void onDecapsulationError(Type errorType) {
    log.add('Decapsulation error: $errorType');
  }

  @override
  void onGatewayError(int statusCode) {
    log.add('Gateway error: HTTP $statusCode');
  }

  @override
  void onCacheInvalidated() {
    log.add('KeyConfig cache invalidated');
  }

  @override
  void onEncapsulationError(Type errorType) {
    log.add('Encapsulation error: $errorType');
  }

  @override
  void onGatewayRetry() {
    log.add('Retrying after gateway error');
  }

  @override
  void onRoundTripCompleted(Duration elapsed) {
    log.add('Round trip completed in $elapsed');
  }
}
