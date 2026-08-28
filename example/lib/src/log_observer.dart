import 'package:ohttp_dart/ohttp_dart.dart';

import 'log_entry.dart';

/// An [OhttpObserver] that reports human-readable lifecycle events.
///
/// Maps all nine [OhttpObserver] callbacks to a [LogLevel] and message and
/// forwards them to [onEvent]; the page turns them into log entries.
class LogObserver extends OhttpObserver {
  final void Function(LogLevel level, String message) onEvent;

  LogObserver(this.onEvent);

  @override
  void onKeyConfigFetched() => onEvent(LogLevel.info, 'KeyConfig received');

  @override
  void onKeyConfigCacheHit() =>
      onEvent(LogLevel.info, 'Using cached KeyConfig');

  @override
  void onPostToRelay() => onEvent(LogLevel.info, 'Sending to OHTTP relay');

  @override
  void onDecapsulationError(Type errorType) =>
      onEvent(LogLevel.error, 'Decapsulation error: $errorType');

  @override
  void onRelayError(int statusCode) =>
      onEvent(LogLevel.error, 'Relay error: HTTP $statusCode');

  @override
  void onCacheInvalidated() =>
      onEvent(LogLevel.warning, 'KeyConfig cache invalidated');

  @override
  void onEncapsulationError(Type errorType) =>
      onEvent(LogLevel.error, 'Encapsulation error: $errorType');

  @override
  void onRelayRetry() =>
      onEvent(LogLevel.warning, 'Retrying after relay error');

  @override
  void onRoundTripCompleted(Duration elapsed) =>
      onEvent(LogLevel.success, 'Round trip completed in $elapsed');
}
