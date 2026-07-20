/// Severity of a [LogEntry], mapped to a color in the log panel.
enum LogLevel { info, success, warning, error }

/// One line in the demo's log panel.
class LogEntry {
  final DateTime time;
  final LogLevel level;

  /// Origin tag rendered in brackets: 'OHTTP' or 'direct'.
  final String source;
  final String message;

  LogEntry({
    required this.time,
    required this.level,
    required this.source,
    required this.message,
  });
}
