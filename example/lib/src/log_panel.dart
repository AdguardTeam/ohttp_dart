import 'package:flutter/material.dart';

import 'log_entry.dart';

/// Scrolling, color-coded list of [LogEntry] lines with a clear action.
///
/// Auto-scrolls to the newest entry whenever the entry count changes.
class LogPanel extends StatefulWidget {
  final List<LogEntry> entries;
  final VoidCallback onClear;

  const LogPanel({super.key, required this.entries, required this.onClear});

  @override
  State<LogPanel> createState() => _LogPanelState();
}

class _LogPanelState extends State<LogPanel> {
  final _scrollController = ScrollController();
  int _lastCount = 0;

  @override
  void initState() {
    super.initState();
    _lastCount = widget.entries.length;
    _scrollToEnd();
  }

  @override
  void didUpdateWidget(LogPanel oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.entries.length != _lastCount) {
      _lastCount = widget.entries.length;
      _scrollToEnd();
    }
  }

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }

  void _scrollToEnd() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scrollController.hasClients) {
        _scrollController.jumpTo(_scrollController.position.maxScrollExtent);
      }
    });
  }

  Color _levelColor(LogLevel level) => switch (level) {
    LogLevel.error => Colors.red.shade700,
    LogLevel.warning => Colors.orange.shade800,
    LogLevel.success => Colors.green.shade700,
    LogLevel.info => Colors.blueGrey.shade700,
  };

  String _timestamp(DateTime time) =>
      '${time.hour.toString().padLeft(2, '0')}:'
      '${time.minute.toString().padLeft(2, '0')}:'
      '${time.second.toString().padLeft(2, '0')}';

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          children: [
            const Text('Log:', style: TextStyle(fontWeight: FontWeight.bold)),
            const Spacer(),
            IconButton(
              icon: const Icon(Icons.clear_all, size: 18),
              tooltip: 'Clear log',
              onPressed: widget.onClear,
            ),
          ],
        ),
        Container(
          height: 120,
          padding: const EdgeInsets.all(8),
          decoration: BoxDecoration(
            color: Colors.grey[100],
            borderRadius: BorderRadius.circular(4),
          ),
          child: ListView(
            controller: _scrollController,
            children: [
              for (final entry in widget.entries)
                Text(
                  '[${_timestamp(entry.time)}] '
                  '[${entry.source}] ${entry.message}',
                  style: TextStyle(
                    fontSize: 11,
                    fontFamily: 'monospace',
                    color: _levelColor(entry.level),
                  ),
                ),
            ],
          ),
        ),
      ],
    );
  }
}
