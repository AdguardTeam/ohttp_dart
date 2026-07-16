import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:ohttp_dart/ohttp_dart.dart';

import 'json_highlighter.dart';

/// Renders one response: colored status chip, timing/size meta line,
/// collapsible headers, and a syntax-highlighted body with a copy action.
class ResponseView extends StatelessWidget {
  final OhttpResponseData? response;
  final Duration? elapsed;

  const ResponseView({
    super.key,
    required this.response,
    required this.elapsed,
  });

  Color _statusColor(int statusCode) => switch (statusCode ~/ 100) {
    2 => Colors.green.shade700,
    3 => Colors.blue.shade700,
    4 => Colors.orange.shade800,
    5 => Colors.red.shade700,
    _ => Colors.grey.shade700,
  };

  String _formatBytes(int bytes) =>
      bytes < 1024 ? '$bytes B' : '${(bytes / 1024).toStringAsFixed(1)} KB';

  @override
  Widget build(BuildContext context) {
    final response = this.response;
    if (response == null) {
      return const Center(child: Text('No response yet'));
    }

    final bodyStr = utf8.decode(response.body, allowMalformed: true);
    final colors = JsonHighlightColors.of(Theme.of(context).brightness);
    final bodySpan = highlightJson(bodyStr, colors);

    return SingleChildScrollView(
      padding: const EdgeInsets.all(8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.symmetric(
                  horizontal: 10,
                  vertical: 4,
                ),
                decoration: BoxDecoration(
                  color: _statusColor(response.statusCode),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Text(
                  'HTTP ${response.statusCode}',
                  style: const TextStyle(
                    color: Colors.white,
                    fontWeight: FontWeight.bold,
                    fontSize: 12,
                  ),
                ),
              ),
              const SizedBox(width: 12),
              Text(
                [
                  if (elapsed != null) '${elapsed!.inMilliseconds} ms',
                  _formatBytes(response.body.length),
                ].join(' · '),
                style: TextStyle(fontSize: 12, color: Colors.grey.shade700),
              ),
            ],
          ),
          const SizedBox(height: 4),
          ExpansionTile(
            tilePadding: EdgeInsets.zero,
            title: Text(
              'Headers (${response.headers.length})',
              style: const TextStyle(fontSize: 13, fontWeight: FontWeight.bold),
            ),
            children: [
              for (final header in response.headers)
                Align(
                  alignment: Alignment.centerLeft,
                  child: Text(
                    '${header.$1}: ${header.$2}',
                    style: const TextStyle(
                      fontSize: 12,
                      fontFamily: 'monospace',
                    ),
                  ),
                ),
            ],
          ),
          Row(
            children: [
              const Text(
                'Body:',
                style: TextStyle(fontWeight: FontWeight.bold),
              ),
              const Spacer(),
              IconButton(
                icon: const Icon(Icons.copy, size: 16),
                tooltip: 'Copy body',
                onPressed: () async {
                  await Clipboard.setData(
                    ClipboardData(text: bodySpan.toPlainText()),
                  );
                  if (context.mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(
                        content: Text('Body copied'),
                        duration: Duration(seconds: 1),
                      ),
                    );
                  }
                },
              ),
            ],
          ),
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: Colors.grey[50],
              borderRadius: BorderRadius.circular(4),
              border: Border.all(color: Colors.grey[300]!),
            ),
            child: SelectableText.rich(
              TextSpan(
                style: TextStyle(
                  fontSize: 12,
                  fontFamily: 'monospace',
                  color: Colors.grey.shade900,
                ),
                children: [bodySpan],
              ),
            ),
          ),
        ],
      ),
    );
  }
}
