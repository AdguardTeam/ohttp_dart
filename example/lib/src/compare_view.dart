import 'package:flutter/material.dart';

import 'privacy_facts.dart';

/// Side-by-side table of what the target server saw for the OHTTP request
/// vs the direct one. Leaked values render red; hidden ones green.
class CompareView extends StatelessWidget {
  final PrivacyFacts? ohttp;
  final PrivacyFacts? direct;

  const CompareView({super.key, required this.ohttp, required this.direct});

  @override
  Widget build(BuildContext context) {
    final ohttp = this.ohttp;
    final direct = this.direct;
    if (ohttp == null || direct == null) {
      return const Center(
        child: Padding(
          padding: EdgeInsets.all(16),
          child: Text(
            'Comparison unavailable — send both requests to an echo '
            'endpoint like /get or /anything',
            textAlign: TextAlign.center,
          ),
        ),
      );
    }

    return SingleChildScrollView(
      padding: const EdgeInsets.all(8),
      child: Table(
        border: TableBorder.all(color: Colors.grey.shade300),
        columnWidths: const {
          0: FlexColumnWidth(1.2),
          1: FlexColumnWidth(1),
          2: FlexColumnWidth(1),
        },
        defaultVerticalAlignment: TableCellVerticalAlignment.middle,
        children: [
          TableRow(
            decoration: BoxDecoration(color: Colors.grey.shade100),
            children: const [
              _HeaderCell('What the server saw'),
              _HeaderCell('Via OHTTP'),
              _HeaderCell('Direct'),
            ],
          ),
          TableRow(
            children: [
              const _HeaderCell('IP address'),
              _FactCell(ohttp.ip),
              _FactCell(direct.ip),
            ],
          ),
          TableRow(
            children: [
              const _HeaderCell('Country'),
              _FactCell(ohttp.country),
              _FactCell(direct.country),
            ],
          ),
          TableRow(
            children: [
              const _HeaderCell('User-Agent'),
              _FactCell(ohttp.userAgent),
              _FactCell(direct.userAgent),
            ],
          ),
          TableRow(
            children: [
              const _HeaderCell('TLS/geo fingerprint'),
              _FactCell(ohttp.fingerprintPresent ? 'present' : null),
              _FactCell(direct.fingerprintPresent ? 'present' : null),
            ],
          ),
          TableRow(
            children: [
              const _HeaderCell('Headers received'),
              _NeutralCell('${ohttp.headerCount}'),
              _NeutralCell('${direct.headerCount}'),
            ],
          ),
        ],
      ),
    );
  }
}

class _HeaderCell extends StatelessWidget {
  final String text;

  const _HeaderCell(this.text);

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.all(8),
    child: Text(
      text,
      style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 12),
    ),
  );
}

class _NeutralCell extends StatelessWidget {
  final String text;

  const _NeutralCell(this.text);

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.all(8),
    child: Text(text, style: const TextStyle(fontSize: 12)),
  );
}

/// Red text when the server saw the value; green shield + "hidden" when not.
class _FactCell extends StatelessWidget {
  final String? value;

  const _FactCell(this.value);

  @override
  Widget build(BuildContext context) {
    final value = this.value;
    if (value == null) {
      return Padding(
        padding: const EdgeInsets.all(8),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.shield, size: 14, color: Colors.green.shade700),
            const SizedBox(width: 4),
            Text(
              'hidden',
              style: TextStyle(fontSize: 12, color: Colors.green.shade700),
            ),
          ],
        ),
      );
    }

    return Padding(
      padding: const EdgeInsets.all(8),
      child: Text(
        value,
        style: TextStyle(fontSize: 12, color: Colors.red.shade700),
      ),
    );
  }
}
