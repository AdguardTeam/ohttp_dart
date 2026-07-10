import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:ohttp_dart/ohttp_dart.dart';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:ohttp_flutter_example/src/gateways.dart';
import 'package:ohttp_flutter_example/src/log_observer.dart';
import 'package:integration_test/integration_test.dart';

/// Integration tests for OHTTP end-to-end with PIR Gateway.
///
/// These tests verify:
/// 1. Fetching KeyConfig from pir-gateway.adtidy.org
/// 2. OHTTP encapsulate → send → decapsulate round-trip
/// 3. Response integrity
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('PIR Gateway: fetch KeyConfig successfully', (
    WidgetTester tester,
  ) async {
    final rawClient = http.Client();
    final transport = pirGatewayTransport(rawClient);
    final logs = <String>[];
    final observer = LogObserver(logs);
    final session = OhttpSession.withTransport(
      transport: transport,
      observer: observer,
    );

    try {
      // Send a simple GET request via OHTTP to PIR Gateway root
      final response = await session.send(
        OhttpRequestData(
          method: 'GET',
          scheme: 'https',
          authority: pirGatewayAuthority,
          path: '/',
        ),
      );

      debugPrint('PIR Gateway response status: ${response.statusCode}');
      debugPrint('PIR Gateway logs: $logs');
      debugPrint(
        'PIR Gateway response body (first 200): '
        '${utf8.decode(response.body.take(200).toList(), allowMalformed: true)}',
      );

      // The KeyConfig was fetched and OHTTP round-trip completed
      expect(
        logs.any((l) => l.contains('KeyConfig received')),
        isTrue,
        reason: 'Should successfully fetch KeyConfig from PIR Gateway',
      );

      // Any valid HTTP status means the round-trip worked
      expect(response.statusCode, greaterThanOrEqualTo(200));
      expect(response.statusCode, lessThan(500));
    } finally {
      rawClient.close();
    }
  });

  testWidgets('PIR Gateway: OHTTP encapsulate/decapsulate round-trip', (
    WidgetTester tester,
  ) async {
    final rawClient = http.Client();
    final transport = pirGatewayTransport(rawClient);
    final logs = <String>[];
    final observer = LogObserver(logs);
    final session = OhttpSession.withTransport(
      transport: transport,
      observer: observer,
    );

    try {
      final response = await session.send(
        OhttpRequestData(
          method: 'GET',
          scheme: 'https',
          authority: pirGatewayAuthority,
          path: '/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB',
          headers: [('accept', 'application/dns-message')],
        ),
      );

      debugPrint('PIR DNS status: ${response.statusCode}');
      debugPrint('PIR DNS logs: $logs');

      // Verify OHTTP request was posted to gateway
      expect(logs.any((l) => l.contains('Sending to OHTTP gateway')), isTrue);

      // Server responded (even 4xx means crypto worked end-to-end)
      expect(response.statusCode, greaterThanOrEqualTo(200));
      expect(response.statusCode, lessThan(500));
    } finally {
      rawClient.close();
    }
  });
}
