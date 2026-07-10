import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:ohttp_dart/ohttp_dart.dart';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:ohttp_flutter_example/main.dart';
import 'package:ohttp_flutter_example/src/gateways.dart';
import 'package:ohttp_flutter_example/src/log_observer.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('App launches and shows OHTTP demo UI', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(const OhttpApp());
    await tester.pumpAndSettle();

    expect(find.text('OHTTP Flutter Demo'), findsOneWidget);
    expect(find.text('Send via OHTTP'), findsOneWidget);
    expect(find.text('Send Direct'), findsOneWidget);
    expect(find.text('OHTTP Response'), findsOneWidget);
    expect(find.text('Direct Response'), findsOneWidget);
  });

  testWidgets('GET /get via OHTTP returns valid JSON', (
    WidgetTester tester,
  ) async {
    final rawClient = http.Client();
    final transport = httpbinTransport(rawClient);
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
          authority: httpbinAuthority,
          path: '/get',
          headers: [('accept', 'application/json')],
        ),
      );

      debugPrint('OHTTP GET /get logs: $logs');
      debugPrint('OHTTP GET /get status: ${response.statusCode}');
      debugPrint(
        'OHTTP GET /get body: ${utf8.decode(response.body, allowMalformed: true)}',
      );

      expect(response.statusCode, 200);

      final body = jsonDecode(utf8.decode(response.body, allowMalformed: true));
      expect(body, isA<Map>());
      expect(body['url'], contains('/get'));
    } finally {
      rawClient.close();
    }
  });

  testWidgets('GET /get via Direct returns valid JSON', (
    WidgetTester tester,
  ) async {
    final rawClient = http.Client();

    try {
      final response = await rawClient.get(
        Uri.https(httpbinAuthority, '/get'),
        headers: {'Accept': 'application/json'},
      );

      debugPrint('Direct GET /get status: ${response.statusCode}');

      expect(response.statusCode, 200);

      final body = jsonDecode(
        utf8.decode(response.bodyBytes, allowMalformed: true),
      );
      expect(body, isA<Map>());
      expect(body['url'], contains('/get'));
    } finally {
      rawClient.close();
    }
  });

  testWidgets('POST /post via OHTTP sends body', (WidgetTester tester) async {
    final rawClient = http.Client();
    final transport = httpbinTransport(rawClient);
    final logs = <String>[];
    final observer = LogObserver(logs);
    final session = OhttpSession.withTransport(
      transport: transport,
      observer: observer,
    );

    try {
      final requestBody = Uint8List.fromList(utf8.encode('{"test": "ohttp"}'));
      final response = await session.send(
        OhttpRequestData(
          method: 'POST',
          scheme: 'https',
          authority: httpbinAuthority,
          path: '/post',
          headers: [
            ('accept', 'application/json'),
            ('content-type', 'application/json'),
          ],
          body: requestBody,
        ),
      );

      debugPrint('OHTTP POST /post logs: $logs');
      debugPrint('OHTTP POST /post status: ${response.statusCode}');
      debugPrint(
        'OHTTP POST /post body: ${utf8.decode(response.body, allowMalformed: true)}',
      );

      expect(response.statusCode, 200);

      final body = jsonDecode(utf8.decode(response.body, allowMalformed: true));
      expect(body, isA<Map>());
      // httpbin echoes back the posted data in 'body' or 'data' field
      final echoedBody = body['body'] ?? body['data'] ?? '';
      expect(echoedBody, contains('ohttp'));
    } finally {
      rawClient.close();
    }
  });

  testWidgets('GET /get via OHTTP forwards custom headers', (
    WidgetTester tester,
  ) async {
    final rawClient = http.Client();
    final transport = httpbinTransport(rawClient);
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
          authority: httpbinAuthority,
          path: '/get',
          headers: [
            ('accept', 'application/json'),
            ('x-custom-test', 'ohttp-value'),
          ],
        ),
      );

      debugPrint('OHTTP GET /get (headers) logs: $logs');
      debugPrint('OHTTP GET /get (headers) status: ${response.statusCode}');
      debugPrint(
        'OHTTP GET /get (headers) body: ${utf8.decode(response.body, allowMalformed: true)}',
      );

      expect(response.statusCode, 200);

      final body = jsonDecode(utf8.decode(response.body, allowMalformed: true));
      expect(body, isA<Map>());
      // httpbin /get returns headers as a list of [name, value] arrays
      final headers = body['headers'] as List<dynamic>;
      final customHeader = headers.firstWhere(
        (h) => (h[0] as String).toLowerCase() == 'x-custom-test',
        orElse: () => null,
      );
      expect(
        customHeader,
        isNotNull,
        reason: 'X-Custom-Test header should be forwarded via OHTTP',
      );
      expect(customHeader[1], 'ohttp-value');
    } finally {
      rawClient.close();
    }
  });

  testWidgets('OHTTP vs Direct comparison: same data returned', (
    WidgetTester tester,
  ) async {
    final rawClient = http.Client();
    final transport = httpbinTransport(rawClient);
    final session = OhttpSession.withTransport(transport: transport);

    try {
      final ohttpResponse = await session.send(
        OhttpRequestData(
          method: 'GET',
          scheme: 'https',
          authority: httpbinAuthority,
          path: '/get',
          headers: [('accept', 'application/json')],
        ),
      );

      final directResponse = await rawClient.get(
        Uri.https(httpbinAuthority, '/get'),
        headers: {'Accept': 'application/json'},
      );

      expect(ohttpResponse.statusCode, directResponse.statusCode);

      // Both should return valid JSON with "url" field
      final ohttpBody = jsonDecode(
        utf8.decode(ohttpResponse.body, allowMalformed: true),
      );
      final directBody = jsonDecode(
        utf8.decode(directResponse.bodyBytes, allowMalformed: true),
      );

      expect(ohttpBody['url'], directBody['url']);
    } finally {
      rawClient.close();
    }
  });
}
