import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:ohttp_flutter_example/main.dart';

/// Fake client whose requests hang until the test completes [completer].
class _FakeHttpClient extends http.BaseClient {
  _FakeHttpClient(this.completer);

  final Completer<http.StreamedResponse> completer;
  int requestCount = 0;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    requestCount++;
    return completer.future;
  }
}

void main() {
  testWidgets('OHTTP demo page renders correctly', (WidgetTester tester) async {
    await tester.pumpWidget(const OhttpApp());
    await tester.pumpAndSettle();

    // App bar title
    expect(find.text('OHTTP Flutter Demo'), findsOneWidget);

    // Method selector defaults to GET
    expect(find.text('GET'), findsOneWidget);

    // Path input
    expect(find.byType(TextField), findsOneWidget);

    // Buttons
    expect(find.text('Send via OHTTP'), findsOneWidget);
    expect(find.text('Send Direct'), findsOneWidget);

    // Tabs
    expect(find.text('OHTTP Response'), findsOneWidget);
    expect(find.text('Direct Response'), findsOneWidget);

    // Default state
    expect(find.text('No response yet'), findsOneWidget);
  });

  testWidgets('short window scrolls vertically instead of clipping', (
    WidgetTester tester,
  ) async {
    tester.view.physicalSize = const Size(800, 300);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await tester.pumpWidget(const OhttpApp());
    await tester.pumpAndSettle();

    // A window shorter than the controls must not overflow the layout.
    expect(tester.takeException(), isNull);

    // The controls live inside a vertically scrollable page.
    final pageScrollable = find.ancestor(
      of: find.text('Send via OHTTP'),
      matching: find.byType(Scrollable),
    );
    expect(pageScrollable, findsOneWidget);

    // Content below the fold starts off-screen and is reachable by scrolling.
    expect(find.text('No response yet').hitTestable(), findsNothing);
    await tester.scrollUntilVisible(
      find.text('No response yet').hitTestable(),
      100,
      scrollable: pageScrollable,
    );
    expect(find.text('No response yet').hitTestable(), findsOneWidget);
  });

  testWidgets('Send Both does not touch state after page disposal', (
    WidgetTester tester,
  ) async {
    final completer = Completer<http.StreamedResponse>();
    final client = _FakeHttpClient(completer);

    await http.runWithClient(() async {
      await tester.pumpWidget(const OhttpApp());
      await tester.pumpAndSettle();

      await tester.tap(find.text('Send Both & Compare'));
      await tester.pump();

      // Dispose the page while the OHTTP leg is still awaiting the network.
      await tester.pumpWidget(const MaterialApp(home: SizedBox()));

      completer.complete(
        http.StreamedResponse(Stream.value(const <int>[]), 500),
      );
      await tester.pump();

      expect(tester.takeException(), isNull);
      // Only the OHTTP key-config fetch reached the network;
      // the direct leg must not start after disposal.
      expect(client.requestCount, 1);
    }, () => client);
  });
}
