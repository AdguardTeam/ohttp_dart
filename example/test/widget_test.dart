import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:ohttp_flutter_example/main.dart';

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
}
