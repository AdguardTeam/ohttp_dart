import 'package:flutter_test/flutter_test.dart';
import 'package:ohttp_flutter_example/src/privacy_facts.dart';

const _directEcho =
    '{"headers":[["accept","application/json"],'
    '["user-agent","Dart/3.11 (dart:io)"],["x-real-ip","203.0.113.7"]],'
    '"method":"GET","url":"https://httpbin.agrd.workers.dev/get",'
    '"ip":"203.0.113.7","country":"GB","body":"",'
    '"cf":{"colo":"LHR","country":"GB"}}';

const _ohttpEcho =
    '{"headers":[["accept","application/json"]],'
    '"method":"GET","url":"https://httpbin.agrd.workers.dev/get",'
    '"ip":null,"country":null,"body":""}';

void main() {
  test('extracts leaked facts from a direct echo response', () {
    final facts = extractPrivacyFacts(_directEcho);
    expect(facts, isNotNull);
    expect(facts!.ip, '203.0.113.7');
    expect(facts.country, 'GB');
    expect(facts.userAgent, 'Dart/3.11 (dart:io)');
    expect(facts.headerCount, 3);
    expect(facts.fingerprintPresent, isTrue);
  });

  test('extracts hidden facts from an OHTTP echo response', () {
    final facts = extractPrivacyFacts(_ohttpEcho);
    expect(facts, isNotNull);
    expect(facts!.ip, isNull);
    expect(facts.country, isNull);
    expect(facts.userAgent, isNull);
    expect(facts.headerCount, 1);
    expect(facts.fingerprintPresent, isFalse);
  });

  test('returns null for non-echo shapes', () {
    expect(extractPrivacyFacts('{"status":"ok"}'), isNull);
    expect(extractPrivacyFacts('[1,2,3]'), isNull);
    expect(extractPrivacyFacts('plain text'), isNull);
    expect(extractPrivacyFacts(''), isNull);
  });
}
