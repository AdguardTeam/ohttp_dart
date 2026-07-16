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

// Classic httpbin shape returned by /anything: headers as a map of
// name -> list of values, client info only in origin / Cf-* headers.
const _classicDirectEcho =
    '{"args":{},"headers":{'
    '"Accept":["application/json"],'
    '"Cf-connecting-ip":["203.0.113.7"],'
    '"Cf-ipcountry":["GB"],'
    '"User-agent":["Dart/3.11 (dart:io)"],'
    '"X-real-ip":["203.0.113.7"]},'
    '"method":"GET","origin":"",'
    '"url":"https://httpbin.agrd.workers.dev/anything",'
    '"data":null,"files":{},"form":{},"json":null}';

const _classicOhttpEcho =
    '{"args":{},"headers":{"Accept":["application/json"]},'
    '"method":"GET","origin":"",'
    '"url":"https://httpbin.agrd.workers.dev/anything",'
    '"data":null,"files":{},"form":{},"json":null}';

// httpbin.org flavor: header values are plain strings, origin is set.
const _httpbinOrgEcho =
    '{"args":{},"headers":{'
    '"Accept":"application/json","User-Agent":"curl/8.7.1"},'
    '"method":"GET","origin":"198.51.100.1",'
    '"url":"https://httpbin.org/anything"}';

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

  test('extracts leaked facts from a classic httpbin direct echo', () {
    final facts = extractPrivacyFacts(_classicDirectEcho);
    expect(facts, isNotNull);
    expect(facts!.ip, '203.0.113.7');
    expect(facts.country, 'GB');
    expect(facts.userAgent, 'Dart/3.11 (dart:io)');
    expect(facts.headerCount, 5);
    expect(facts.fingerprintPresent, isFalse);
  });

  test('extracts hidden facts from a classic httpbin OHTTP echo', () {
    final facts = extractPrivacyFacts(_classicOhttpEcho);
    expect(facts, isNotNull);
    expect(facts!.ip, isNull);
    expect(facts.country, isNull);
    expect(facts.userAgent, isNull);
    expect(facts.headerCount, 1);
    expect(facts.fingerprintPresent, isFalse);
  });

  test('extracts facts from httpbin.org-style string header values', () {
    final facts = extractPrivacyFacts(_httpbinOrgEcho);
    expect(facts, isNotNull);
    expect(facts!.ip, '198.51.100.1');
    expect(facts.country, isNull);
    expect(facts.userAgent, 'curl/8.7.1');
    expect(facts.headerCount, 2);
  });

  test('headerCount counts name-value occurrences equally in both shapes', () {
    // Same logical header set: "a" repeated twice + single "b".
    const pairList =
        '{"headers":[["a","1"],["a","2"],["b","3"]],'
        '"ip":null,"country":null,"body":""}';
    const classic =
        '{"headers":{"A":["1","2"],"B":"3"},'
        '"origin":"","url":"https://httpbin.org/anything"}';

    expect(extractPrivacyFacts(pairList)!.headerCount, 3);
    expect(extractPrivacyFacts(classic)!.headerCount, 3);
  });

  test('returns null for non-echo shapes', () {
    expect(extractPrivacyFacts('{"status":"ok"}'), isNull);
    expect(extractPrivacyFacts('[1,2,3]'), isNull);
    expect(extractPrivacyFacts('plain text'), isNull);
    expect(extractPrivacyFacts(''), isNull);
  });
}
