import 'dart:convert';
import 'dart:typed_data';

import 'package:ohttp_dart/ohttp_dart.dart';
import 'package:test/test.dart';

void main() {
  group('varint encoding', () {
    test('1-byte values (0–63)', () {
      expect(encodeVarint(0), [0x00]);
      expect(encodeVarint(1), [0x01]);
      expect(encodeVarint(63), [0x3F]);
    });

    test('2-byte values (64–16383)', () {
      final encoded = encodeVarint(64);
      expect(encoded, [0x40, 0x40]);

      final encoded2 = encodeVarint(16383);
      expect(encoded2, [0x7F, 0xFF]);
    });

    test('4-byte values (16384–1073741823)', () {
      final encoded = encodeVarint(16384);
      expect(encoded, [0x80, 0x00, 0x40, 0x00]);

      final encoded2 = encodeVarint(1073741823);
      expect(encoded2, [0xBF, 0xFF, 0xFF, 0xFF]);
    });
  });

  group('varint decoding', () {
    test('1-byte decode', () {
      final data = Uint8List.fromList([0x00]);
      expect(decodeVarint(data, 0), (0, 1));

      final data2 = Uint8List.fromList([0x3F]);
      expect(decodeVarint(data2, 0), (63, 1));
    });

    test('2-byte decode', () {
      final data = Uint8List.fromList([0x40, 0x40]);
      expect(decodeVarint(data, 0), (64, 2));

      final data2 = Uint8List.fromList([0x7F, 0xFF]);
      expect(decodeVarint(data2, 0), (16383, 2));
    });

    test('4-byte decode', () {
      final data = Uint8List.fromList([0x80, 0x00, 0x40, 0x00]);
      expect(decodeVarint(data, 0), (16384, 4));
    });

    test('decode with offset', () {
      final data = Uint8List.fromList([0xFF, 0xFF, 0x05]);
      expect(decodeVarint(data, 2), (5, 1));
    });
  });

  group('varint roundtrip', () {
    test('encode then decode matches', () {
      for (final value in [0, 1, 63, 64, 100, 255, 16383, 16384, 100000]) {
        final encoded = encodeVarint(value);
        final (decoded, len) = decodeVarint(Uint8List.fromList(encoded), 0);
        expect(decoded, value, reason: 'roundtrip failed for $value');
        expect(len, encoded.length);
      }
    });
  });

  group('serializeRequest', () {
    test('simple GET request', () {
      final data = serializeRequest(
        method: 'GET',
        scheme: 'https',
        authority: 'example.com',
        path: '/test',
        headers: [],
        body: Uint8List(0),
      );

      // Should start with framing indicator 0
      expect(data[0], 0x00);

      // Verify we can at least parse the control data
      var offset = 1; // skip framing
      // method length
      final (methodLen, ml) = decodeVarint(data, offset);
      offset += ml;
      expect(utf8.decode(data.sublist(offset, offset + methodLen)), 'GET');
    });

    test('POST request with headers and body', () {
      final body = utf8.encode('hello');
      final data = serializeRequest(
        method: 'POST',
        scheme: 'https',
        authority: 'example.com',
        path: '/post',
        headers: [('content-type', 'text/plain')],
        body: Uint8List.fromList(body),
      );

      expect(data[0], 0x00); // framing indicator
      expect(data.length > 10, true);
    });

    test('headers are lowercased', () {
      final data = serializeRequest(
        method: 'GET',
        scheme: 'https',
        authority: 'example.com',
        path: '/',
        headers: [('Content-Type', 'text/plain')],
        body: Uint8List(0),
      );

      // The serialized data should contain lowercase header name
      final str = utf8.decode(data, allowMalformed: true);
      expect(str.contains('content-type'), true);
      expect(str.contains('Content-Type'), false);
    });
  });

  group('parseResponse', () {
    test('parse simple 200 response', () {
      // Build a response manually:
      // framing(1) || status(200) || headers_len(0) || content_len || content || trailers(0)
      final buf = BytesBuilder();
      buf.add(encodeVarint(1)); // framing = response
      buf.add(encodeVarint(200)); // status
      buf.add(encodeVarint(0)); // empty headers
      final body = utf8.encode('OK');
      buf.add(encodeVarint(body.length));
      buf.add(body);

      final resp = parseResponse(buf.toBytes());
      expect(resp.statusCode, 200);
      expect(resp.headers, isEmpty);
      expect(utf8.decode(resp.body), 'OK');
    });

    test('parse response with headers', () {
      final buf = BytesBuilder();
      buf.add(encodeVarint(1)); // framing

      buf.add(encodeVarint(200)); // status

      // headers section
      final headerBuf = BytesBuilder();
      final name = utf8.encode('content-type');
      headerBuf.add(encodeVarint(name.length));
      headerBuf.add(name);
      final value = utf8.encode('application/json');
      headerBuf.add(encodeVarint(value.length));
      headerBuf.add(value);
      final headerBytes = headerBuf.toBytes();
      buf.add(encodeVarint(headerBytes.length));
      buf.add(headerBytes);

      // content
      final body = utf8.encode('{"ok":true}');
      buf.add(encodeVarint(body.length));
      buf.add(body);

      final resp = parseResponse(buf.toBytes());
      expect(resp.statusCode, 200);
      expect(resp.headers.length, 1);
      expect(resp.headers[0].$1, 'content-type');
      expect(resp.headers[0].$2, 'application/json');
      expect(utf8.decode(resp.body), '{"ok":true}');
    });

    test('rejects non-response framing', () {
      final buf = BytesBuilder();
      buf.add(encodeVarint(0)); // request framing, not response
      buf.add(encodeVarint(200));
      buf.add(encodeVarint(0));
      buf.add(encodeVarint(0));

      expect(
        () => parseResponse(buf.toBytes()),
        throwsA(isA<OhttpFormatException>()),
      );
    });
  });

  group('serialize/parse roundtrip', () {
    test('request serialize then manually build matching response', () {
      // Serialize a request
      final reqData = serializeRequest(
        method: 'GET',
        scheme: 'https',
        authority: 'example.com',
        path: '/get',
        headers: [('accept', 'application/json')],
        body: Uint8List(0),
      );

      // Just verify it's non-empty and starts with framing=0
      expect(reqData.isNotEmpty, true);
      expect(reqData[0], 0x00);
    });

    test('response with 404 status', () {
      final buf = BytesBuilder();
      buf.add(encodeVarint(1));
      buf.add(encodeVarint(404));
      buf.add(encodeVarint(0)); // no headers
      final body = utf8.encode('Not Found');
      buf.add(encodeVarint(body.length));
      buf.add(body);

      final resp = parseResponse(buf.toBytes());
      expect(resp.statusCode, 404);
      expect(utf8.decode(resp.body), 'Not Found');
    });

    test('response with empty body', () {
      final buf = BytesBuilder();
      buf.add(encodeVarint(1));
      buf.add(encodeVarint(204));
      buf.add(encodeVarint(0));
      buf.add(encodeVarint(0)); // empty content

      final resp = parseResponse(buf.toBytes());
      expect(resp.statusCode, 204);
      expect(resp.body, isEmpty);
    });
  });
}
