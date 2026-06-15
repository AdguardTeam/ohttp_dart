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

    // RFC 9000 §16: 8-byte varint boundary
    test('largest 4-byte value (0x3FFFFFFF = 2^30 - 1) roundtrips as 4 bytes', () {
      const value = 0x3FFFFFFF; // 1073741823
      final encoded = encodeVarint(value);
      expect(encoded.length, 4, reason: 'largest 4-byte varint must be 4 bytes');
      final (decoded, len) = decodeVarint(Uint8List.fromList(encoded), 0);
      expect(decoded, value);
      expect(len, 4);
    });

    test('smallest 8-byte value (0x40000000 = 2^30) roundtrips as 8 bytes', () {
      const value = 0x40000000; // 1073741824
      final encoded = encodeVarint(value);
      expect(encoded.length, 8, reason: 'smallest 8-byte varint must be 8 bytes');
      final (decoded, len) = decodeVarint(Uint8List.fromList(encoded), 0);
      expect(decoded, value);
      expect(len, 8);
    });

    test('largest 8-byte value (2^62 - 1) roundtrips as 8 bytes', () {
      const value = 0x3FFFFFFFFFFFFFFF; // 4611686018427387903
      final encoded = encodeVarint(value);
      expect(encoded.length, 8, reason: 'largest valid varint must be 8 bytes');
      final (decoded, len) = decodeVarint(Uint8List.fromList(encoded), 0);
      expect(decoded, value);
      expect(len, 8);
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

      final resp = parseResponse(
        buf.toBytes(),
        limits: const BhttpResponseLimits(),
      );
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

      final resp = parseResponse(
        buf.toBytes(),
        limits: const BhttpResponseLimits(),
      );
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
        () => parseResponse(
          buf.toBytes(),
          limits: const BhttpResponseLimits(),
        ),
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

      final resp = parseResponse(
        buf.toBytes(),
        limits: const BhttpResponseLimits(),
      );
      expect(resp.statusCode, 404);
      expect(utf8.decode(resp.body), 'Not Found');
    });

    test('response with empty body', () {
      final buf = BytesBuilder();
      buf.add(encodeVarint(1));
      buf.add(encodeVarint(204));
      buf.add(encodeVarint(0));
      buf.add(encodeVarint(0)); // empty content

      final resp = parseResponse(
        buf.toBytes(),
        limits: const BhttpResponseLimits(),
      );
      expect(resp.statusCode, 204);
      expect(resp.body, isEmpty);
    });
  });

  group('decodeVarint boundary checks', () {
    test('throws OhttpFormatException on truncated or out-of-bounds data', () {
      // Empty data
      expect(
        () => decodeVarint(Uint8List(0), 0),
        throwsA(isA<OhttpFormatException>()),
      );

      // Truncated 2-byte varint (0x40 indicates 2 bytes, only 1 provided)
      expect(
        () => decodeVarint(Uint8List.fromList([0x40]), 0),
        throwsA(isA<OhttpFormatException>()),
      );

      // Truncated 4-byte varint (0x80 indicates 4 bytes, only 2 provided)
      expect(
        () => decodeVarint(Uint8List.fromList([0x80, 0x00]), 0),
        throwsA(isA<OhttpFormatException>()),
      );

      // Truncated 8-byte varint (0xC0 indicates 8 bytes, only 4 provided)
      expect(
        () => decodeVarint(Uint8List.fromList([0xC0, 0x00, 0x00, 0x00]), 0),
        throwsA(isA<OhttpFormatException>()),
      );

      // Offset exceeds data length
      expect(
        () => decodeVarint(Uint8List.fromList([0x05]), 10),
        throwsA(isA<OhttpFormatException>()),
      );
    });
  });

  group('parseResponse validation', () {
    test('throws OhttpFormatException on status below 100 and above 599', () {
      // Status code 50 (below 100)
      final buf1 = BytesBuilder();
      buf1.add(encodeVarint(1));
      buf1.add(encodeVarint(50));
      buf1.add(encodeVarint(0));
      buf1.add(encodeVarint(0));
      expect(
        () => parseResponse(
          buf1.toBytes(),
          limits: const BhttpResponseLimits(),
        ),
        throwsA(isA<OhttpFormatException>()),
      );

      // Status code 700 (above 599)
      final buf2 = BytesBuilder();
      buf2.add(encodeVarint(1));
      buf2.add(encodeVarint(700));
      buf2.add(encodeVarint(0));
      buf2.add(encodeVarint(0));
      expect(
        () => parseResponse(
          buf2.toBytes(),
          limits: const BhttpResponseLimits(),
        ),
        throwsA(isA<OhttpFormatException>()),
      );
    });

    test('accepts boundary status codes 100 and 599', () {
      // Status code 100 (informational, followed by final 200)
      final buf1 = BytesBuilder();
      buf1.add(encodeVarint(1));
      buf1.add(encodeVarint(100));
      buf1.add(encodeVarint(0));
      buf1.add(encodeVarint(200));
      buf1.add(encodeVarint(0));
      buf1.add(encodeVarint(0));
      expect(
        parseResponse(
          buf1.toBytes(),
          limits: const BhttpResponseLimits(),
        ).statusCode,
        200,
      );

      // Status code 599
      final buf2 = BytesBuilder();
      buf2.add(encodeVarint(1));
      buf2.add(encodeVarint(599));
      buf2.add(encodeVarint(0));
      buf2.add(encodeVarint(0));
      expect(
        parseResponse(
          buf2.toBytes(),
          limits: const BhttpResponseLimits(),
        ).statusCode,
        599,
      );
    });

    test('throws OhttpFormatException on truncated response sections', () {
      // Truncated: only framing indicator
      final buf1 = BytesBuilder();
      buf1.add(encodeVarint(1));
      expect(
        () => parseResponse(
          buf1.toBytes(),
          limits: const BhttpResponseLimits(),
        ),
        throwsA(isA<OhttpFormatException>()),
      );

      // Truncated header section
      final buf2 = BytesBuilder();
      buf2.add(encodeVarint(1));
      buf2.add(encodeVarint(200));
      buf2.add(encodeVarint(100));
      expect(
        () => parseResponse(
          buf2.toBytes(),
          limits: const BhttpResponseLimits(),
        ),
        throwsA(isA<OhttpFormatException>()),
      );

      // Truncated content
      final buf3 = BytesBuilder();
      buf3.add(encodeVarint(1));
      buf3.add(encodeVarint(200));
      buf3.add(encodeVarint(0));
      buf3.add(encodeVarint(100));
      expect(
        () => parseResponse(
          buf3.toBytes(),
          limits: const BhttpResponseLimits(),
        ),
        throwsA(isA<OhttpFormatException>()),
      );
    });
  });

  group('parseResponse size validation', () {
    test('throws OhttpSizeLimitException when response headers exceed limit', () {
      final buf = BytesBuilder();
      buf.add(encodeVarint(1)); // framing
      buf.add(encodeVarint(200)); // status

      // Create large header section
      final headerBuf = BytesBuilder();
      final name = utf8.encode('x-custom');
      headerBuf.add(encodeVarint(name.length));
      headerBuf.add(name);
      final value = utf8.encode('A' * 20000);
      headerBuf.add(encodeVarint(value.length));
      headerBuf.add(value);
      final headerBytes = headerBuf.toBytes();
      buf.add(encodeVarint(headerBytes.length));
      buf.add(headerBytes);

      buf.add(encodeVarint(0)); // empty body

      expect(
        () => parseResponse(
          buf.toBytes(),
          limits: const BhttpResponseLimits(maxHeaderBytes: 1000),
        ),
        throwsA(
          isA<OhttpSizeLimitException>()
              .having((e) => e.limit, 'limit', 1000)
              .having((e) => e.message, 'message', contains('headers')),
        ),
      );
    });

    test('throws OhttpSizeLimitException when response body exceeds limit', () {
      final buf = BytesBuilder();
      buf.add(encodeVarint(1)); // framing
      buf.add(encodeVarint(200)); // status
      buf.add(encodeVarint(0)); // empty headers

      // Large body
      final body = Uint8List(20 * 1024 * 1024); // 20 MB
      buf.add(encodeVarint(body.length));
      buf.add(body);

      expect(
        () => parseResponse(
          buf.toBytes(),
          limits: const BhttpResponseLimits(maxBodyBytes: 5 * 1024 * 1024), // 5 MB
        ),
        throwsA(
          isA<OhttpSizeLimitException>()
              .having((e) => e.limit, 'limit', 5 * 1024 * 1024)
              .having((e) => e.actualSize, 'actualSize', 20 * 1024 * 1024)
              .having((e) => e.message, 'message', contains('body')),
        ),
      );
    });
  });
}
