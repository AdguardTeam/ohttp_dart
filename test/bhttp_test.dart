import 'dart:convert';
import 'dart:typed_data';

import 'package:kiri_check/kiri_check.dart';
import 'package:ohttp_dart/ohttp_dart.dart';
import 'package:test/test.dart';

void main() {
  group('varint encoding', () {
    test('1-byte values (0–63)', () {
      expect(encodeVarint(0), [0x00]);
      expect(encodeVarint(1), [0x01]);
      expect(encodeVarint(63), [0x3F]);
    });

    test('2-byte values (64–2^14 - 1)', () {
      final encoded = encodeVarint(64);
      expect(encoded, [0x40, 0x40]);

      final encoded2 = encodeVarint(16383);
      expect(encoded2, [0x7F, 0xFF]);
    });

    test('4-byte values (2^14–2^30 - 1)', () {
      final encoded = encodeVarint(16384);
      expect(encoded, [0x80, 0x00, 0x40, 0x00]);

      final encoded2 = encodeVarint(0x3FFFFFFF);
      expect(encoded2, [0xBF, 0xFF, 0xFF, 0xFF]);
    });

    // RFC 9000 §16: the two top bits of the first byte encode the length category.
    property('first-byte top 2 bits are 0b00 for 1-byte values', () {
      forAll(
        integer(min: 0, max: 63),
        (value) => expect(encodeVarint(value)[0] >> 6, 0),
      );
    });

    property('first-byte top 2 bits are 0b01 for 2-byte values', () {
      forAll(
        integer(min: 64, max: 0x3FFF),
        (value) => expect(encodeVarint(value)[0] >> 6, 1),
      );
    });

    property('first-byte top 2 bits are 0b10 for 4-byte values', () {
      forAll(
        integer(min: 0x4000, max: 0x3FFFFFFF),
        (value) => expect(encodeVarint(value)[0] >> 6, 2),
      );
    });

    property('throws OhttpFormatException for all negative values', () {
      forAll(
        integer(min: -0x8000000000000000, max: -1),
        (value) => expect(() => encodeVarint(value), throwsA(isA<OhttpFormatException>())),
      );
    });

    property('throws OhttpFormatException for all values ≥ 2^62', () {
      forAll(
        integer(min: 0x4000000000000000, max: 0x7FFFFFFFFFFFFFFF),
        (value) => expect(() => encodeVarint(value), throwsA(isA<OhttpFormatException>())),
      );
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
      expect(decodeVarint(data2, 0), (0x3FFF, 2));
    });

    test('4-byte decode', () {
      final data = Uint8List.fromList([0x80, 0x00, 0x40, 0x00]);
      expect(decodeVarint(data, 0), (0x4000, 4));
    });

    test('decode with offset', () {
      final data = Uint8List.fromList([0xFF, 0xFF, 0x05]);
      expect(decodeVarint(data, 2), (5, 1));
    });

    // Range [0, 2^14) covers the 1-byte and 2-byte varint ranges
    // plus the 2^14 - 1 → 2^14 length-boundary (RFC 9000 §16).
    property('decode at arbitrary byte offset returns correct value and length', () {
      forAll(
        combine2(
          integer(min: 0, max: 0x3FFF),
          integer(min: 0, max: 9),
        ),
        (args) {
          final (value, offset) = args;
          final encoded = encodeVarint(value);
          final data = Uint8List.fromList([...List.filled(offset, 0xFF), ...encoded]);
          final (decoded, len) = decodeVarint(data, offset);
          expect(decoded, value, reason: 'value=$value at offset=$offset');
          expect(len, encoded.length);
        },
      );
    });

    // Range [0, 2^30) covers 1-byte, 2-byte, and 4-byte varint encodings
    // (RFC 9000 §16). 8-byte varints are covered by the roundtrip group.
    property('sequential concatenated varints decode without loss', () {
      forAll(
        list(integer(min: 0, max: 0x3FFFFFFF)),
        (values) {
          final buf = BytesBuilder();
          for (final v in values) {
            buf.add(encodeVarint(v));
          }
          final data = buf.toBytes();
          var offset = 0;
          for (final expected in values) {
            final (decoded, len) = decodeVarint(data, offset);
            expect(decoded, expected);
            offset += len;
          }
          expect(offset, data.length, reason: 'all bytes must be consumed after sequential decode');
        },
      );
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
      const value = 0x3FFFFFFF; // 2^30 - 1
      final encoded = encodeVarint(value);
      expect(encoded.length, 4, reason: 'largest 4-byte varint must be 4 bytes');
      final (decoded, len) = decodeVarint(Uint8List.fromList(encoded), 0);
      expect(decoded, value);
      expect(len, 4);
    });

    test('smallest 8-byte value (0x40000000 = 2^30) roundtrips as 8 bytes', () {
      const value = 0x40000000; // 2^30
      final encoded = encodeVarint(value);
      expect(encoded.length, 8, reason: 'smallest 8-byte varint must be 8 bytes');
      final (decoded, len) = decodeVarint(Uint8List.fromList(encoded), 0);
      expect(decoded, value);
      expect(len, 8);
    });

    test('largest 8-byte value (2^62 - 1) roundtrips as 8 bytes', () {
      const value = 0x3FFFFFFFFFFFFFFF; // 2^62 - 1
      final encoded = encodeVarint(value);
      expect(encoded.length, 8, reason: 'largest valid varint must be 8 bytes');
      final (decoded, len) = decodeVarint(Uint8List.fromList(encoded), 0);
      expect(decoded, value);
      expect(len, 8);
    });

    property('roundtrip: 1-byte values [0, 63]', () {
      forAll(
        integer(min: 0, max: 63),
        (value) {
          final encoded = encodeVarint(value);
          expect(encoded.length, 1, reason: 'value=$value must encode as 1 byte');
          final (decoded, len) = decodeVarint(Uint8List.fromList(encoded), 0);
          expect(decoded, value);
          expect(len, 1);
        },
      );
    });

    property('roundtrip: 2-byte values [64, 2^14 - 1]', () {
      forAll(
        integer(min: 64, max: 0x3FFF),
        (value) {
          final encoded = encodeVarint(value);
          expect(encoded.length, 2, reason: 'value=$value must encode as 2 bytes');
          final (decoded, len) = decodeVarint(Uint8List.fromList(encoded), 0);
          expect(decoded, value);
          expect(len, 2);
        },
      );
    });

    property('roundtrip: 4-byte values [2^14, 2^30 - 1]', () {
      forAll(
        integer(min: 0x4000, max: 0x3FFFFFFF),
        (value) {
          final encoded = encodeVarint(value);
          expect(encoded.length, 4, reason: 'value=$value must encode as 4 bytes');
          final (decoded, len) = decodeVarint(Uint8List.fromList(encoded), 0);
          expect(decoded, value);
          expect(len, 4);
        },
      );
    });

    // Full 8-byte varint range (RFC 9000 §16): [2^30, 2^62 - 1].
    property('roundtrip: 8-byte values [2^30, 2^62 - 1]', () {
      forAll(
        integer(min: 0x40000000, max: 0x3FFFFFFFFFFFFFFF),
        (value) {
          final encoded = encodeVarint(value);
          expect(encoded.length, 8, reason: 'value=$value must encode as 8 bytes');
          final (decoded, len) = decodeVarint(Uint8List.fromList(encoded), 0);
          expect(decoded, value);
          expect(len, 8);
        },
      );
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

    test('trailing trailers varint is 0x00 (RFC 9292 §3.1)', () {
      final data = serializeRequest(
        method: 'POST',
        scheme: 'https',
        authority: 'example.com',
        path: '/submit',
        headers: [('content-type', 'application/json')],
        body: Uint8List.fromList(utf8.encode('{"x":1}')),
      );

      // Navigate past framing(1) + 4 control fields + header section + body
      var offset = 1;
      for (var j = 0; j < 4; j++) {
        final (fieldLen, fll) = decodeVarint(data, offset);
        offset += fll + fieldLen;
      }
      final (headersLen, hll) = decodeVarint(data, offset);
      offset += hll + headersLen;
      final (bodyLen, bll) = decodeVarint(data, offset);
      offset += bll + bodyLen;

      // Trailers must be a single zero varint
      final (trailersLen, tll) = decodeVarint(data, offset);
      expect(trailersLen, 0, reason: 'trailing trailers length must be 0');
      expect(offset + tll, data.length, reason: 'trailers must be the last field');
    });

    property('framing indicator is always 0x00 for arbitrary body', () {
      forAll(
        list(integer(min: 0, max: 255)).map(Uint8List.fromList),
        (body) {
          final data = serializeRequest(
            method: 'GET',
            scheme: 'https',
            authority: 'example.com',
            path: '/',
            headers: [],
            body: body,
          );
          expect(data[0], 0x00);
        },
      );
    });

    property('header name is lowercased in output', () {
      forAll(
        string(
          characterSet: CharacterSet.alphanum(CharacterEncoding.ascii),
          minLength: 1,
        ),
        (name) {
          final data = serializeRequest(
            method: 'GET',
            scheme: 'https',
            authority: 'example.com',
            path: '/',
            headers: [(name, 'value')],
            body: Uint8List(0),
          );
          // Navigate past framing indicator + 4 control fields (method/scheme/authority/path)
          var offset = 1;
          for (var j = 0; j < 4; j++) {
            final (fieldLen, fll) = decodeVarint(data, offset);
            offset += fll + fieldLen;
          }
          // Header section length
          final (_, hll) = decodeVarint(data, offset);
          offset += hll;
          // First header name
          final (nameLen, nll) = decodeVarint(data, offset);
          offset += nll;
          final decodedName = utf8.decode(data.sublist(offset, offset + nameLen));
          expect(decodedName, equals(name.toLowerCase()));
        },
      );
    });

    property('body length varint matches actual body length', () {
      forAll(
        list(integer(min: 0, max: 255)).map(Uint8List.fromList),
        (body) {
          final data = serializeRequest(
            method: 'GET',
            scheme: 'https',
            authority: 'example.com',
            path: '/',
            headers: [],
            body: body,
          );
          // Navigate past: framing(1 byte) + 4 length-prefixed control fields + header section
          var offset = 1; // framing indicator
          for (var j = 0; j < 4; j++) {
            // method, scheme, authority, path
            final (fieldLen, fll) = decodeVarint(data, offset);
            offset += fll + fieldLen;
          }
          final (headersLen, hll) = decodeVarint(data, offset);
          offset += hll + headersLen;
          final (encodedBodyLen, _) = decodeVarint(data, offset);
          expect(encodedBodyLen, body.length);
        },
      );
    });

    property('output is deterministic: same inputs produce identical bytes', () {
      forAll(
        combine2(
          string(
            characterSet: CharacterSet.lower(CharacterEncoding.ascii),
            minLength: 1,
          ),
          list(integer(min: 0, max: 255)).map(Uint8List.fromList),
        ),
        (args) {
          final (path, body) = args;
          final first = serializeRequest(
            method: 'GET',
            scheme: 'https',
            authority: 'example.com',
            path: '/$path',
            headers: [],
            body: body,
          );
          final second = serializeRequest(
            method: 'GET',
            scheme: 'https',
            authority: 'example.com',
            path: '/$path',
            headers: [],
            body: body,
          );
          expect(first, equals(second));
        },
      );
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

    // RFC 9292 §3.3: only framing=1 (known-length response) is accepted.
    // Indicators 2 and 3 (indeterminate-length) are defined but unsupported;
    // indicator 4 and above are invalid per the RFC.
    for (final indicator in [2, 3]) {
      test('rejects unsupported indeterminate-length framing indicator $indicator (RFC 9292 §3.3)', () {
        final buf = BytesBuilder();
        buf.add(encodeVarint(indicator));
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
    }

    test('rejects unknown framing indicator 4 (RFC 9292 §3.3)', () {
      const indicator = 4;
      final buf = BytesBuilder();
      buf.add(encodeVarint(indicator));
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

    test('rejects large varint framing indicator (RFC 9292 §3.3)', () {
      // 8-byte varint encoding of value 0x40000000 (invalid per RFC 9292 §3.3)
      final buf = BytesBuilder();
      buf.add(
        encodeVarint(0x40000000),
      ); // invalid framing indicator (value 2^30, must be 0 or 1 per RFC 9292 §3.3)
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

    property('status code is preserved for all valid codes 200–599', () {
      forAll(
        integer(min: 200, max: 599),
        (code) {
          final resp = parseResponse(
            _buildBhttpResponse(statusCode: code),
            limits: const BhttpResponseLimits(),
          );
          expect(resp.statusCode, code);
        },
      );
    });

    property('body bytes are preserved byte-for-byte', () {
      forAll(
        list(integer(min: 0, max: 255)).map(Uint8List.fromList),
        (body) {
          final resp = parseResponse(
            _buildBhttpResponse(statusCode: 200, body: body),
            limits: const BhttpResponseLimits(),
          );
          expect(resp.body, equals(body));
        },
      );
    });

    property('headers are preserved in insertion order', () {
      forAll(
        list(
          combine2(
            string(
              characterSet: CharacterSet.lower(CharacterEncoding.ascii),
              minLength: 1,
            ),
            string(
              characterSet: CharacterSet.lower(CharacterEncoding.ascii),
            ),
          ),
        ),
        (headers) {
          final resp = parseResponse(
            _buildBhttpResponse(statusCode: 200, headers: headers),
            limits: const BhttpResponseLimits(),
          );
          expect(resp.headers.length, headers.length);
          for (final (i, header) in headers.indexed) {
            expect(resp.headers[i].$1, header.$1);
            expect(resp.headers[i].$2, header.$2);
          }
        },
      );
    });

    property('arbitrary count of 1xx responses are skipped before final status', () {
      forAll(
        integer(min: 1, max: 5),
        (count1xx) {
          final buf = BytesBuilder();
          buf.add(encodeVarint(1)); // framing
          for (var k = 0; k < count1xx; k++) {
            buf.add(encodeVarint(100 + k % 100)); // 1xx status
            buf.add(encodeVarint(0)); // empty informational header section
          }
          buf.add(encodeVarint(200));
          buf.add(encodeVarint(0)); // empty headers
          buf.add(encodeVarint(0)); // empty body
          final resp = parseResponse(buf.toBytes(), limits: const BhttpResponseLimits());
          expect(resp.statusCode, 200);
        },
      );
    });

    // RFC 9292 §3.3: a 1xx informational response must be followed by a final
    // response. A buffer that ends after 1xx — with no final status — is truncated
    // and must throw OhttpFormatException.
    property('throws OhttpFormatException when buffer ends after 1xx with no final status', () {
      forAll(
        integer(min: 100, max: 199),
        (status1xx) {
          final buf = BytesBuilder();
          buf.add(encodeVarint(1)); // framing
          buf.add(encodeVarint(status1xx)); // 1xx status
          buf.add(encodeVarint(0)); // empty informational header section
          // intentionally no final status — buffer is truncated here
          expect(
            () => parseResponse(buf.toBytes(), limits: const BhttpResponseLimits()),
            throwsA(isA<OhttpFormatException>()),
          );
        },
      );
    });

    // For limit tests, we test both "at limit" (passes) and "over limit" (throws)
    // as properties over a range of body lengths.
    property('body never silently truncated when within limit', () {
      forAll(
        integer(min: 0, max: 999),
        (bodyLen) {
          final body = Uint8List(bodyLen);
          final resp = parseResponse(
            _buildBhttpResponse(statusCode: 200, body: body),
            limits: BhttpResponseLimits(maxBodyBytes: bodyLen),
          );
          expect(resp.body.length, bodyLen);
        },
      );
    });

    property('body exceeding limit throws OhttpSizeLimitException', () {
      forAll(
        integer(min: 1, max: 999),
        (bodyLen) {
          final body = Uint8List(bodyLen);
          expect(
            () => parseResponse(
              _buildBhttpResponse(statusCode: 200, body: body),
              limits: BhttpResponseLimits(maxBodyBytes: bodyLen - 1),
            ),
            throwsA(isA<OhttpSizeLimitException>()),
          );
        },
      );
    });

    // Header section = varint(nameLen=1) + "n" + varint(valueLen) + value
    //                = 1 + 1 + 1 + valueLen = 3 + valueLen  (for valueLen ∈ [0, 62])
    // Range [3, 65]: valueLen = limit - 3 ∈ [0, 62], so valueLen + 1 ≤ 63 — always
    // fits in a 1-byte varint.  Stopping at 66 would give valueLen = 63, making
    // valueLen + 1 = 64 which encodes as 2 bytes and breaks the "one byte over" invariant.
    property('header section at limit passes, one byte over throws', () {
      forAll(
        integer(min: 3, max: 65),
        (limit) {
          final name = utf8.encode('n');
          final valueLen = limit - 3;
          final exactSection = _buildHeaderSection(name, utf8.encode('v' * valueLen));
          final buf1 = BytesBuilder()
            ..add(encodeVarint(1))
            ..add(encodeVarint(200))
            ..add(encodeVarint(exactSection.length))
            ..add(exactSection)
            ..add(encodeVarint(0));
          expect(
            parseResponse(buf1.toBytes(), limits: BhttpResponseLimits(maxHeaderBytes: limit)).statusCode,
            200,
          );

          final overSection = _buildHeaderSection(name, utf8.encode('v' * (valueLen + 1)));
          final buf2 = BytesBuilder()
            ..add(encodeVarint(1))
            ..add(encodeVarint(200))
            ..add(encodeVarint(overSection.length))
            ..add(overSection)
            ..add(encodeVarint(0));
          expect(
            () => parseResponse(buf2.toBytes(), limits: BhttpResponseLimits(maxHeaderBytes: limit)),
            throwsA(isA<OhttpSizeLimitException>()),
          );
        },
      );
    });
  });

  group('serialize/parse roundtrip', () {
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
    property('throws OhttpFormatException for all status codes below 100', () {
      forAll(
        integer(min: 0, max: 99),
        (code) {
          final buf = BytesBuilder()
            ..add(encodeVarint(1))
            ..add(encodeVarint(code))
            ..add(encodeVarint(0))
            ..add(encodeVarint(0));
          expect(
            () => parseResponse(buf.toBytes(), limits: const BhttpResponseLimits()),
            throwsA(isA<OhttpFormatException>()),
          );
        },
      );
    });

    property('throws OhttpFormatException for all status codes above 599', () {
      forAll(
        integer(min: 600, max: 999),
        (code) {
          final buf = BytesBuilder()
            ..add(encodeVarint(1))
            ..add(encodeVarint(code))
            ..add(encodeVarint(0))
            ..add(encodeVarint(0));
          expect(
            () => parseResponse(buf.toBytes(), limits: const BhttpResponseLimits()),
            throwsA(isA<OhttpFormatException>()),
          );
        },
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

    test('throws OhttpFormatException when truncated after framing indicator', () {
      final buf = BytesBuilder();
      buf.add(encodeVarint(1));
      expect(
        () => parseResponse(
          buf.toBytes(),
          limits: const BhttpResponseLimits(),
        ),
        throwsA(isA<OhttpFormatException>()),
      );
    });

    test('throws OhttpFormatException when header section bytes are missing', () {
      final buf = BytesBuilder();
      buf.add(encodeVarint(1));
      buf.add(encodeVarint(200));
      buf.add(encodeVarint(100));
      expect(
        () => parseResponse(
          buf.toBytes(),
          limits: const BhttpResponseLimits(),
        ),
        throwsA(isA<OhttpFormatException>()),
      );
    });

    test('throws OhttpFormatException when content bytes are missing', () {
      final buf = BytesBuilder();
      buf.add(encodeVarint(1));
      buf.add(encodeVarint(200));
      buf.add(encodeVarint(0));
      buf.add(encodeVarint(100));
      expect(
        () => parseResponse(
          buf.toBytes(),
          limits: const BhttpResponseLimits(),
        ),
        throwsA(isA<OhttpFormatException>()),
      );
    });

    test('throws OhttpFormatException when header name bytes are truncated', () {
      final buf = BytesBuilder();
      buf.add(encodeVarint(1));
      buf.add(encodeVarint(200));
      final headerBuf = BytesBuilder();
      headerBuf.add(encodeVarint(8)); // nameLen = 8
      headerBuf.add([0x61, 0x62, 0x63]); // only 3 bytes of name instead of 8
      final headerBytes = headerBuf.toBytes();
      buf.add(encodeVarint(headerBytes.length));
      buf.add(headerBytes);
      expect(
        () => parseResponse(
          buf.toBytes(),
          limits: const BhttpResponseLimits(),
        ),
        throwsA(isA<OhttpFormatException>()),
      );
    });

    test('throws OhttpFormatException when header value bytes are truncated', () {
      final buf = BytesBuilder();
      buf.add(encodeVarint(1));
      buf.add(encodeVarint(200));
      final headerBuf = BytesBuilder();
      final headerName = utf8.encode('x-test');
      headerBuf.add(encodeVarint(headerName.length));
      headerBuf.add(headerName);
      headerBuf.add(encodeVarint(10)); // valueLen = 10
      headerBuf.add([0x61, 0x62]); // only 2 bytes of value instead of 10
      final headerBytes = headerBuf.toBytes();
      buf.add(encodeVarint(headerBytes.length));
      buf.add(headerBytes);
      expect(
        () => parseResponse(
          buf.toBytes(),
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
          isA<OhttpSizeLimitException>().having((e) => e.limit, 'limit', 1000),
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
              .having((e) => e.actualSize, 'actualSize', 20 * 1024 * 1024),
        ),
      );
    });
  });
}

Uint8List _buildBhttpResponse({
  required int statusCode,
  Uint8List? body,
  List<(String, String)> headers = const <(String, String)>[],
}) {
  final buf = BytesBuilder();
  buf.add(encodeVarint(1)); // framing = known-length response
  buf.add(encodeVarint(statusCode));
  final headerBuf = BytesBuilder();
  for (final (name, value) in headers) {
    final n = utf8.encode(name);
    headerBuf.add(encodeVarint(n.length));
    headerBuf.add(n);
    final v = utf8.encode(value);
    headerBuf.add(encodeVarint(v.length));
    headerBuf.add(v);
  }
  final headerBytes = headerBuf.toBytes();
  buf.add(encodeVarint(headerBytes.length));
  buf.add(headerBytes);
  final b = body ?? Uint8List(0);
  buf.add(encodeVarint(b.length));
  buf.add(b);

  return buf.toBytes();
}

Uint8List _buildHeaderSection(List<int> nameBytes, List<int> valueBytes) {
  final buf = BytesBuilder();
  buf.add(encodeVarint(nameBytes.length));
  buf.add(nameBytes);
  buf.add(encodeVarint(valueBytes.length));
  buf.add(valueBytes);

  return buf.toBytes();
}
