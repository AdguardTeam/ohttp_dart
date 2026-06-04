import 'dart:convert';
import 'dart:typed_data';
import 'exceptions.dart';

/// Binary HTTP Messages (RFC 9292) — Known-Length framing.
///
/// Implements serialization of requests and deserialization of responses
/// using the Known-Length framing format (framing indicator 0 for requests,
/// 1 for responses).

// ---------------------------------------------------------------------------
// Varint encoding/decoding (QUIC variable-length integer, RFC 9000 §16)
// ---------------------------------------------------------------------------

/// Encode an integer as a QUIC variable-length integer.
Uint8List encodeVarint(int value) {
  if (value < 0x40) {
    return Uint8List.fromList([value]);
  } else if (value < 0x4000) {
    return Uint8List.fromList([0x40 | (value >> 8), value & 0xFF]);
  } else if (value < 0x40000000) {
    return Uint8List.fromList([
      0x80 | (value >> 24) & 0x3F,
      (value >> 16) & 0xFF,
      (value >> 8) & 0xFF,
      value & 0xFF,
    ]);
  } else {
    // 8-byte varint (62-bit)
    return Uint8List.fromList([
      0xC0 | ((value >> 56) & 0x3F),
      (value >> 48) & 0xFF,
      (value >> 40) & 0xFF,
      (value >> 32) & 0xFF,
      (value >> 24) & 0xFF,
      (value >> 16) & 0xFF,
      (value >> 8) & 0xFF,
      value & 0xFF,
    ]);
  }
}

/// Decode a QUIC variable-length integer at [offset] in [data].
/// Returns (value, bytesConsumed).
(int, int) decodeVarint(Uint8List data, int offset) {
  final first = data[offset];
  final prefix = first >> 6;
  switch (prefix) {
    case 0:
      return (first & 0x3F, 1);
    case 1:
      return (((first & 0x3F) << 8) | data[offset + 1], 2);
    case 2:
      return (
        ((first & 0x3F) << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3],
        4,
      );
    case 3:
      // 8-byte varint — for our use cases this won't occur, but handle it
      var value = (first & 0x3F);
      for (var i = 1; i <= 7; i++) {
        value = (value << 8) | data[offset + i];
      }

      return (value, 8);
    default:
      throw OhttpFormatException('Unexpected varint prefix: ${first >> 6}');
  }
}

// ---------------------------------------------------------------------------
// BHTTP request serialization
// ---------------------------------------------------------------------------

/// Serialize an HTTP request into Known-Length BHTTP format (RFC 9292).
Uint8List serializeRequest({
  required String method,
  required String scheme,
  required String authority,
  required String path,
  required List<(String, String)> headers,
  required Uint8List body,
}) {
  final buf = BytesBuilder();

  // Framing indicator: 0 = known-length request
  buf.add(encodeVarint(0));

  // Request control data
  _writeField(buf, utf8.encode(method));
  _writeField(buf, utf8.encode(scheme));
  _writeField(buf, utf8.encode(authority));
  _writeField(buf, utf8.encode(path));

  // Header section (known-length)
  final headerBuf = BytesBuilder();
  for (final (name, value) in headers) {
    _writeField(headerBuf, utf8.encode(name.toLowerCase()));
    _writeField(headerBuf, utf8.encode(value));
  }
  final headerBytes = headerBuf.toBytes();
  buf.add(encodeVarint(headerBytes.length));
  buf.add(headerBytes);

  // Content (known-length)
  buf.add(encodeVarint(body.length));
  if (body.isNotEmpty) {
    buf.add(body);
  }

  // Trailers (empty)
  buf.add(encodeVarint(0));

  return buf.toBytes();
}

void _writeField(BytesBuilder buf, List<int> data) {
  buf.add(encodeVarint(data.length));
  buf.add(data);
}

// ---------------------------------------------------------------------------
// BHTTP response parsing
// ---------------------------------------------------------------------------

/// A parsed BHTTP response.
// ignore: prefer-match-file-name
class BhttpResponse {
  /// HTTP status code.
  final int statusCode;

  /// Response headers as name-value pairs, preserving insertion order.
  final List<(String, String)> headers;

  /// Raw response body bytes.
  final Uint8List body;

  /// Creates a parsed BHTTP response.
  BhttpResponse({
    required this.statusCode,
    required this.headers,
    required this.body,
  });
}

/// Parse a Known-Length BHTTP response (RFC 9292).
BhttpResponse parseResponse(Uint8List data) {
  try {
    var offset = 0;

    // Framing indicator
    final (framing, framingLen) = decodeVarint(data, offset);
    offset += framingLen;
    if (framing != 1) {
      throw OhttpFormatException(
        'Expected known-length response (framing=1), got $framing',
      );
    }

    // Skip informational responses (1xx)
    int statusCode;
    int statusLen;
    while (true) {
      (statusCode, statusLen) = decodeVarint(data, offset);
      offset += statusLen;

      if (statusCode >= 100 && statusCode < 200) {
        // Skip informational response header section
        final (hLen, hLenLen) = decodeVarint(data, offset);
        offset += hLenLen + hLen;
      } else {
        break;
      }
    }

    // Header section
    final (headersLen, headersLenLen) = decodeVarint(data, offset);
    offset += headersLenLen;
    final headersEnd = offset + headersLen;

    final headers = <(String, String)>[];
    while (offset < headersEnd) {
      final (nameLen, nameLenLen) = decodeVarint(data, offset);
      offset += nameLenLen;
      final name = utf8.decode(data.sublist(offset, offset + nameLen));
      offset += nameLen;

      final (valueLen, valueLenLen) = decodeVarint(data, offset);
      offset += valueLenLen;
      final value = utf8.decode(data.sublist(offset, offset + valueLen));
      offset += valueLen;

      headers.add((name, value));
    }

    // Content
    final (contentLen, contentLenLen) = decodeVarint(data, offset);
    offset += contentLenLen;
    final body = Uint8List.fromList(data.sublist(offset, offset + contentLen));

    return BhttpResponse(statusCode: statusCode, headers: headers, body: body);
  } on FormatException catch (e) {
    throw OhttpFormatException('Malformed BHTTP response: ${e.message}');
  } on RangeError catch (e) {
    throw OhttpFormatException('BHTTP response out of bounds: ${e.message}');
  }
}
