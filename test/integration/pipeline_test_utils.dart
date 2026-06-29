import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart';
import 'package:http/testing.dart';
import 'package:ohttp_dart/ohttp_dart.dart';
import 'package:ohttp_dart/src/cipher_suite.dart';

import '../stubs/gateway_stub.dart';
import '../test_utils.dart';

// ---------------------------------------------------------------------------
// Test observer — records which lifecycle events fired (safe fields only).
// Never captures keys, nonces, shared secrets, or plaintext bodies.
// ---------------------------------------------------------------------------

final class PipelineTestObserver extends OhttpObserver {
  bool keyConfigFetched = false;
  bool keyConfigCacheHit = false;
  bool postToGateway = false;
  bool gatewayError = false;
  bool cacheInvalidated = false;
  bool decapsulationError = false;
  bool encapsulationError = false;
  int? lastGatewayErrorStatus;
  Type? lastDecapsulationErrorType;
  Type? lastEncapsulationErrorType;

  @override
  void onKeyConfigFetched() => keyConfigFetched = true;

  @override
  void onKeyConfigCacheHit() => keyConfigCacheHit = true;

  @override
  void onPostToGateway() => postToGateway = true;

  @override
  void onGatewayError(int statusCode) {
    gatewayError = true;
    lastGatewayErrorStatus = statusCode;
  }

  @override
  void onCacheInvalidated() => cacheInvalidated = true;

  @override
  void onDecapsulationError(Type errorType) {
    decapsulationError = true;
    lastDecapsulationErrorType = errorType;
  }

  @override
  void onEncapsulationError(Type errorType) {
    encapsulationError = true;
    lastEncapsulationErrorType = errorType;
  }
}

// ---------------------------------------------------------------------------
// Test constants — http:// URLs require HttpClientTransport.insecureForTesting.
// ---------------------------------------------------------------------------

const testKeysUrl = 'http://test.local/keys';
const testGatewayUrl = 'http://test.local/gateway';

// ---------------------------------------------------------------------------
// MockClient builder
// ---------------------------------------------------------------------------

/// Returns a [MockClient] routing:
///   GET  [testKeysUrl]    → 200, body = [keyConfigBytes]
///   POST [testGatewayUrl] → [gatewayHandler](request)
MockClient buildMockClient({
  required Uint8List keyConfigBytes,
  required Future<Response> Function(Request) gatewayHandler,
}) => MockClient((request) async {
  if (request.method == 'GET' && request.url.toString() == testKeysUrl) {
    return Response.bytes(keyConfigBytes, 200);
  }
  if (request.method == 'POST' && request.url.toString() == testGatewayUrl) {
    return gatewayHandler(request);
  }

  return Response('Not found', 404);
});

// ---------------------------------------------------------------------------
// BHTTP helper — builds a minimal Known-Length 200 response (RFC 9292 §3.2).
// framing(1) || status(200) || hdrSectionLen(0) || bodyLen || body || trailerLen(0)
// ---------------------------------------------------------------------------

Uint8List buildBhttpResponse(List<int> body) {
  final buf = BytesBuilder()
    ..add(encodeVarint(1)) // framing indicator: 1 = known-length response
    ..add(encodeVarint(200)) // status code
    ..add(encodeVarint(0)) // header section length = 0
    ..add(encodeVarint(body.length)) // body length
    ..add(body) // body bytes
    ..add(encodeVarint(0)); // trailer section length = 0

  return Uint8List.fromList(buf.toBytes());
}

// Builds a Known-Length 200 BHTTP response (RFC 9292 §3.2) with named headers.
// Each field line: nameLen(varint) || name || valueLen(varint) || value.
Uint8List buildBhttpResponseWithHeaders(List<int> body, List<(String, String)> headers) {
  final headerBuf = BytesBuilder();
  for (final (name, value) in headers) {
    final nameBytes = utf8.encode(name);
    final valueBytes = utf8.encode(value);
    headerBuf
      ..add(encodeVarint(nameBytes.length))
      ..add(nameBytes)
      ..add(encodeVarint(valueBytes.length))
      ..add(valueBytes);
  }
  final headerBytes = headerBuf.toBytes();

  final buf = BytesBuilder()
    ..add(encodeVarint(1)) // framing indicator
    ..add(encodeVarint(200)) // status code
    ..add(encodeVarint(headerBytes.length))
    ..add(headerBytes)
    ..add(encodeVarint(body.length))
    ..add(body)
    ..add(encodeVarint(0)); // trailer section length = 0

  return Uint8List.fromList(buf.toBytes());
}

// ---------------------------------------------------------------------------
// Shared gateway handler — KEM decap + seal canned BHTTP response.
// ---------------------------------------------------------------------------

Future<Response> gatewayHandlerFor(Request request, Uint8List bhttpResponseBytes) async {
  final postBody = request.bodyBytes;
  final exportedSecret = await decapExportedSecret(postBody);
  final enc = postBody.sublist(ohttpHeaderLen, ohttpHeaderLen + CipherSuite.kemPublicKeyLength);
  final encResponse = await sealBhttpResponse(enc, exportedSecret, bhttpResponseBytes);

  return Response.bytes(encResponse, 200);
}

// Shorthand for the default KeyConfig used by most tests:
// DHKEM(X25519) + HKDF-SHA256 + AES-128-GCM against the fixed gateway key.
Uint8List defaultKeyConfigBytes() => multiSuiteKeyConfig(
  publicKey: gatewayPublicKeyBytes,
  suiteIds: [(0x0001, 0x0001)],
);
