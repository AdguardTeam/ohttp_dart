// ignore_for_file: avoid_print

import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:ohttp_dart/http.dart';
import 'package:ohttp_dart/ohttp_dart.dart';

Future<void> main() async {
  // ---------------------------------------------------------------------------
  // 1. Quick-start: OhttpHttpClient (drop-in http.Client replacement)
  // ---------------------------------------------------------------------------

  final raw = http.Client();
  final transport = HttpClientTransport(
    client: raw,
    keysUrl: Uri.parse('https://gateway.example.com/ohttp/config'),
    gatewayUrl: Uri.parse('https://gateway.example.com/ohttp/gateway'),
  );
  final session = OhttpSession.withTransport(transport: transport);
  final client = OhttpHttpClient(session: session, closeWith: raw);

  final response = await client.get(Uri.https('target.example.com', '/api/data'));
  print('OhttpHttpClient: ${response.statusCode}');

  client.close();

  // ---------------------------------------------------------------------------
  // 2. Low-level: OhttpSession.send (for Dio or custom adapters)
  // ---------------------------------------------------------------------------

  final lowLevelSession = OhttpSession.withTransport(transport: transport);
  final requestData = OhttpRequestData(
    method: 'GET',
    scheme: 'https',
    authority: 'target.example.com',
    path: '/api/data',
    headers: [('accept', 'application/json')],
    body: Uint8List(0),
  );
  final responseData = await lowLevelSession.send(requestData);
  print('OhttpSession.send: ${responseData.statusCode}');
}
