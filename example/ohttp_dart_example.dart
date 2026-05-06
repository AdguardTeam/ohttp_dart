// ignore_for_file: avoid_print

import 'dart:convert';

import 'package:ohttp_dart/ohttp_dart.dart';

void main() async {
  final client = OhttpClient(
    gateway: const OhttpGatewayConfig(
      gatewayBaseUrl: 'https://your-gateway.example.com',
      configPath: '/ohttp/config',
      requestPath: '/ohttp/gateway',
      targetAuthority: 'your-gateway.example.com',
    ),
  );

  // Send a GET request through OHTTP
  final response = await client.send(
    method: 'GET',
    path: '/get',
    headers: {'Accept': 'application/json'},
    onLog: print,
  );
  print('GET ${response.statusCode}: ${utf8.decode(response.body)}');

  // Send a POST request through OHTTP
  final postResponse = await client.send(
    method: 'POST',
    path: '/post',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: utf8.encode('{"hello": "ohttp"}'),
    onLog: print,
  );
  print('POST ${postResponse.statusCode}: ${utf8.decode(postResponse.body)}');
}
