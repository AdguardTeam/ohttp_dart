import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:ohttp_dart/ohttp_dart.dart';
import 'package:ohttp_dart/http.dart';

import 'src/gateways.dart';
import 'src/log_observer.dart';

void main() {
  runApp(const OhttpApp());
}

class OhttpApp extends StatelessWidget {
  const OhttpApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'OHTTP Flutter Example',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.teal),
        useMaterial3: true,
      ),
      home: const OhttpDemoPage(),
    );
  }
}

class OhttpDemoPage extends StatefulWidget {
  const OhttpDemoPage({super.key});

  @override
  State<OhttpDemoPage> createState() => _OhttpDemoPageState();
}

class _OhttpDemoPageState extends State<OhttpDemoPage> {
  final _pathController = TextEditingController(text: '/get');
  final _bodyController = TextEditingController();
  String _method = 'GET';
  bool _loading = false;
  final List<String> _logs = [];
  OhttpResponseData? _ohttpResponse;
  OhttpResponseData? _directResponse;

  late http.Client _rawClient;
  late OhttpSession _session;
  String _authority = httpbinAuthority;

  // Gateway presets
  static final _gateways =
      <
        String,
        ({
          HttpClientTransport Function(http.Client client) transport,
          String authority,
        })
      >{
        'httpbin': (transport: httpbinTransport, authority: httpbinAuthority),
        'PIR Gateway': (
          transport: pirGatewayTransport,
          authority: pirGatewayAuthority,
        ),
      };
  String _selectedGateway = 'httpbin';

  @override
  void initState() {
    super.initState();
    _initSession('httpbin');
  }

  void _initSession(String name) {
    _rawClient = http.Client();
    final entry = _gateways[name]!;
    _authority = entry.authority;
    final observer = LogObserver(_logs);
    _session = OhttpSession.withTransport(
      transport: entry.transport(_rawClient),
      observer: observer,
    );
  }

  @override
  void dispose() {
    _pathController.dispose();
    _bodyController.dispose();
    _rawClient.close();
    super.dispose();
  }

  void _onGatewayChanged(String? name) {
    if (name == null) return;
    _rawClient.close();
    setState(() {
      _selectedGateway = name;
      _initSession(name);
      _ohttpResponse = null;
      _directResponse = null;
      _logs.clear();
      // Set sensible default path for each gateway
      if (name == 'httpbin') {
        _pathController.text = '/get';
      } else if (name == 'PIR Gateway') {
        _pathController.text = '/.well-known/private-token-issuer-directory';
      }
    });
  }

  void _addLog(String msg) {
    setState(() {
      _logs.add('[${DateTime.now().toIso8601String().substring(11, 19)}] $msg');
    });
  }

  Future<void> _sendOhttp() async {
    setState(() {
      _loading = true;
      _logs.clear();
      _ohttpResponse = null;
    });

    try {
      final body = _method != 'GET' && _bodyController.text.isNotEmpty
          ? Uint8List.fromList(utf8.encode(_bodyController.text))
          : Uint8List(0);

      final headers = <(String, String)>[('accept', 'application/json')];

      final requestData = OhttpRequestData(
        method: _method,
        scheme: 'https',
        authority: _authority,
        path: _pathController.text,
        headers: headers,
        body: body,
      );

      final response = await _session.send(requestData);

      setState(() {
        _ohttpResponse = response;
      });
      _addLog('Done!');
    } catch (e) {
      _addLog('ERROR: $e');
    } finally {
      setState(() {
        _loading = false;
      });
    }
  }

  Future<void> _sendDirect() async {
    setState(() {
      _loading = true;
      _logs.clear();
      _directResponse = null;
    });

    try {
      _addLog('Sending direct request...');

      final uri = Uri.https(_authority, _pathController.text);

      http.Response response;
      final headers = <String, String>{'Accept': 'application/json'};
      final body = _method != 'GET' && _bodyController.text.isNotEmpty
          ? _bodyController.text
          : null;

      switch (_method) {
        case 'GET':
          response = await _rawClient.get(uri, headers: headers);
        case 'POST':
          response = await _rawClient.post(uri, headers: headers, body: body);
        case 'PUT':
          response = await _rawClient.put(uri, headers: headers, body: body);
        case 'DELETE':
          response = await _rawClient.delete(uri, headers: headers);
        default:
          response = await _rawClient.get(uri, headers: headers);
      }

      final responseData = OhttpResponseData(
        statusCode: response.statusCode,
        body: response.bodyBytes,
        headers: response.headers.entries.map((e) => (e.key, e.value)).toList(),
      );

      setState(() {
        _directResponse = responseData;
      });
      _addLog('Direct response: HTTP ${responseData.statusCode}');
    } catch (e) {
      _addLog('ERROR: $e');
    } finally {
      setState(() {
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('OHTTP Flutter Demo'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
      ),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Gateway selector
            Row(
              children: [
                const Text(
                  'Gateway: ',
                  style: TextStyle(fontWeight: FontWeight.bold),
                ),
                const SizedBox(width: 8),
                DropdownButton<String>(
                  value: _selectedGateway,
                  items: _gateways.keys
                      .map(
                        (name) =>
                            DropdownMenuItem(value: name, child: Text(name)),
                      )
                      .toList(),
                  onChanged: _loading ? null : _onGatewayChanged,
                ),
              ],
            ),
            const SizedBox(height: 8),

            // Method + Path row
            Row(
              children: [
                DropdownButton<String>(
                  value: _method,
                  items: ['GET', 'POST', 'PUT', 'DELETE']
                      .map((m) => DropdownMenuItem(value: m, child: Text(m)))
                      .toList(),
                  onChanged: (v) => setState(() => _method = v!),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: TextField(
                    controller: _pathController,
                    decoration: const InputDecoration(
                      labelText: 'Path',
                      hintText: '/get',
                      border: OutlineInputBorder(),
                      isDense: true,
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),

            // Body field (for POST)
            if (_method != 'GET')
              TextField(
                controller: _bodyController,
                decoration: const InputDecoration(
                  labelText: 'Request Body',
                  border: OutlineInputBorder(),
                  isDense: true,
                ),
                maxLines: 2,
              ),
            if (_method != 'GET') const SizedBox(height: 8),

            // Buttons
            Row(
              children: [
                Expanded(
                  child: ElevatedButton.icon(
                    onPressed: _loading ? null : _sendOhttp,
                    icon: const Icon(Icons.lock),
                    label: const Text('Send via OHTTP'),
                  ),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: _loading ? null : _sendDirect,
                    icon: const Icon(Icons.send),
                    label: const Text('Send Direct'),
                  ),
                ),
              ],
            ),

            if (_loading)
              const Padding(
                padding: EdgeInsets.symmetric(vertical: 8),
                child: LinearProgressIndicator(),
              ),

            const SizedBox(height: 12),

            // Logs
            if (_logs.isNotEmpty) ...[
              const Text('Log:', style: TextStyle(fontWeight: FontWeight.bold)),
              Container(
                height: 100,
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: Colors.grey[100],
                  borderRadius: BorderRadius.circular(4),
                ),
                child: ListView(
                  children: _logs
                      .map(
                        (l) => Text(
                          l,
                          style: const TextStyle(
                            fontSize: 11,
                            fontFamily: 'monospace',
                          ),
                        ),
                      )
                      .toList(),
                ),
              ),
              const SizedBox(height: 12),
            ],

            // Response
            Expanded(
              child: DefaultTabController(
                length: 2,
                child: Column(
                  children: [
                    const TabBar(
                      tabs: [
                        Tab(text: 'OHTTP Response'),
                        Tab(text: 'Direct Response'),
                      ],
                    ),
                    Expanded(
                      child: TabBarView(
                        children: [
                          _buildResponseView(_ohttpResponse),
                          _buildResponseView(_directResponse),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildResponseView(OhttpResponseData? response) {
    if (response == null) {
      return const Center(child: Text('No response yet'));
    }

    final bodyStr = utf8.decode(response.body, allowMalformed: true);
    String formattedBody;
    try {
      final json = jsonDecode(bodyStr);
      formattedBody = const JsonEncoder.withIndent('  ').convert(json);
    } catch (_) {
      formattedBody = bodyStr;
    }

    return SingleChildScrollView(
      padding: const EdgeInsets.all(8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Status: ${response.statusCode}',
            style: TextStyle(
              fontWeight: FontWeight.bold,
              color: response.statusCode < 400 ? Colors.green : Colors.red,
            ),
          ),
          const SizedBox(height: 4),
          const Text('Headers:', style: TextStyle(fontWeight: FontWeight.bold)),
          ...response.headers.map(
            (h) => Text(
              '  ${h.$1}: ${h.$2}',
              style: const TextStyle(fontSize: 12, fontFamily: 'monospace'),
            ),
          ),
          const SizedBox(height: 8),
          const Text('Body:', style: TextStyle(fontWeight: FontWeight.bold)),
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: Colors.grey[50],
              borderRadius: BorderRadius.circular(4),
              border: Border.all(color: Colors.grey[300]!),
            ),
            child: SelectableText(
              formattedBody,
              style: const TextStyle(fontSize: 12, fontFamily: 'monospace'),
            ),
          ),
        ],
      ),
    );
  }
}
