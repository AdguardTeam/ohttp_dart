import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:ohttp_dart/http.dart';
import 'package:ohttp_dart/ohttp_dart.dart';

import 'src/compare_view.dart';
import 'src/gateways.dart';
import 'src/log_entry.dart';
import 'src/log_observer.dart';
import 'src/log_panel.dart';
import 'src/path_defaults.dart';
import 'src/privacy_facts.dart';
import 'src/response_view.dart';

void main() {
  runApp(const OhttpApp());
}

class OhttpApp extends StatelessWidget {
  const OhttpApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'OHTTP Flutter Example',
      theme: ThemeData(colorScheme: ColorScheme.fromSeed(seedColor: Colors.teal), useMaterial3: true),
      home: const OhttpDemoPage(),
    );
  }
}

class OhttpDemoPage extends StatefulWidget {
  const OhttpDemoPage({super.key});

  @override
  State<OhttpDemoPage> createState() => _OhttpDemoPageState();
}

class _OhttpDemoPageState extends State<OhttpDemoPage> with SingleTickerProviderStateMixin {
  static const _methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
  static const _presetPaths = ['/headers', '/ip', '/status/500', '/delay/2', '/anything'];

  /// Smallest height the response tab section may take before the page
  /// starts scrolling vertically instead of squeezing it further.
  static const _minTabSectionHeight = 320.0;

  // Gateway presets
  static final _gateways = <String, ({HttpClientTransport Function(http.Client client) transport, String authority})>{
    'httpbin': (transport: httpbinTransport, authority: httpbinAuthority),
  };

  final _pathController = TextEditingController(text: methodDefaultPaths['GET']);
  final _bodyController = TextEditingController();
  String _method = 'GET';
  bool _loading = false;
  final List<LogEntry> _logEntries = [];
  OhttpResponseData? _ohttpResponse;
  OhttpResponseData? _directResponse;
  Duration? _ohttpElapsed;
  Duration? _directElapsed;

  late final TabController _tabController;
  late http.Client _rawClient;
  late KeyConfigCache _cache;
  late OhttpSession _session;
  String _authority = httpbinAuthority;
  String _selectedGateway = 'httpbin';
  bool _proxyEnabled = false;
  int _proxyPort = 9090;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 3, vsync: this);
    _initSession('httpbin');
  }

  void _initSession(String name) {
    final useLocal = localGatewayEnabled && _proxyEnabled;
    _rawClient = useLocal
        ? _createLocalGatewayClient()
        : _proxyEnabled
        ? _createProxiedClient('localhost:$_proxyPort')
        : http.Client();
    final entry = _gateways[name]!;
    _authority = entry.authority;
    final observer = LogObserver((level, message) => _addEntry(level, 'OHTTP', message));
    final transport = useLocal ? localGatewayTransport(_rawClient) : entry.transport(_rawClient);
    _cache = KeyConfigCache(transport: transport, observer: observer);
    _session = OhttpSession(transport: transport, cache: _cache, observer: observer);
  }

  // Accepts the self-signed cert generated at runtime by the local Go gateway.
  http.Client _createLocalGatewayClient() {
    final ioClient = HttpClient()..badCertificateCallback = (cert, host, port) => true;
    return IOClient(ioClient);
  }

  http.Client _createProxiedClient(String proxyUrl) {
    final ioClient = HttpClient()..findProxy = (uri) => 'PROXY $proxyUrl';
    if (kDebugMode) {
      ioClient.badCertificateCallback = (cert, host, port) => true;
    }
    return IOClient(ioClient);
  }

  @override
  void dispose() {
    _tabController.dispose();
    _pathController.dispose();
    _bodyController.dispose();
    _rawClient.close();
    super.dispose();
  }

  void _onGatewayChanged(String? name) {
    if (name == null) {
      return;
    }
    _rawClient.close();
    setState(() {
      _selectedGateway = name;
      _initSession(name);
      _ohttpResponse = null;
      _directResponse = null;
      _ohttpElapsed = null;
      _directElapsed = null;
      _logEntries.clear();
      _pathController.text = methodDefaultPaths[_method]!;
    });
  }

  void _onMethodChanged(String? method) {
    if (method == null) {
      return;
    }
    setState(() {
      _pathController.text = syncedPath(_pathController.text, method);
      _method = method;
    });
  }

  void _onProxyToggled(bool value) async {
    if (value) {
      final port = await _showProxyPortDialog();
      if (port == null) return;
      _proxyPort = port;
    }
    _rawClient.close();
    setState(() {
      _proxyEnabled = value;
      _initSession(_selectedGateway);
    });
    _addEntry(LogLevel.info, 'proxy', value ? 'Proxy enabled: localhost:$_proxyPort' : 'Proxy disabled');
  }

  Future<int?> _showProxyPortDialog() {
    final controller = TextEditingController(text: '$_proxyPort');
    return showDialog<int>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Proxy Port'),
        content: TextField(
          controller: controller,
          keyboardType: TextInputType.number,
          decoration: const InputDecoration(
            labelText: 'Port',
            hintText: '9090',
            border: OutlineInputBorder(),
            isDense: true,
          ),
          autofocus: true,
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          FilledButton(
            onPressed: () {
              final port = int.tryParse(controller.text);
              Navigator.pop(ctx, port);
            },
            child: const Text('Enable'),
          ),
        ],
      ),
    );
  }

  void _addEntry(LogLevel level, String source, String message) {
    if (!mounted) {
      return;
    }
    setState(() {
      _logEntries.add(LogEntry(time: DateTime.now(), level: level, source: source, message: message));
    });
  }

  bool get _hasBody => _method != 'GET' && _bodyController.text.isNotEmpty;

  Uint8List _ohttpBody() => _hasBody ? Uint8List.fromList(utf8.encode(_bodyController.text)) : Uint8List(0);

  Future<void> _sendOhttp() async {
    setState(() {
      _loading = true;
      _ohttpResponse = null;
      _ohttpElapsed = null;
    });

    try {
      final requestData = OhttpRequestData(
        method: _method,
        scheme: 'https',
        authority: _authority,
        path: _pathController.text,
        headers: [('accept', 'application/json'), if (_hasBody) ('content-type', 'application/json')],
        body: _ohttpBody(),
      );

      final stopwatch = Stopwatch()..start();
      final response = await _session.send(requestData);
      stopwatch.stop();

      if (!mounted) {
        return;
      }
      setState(() {
        _ohttpResponse = response;
        _ohttpElapsed = stopwatch.elapsed;
      });
      _addEntry(LogLevel.success, 'OHTTP', 'Done: HTTP ${response.statusCode}');
    } catch (e) {
      _addEntry(LogLevel.error, 'OHTTP', 'ERROR: $e');
    } finally {
      if (mounted) {
        setState(() {
          _loading = false;
        });
      }
    }
  }

  Future<void> _sendDirect() async {
    setState(() {
      _loading = true;
      _directResponse = null;
      _directElapsed = null;
    });

    try {
      _addEntry(LogLevel.info, 'direct', 'Sending direct request...');

      final uri = Uri.https(_authority, _pathController.text);
      final headers = <String, String>{'Accept': 'application/json', if (_hasBody) 'Content-Type': 'application/json'};
      final body = _hasBody ? _bodyController.text : null;

      final stopwatch = Stopwatch()..start();
      final response = switch (_method) {
        'GET' => await _rawClient.get(uri, headers: headers),
        'POST' => await _rawClient.post(uri, headers: headers, body: body),
        'PUT' => await _rawClient.put(uri, headers: headers, body: body),
        'PATCH' => await _rawClient.patch(uri, headers: headers, body: body),
        'DELETE' => await _rawClient.delete(uri, headers: headers, body: body),
        _ => throw StateError('Unsupported method: $_method'),
      };
      stopwatch.stop();

      final responseData = OhttpResponseData(
        statusCode: response.statusCode,
        body: response.bodyBytes,
        headers: response.headers.entries.map((e) => (e.key, e.value)).toList(),
      );

      if (!mounted) {
        return;
      }
      setState(() {
        _directResponse = responseData;
        _directElapsed = stopwatch.elapsed;
      });
      _addEntry(LogLevel.success, 'direct', 'Direct response: HTTP ${responseData.statusCode}');
    } catch (e) {
      _addEntry(LogLevel.error, 'direct', 'ERROR: $e');
    } finally {
      if (mounted) {
        setState(() {
          _loading = false;
        });
      }
    }
  }

  Future<void> _sendBoth() async {
    await _sendOhttp();
    if (!mounted) {
      return;
    }
    await _sendDirect();
    if (!mounted) {
      return;
    }
    _tabController.animateTo(2);
  }

  PrivacyFacts? _factsOf(OhttpResponseData? response) {
    if (response == null) return null;

    return extractPrivacyFacts(utf8.decode(response.body, allowMalformed: true));
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
        child: LayoutBuilder(
          builder: (context, viewport) => CustomScrollView(
            slivers: [
              SliverToBoxAdapter(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    // Gateway selector + key-rotation demo action
                    Row(
                      children: [
                        const Text('Gateway: ', style: TextStyle(fontWeight: FontWeight.bold)),
                        const SizedBox(width: 8),
                        DropdownButton<String>(
                          value: _selectedGateway,
                          items: _gateways.keys
                              .map((name) => DropdownMenuItem(value: name, child: Text(name)))
                              .toList(),
                          onChanged: _loading ? null : _onGatewayChanged,
                        ),
                        const Spacer(),
                        Text(_proxyEnabled ? 'Proxy :$_proxyPort' : 'Proxy'),
                        Switch(value: _proxyEnabled, onChanged: _loading ? null : _onProxyToggled),
                        IconButton(
                          icon: const Icon(Icons.key_off),
                          tooltip: 'Invalidate cached key config',
                          onPressed: _loading ? null : _cache.invalidate,
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),

                    // Method + Path row
                    Row(
                      children: [
                        DropdownButton<String>(
                          value: _method,
                          items: _methods.map((m) => DropdownMenuItem(value: m, child: Text(m))).toList(),
                          onChanged: _loading ? null : _onMethodChanged,
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

                    // Preset paths for demoing specific behaviors
                    SingleChildScrollView(
                      scrollDirection: Axis.horizontal,
                      child: Row(
                        children: [
                          for (final preset in _presetPaths) ...[
                            ActionChip(
                              label: Text(preset),
                              onPressed: _loading ? null : () => setState(() => _pathController.text = preset),
                            ),
                            const SizedBox(width: 8),
                          ],
                        ],
                      ),
                    ),
                    const SizedBox(height: 8),

                    // Body field (for methods that send one)
                    if (_method != 'GET') ...[
                      TextField(
                        controller: _bodyController,
                        decoration: const InputDecoration(
                          labelText: 'Request Body',
                          border: OutlineInputBorder(),
                          isDense: true,
                        ),
                        maxLines: 2,
                      ),
                      const SizedBox(height: 8),
                    ],

                    // Send buttons
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
                    const SizedBox(height: 8),
                    FilledButton.tonalIcon(
                      onPressed: _loading ? null : _sendBoth,
                      icon: const Icon(Icons.compare_arrows),
                      label: const Text('Send Both & Compare'),
                    ),

                    if (_loading)
                      const Padding(padding: EdgeInsets.symmetric(vertical: 8), child: LinearProgressIndicator()),

                    const SizedBox(height: 12),

                    if (_logEntries.isNotEmpty) ...[
                      LogPanel(entries: _logEntries, onClear: () => setState(_logEntries.clear)),
                      const SizedBox(height: 12),
                    ],
                  ],
                ),
              ),

              // Response tabs: fill the viewport space left below the controls,
              // but never shrink under a usable height — on short windows the
              // page scrolls instead.
              SliverLayoutBuilder(
                builder: (context, constraints) {
                  final tabHeight = math.max(
                    _minTabSectionHeight,
                    viewport.maxHeight - constraints.precedingScrollExtent,
                  );
                  return SliverToBoxAdapter(
                    child: SizedBox(
                      height: tabHeight,
                      child: Column(
                        children: [
                          TabBar(
                            controller: _tabController,
                            tabs: const [
                              Tab(text: 'OHTTP Response'),
                              Tab(text: 'Direct Response'),
                              Tab(text: 'Compare'),
                            ],
                          ),
                          Expanded(
                            child: TabBarView(
                              controller: _tabController,
                              children: [
                                ResponseView(response: _ohttpResponse, elapsed: _ohttpElapsed),
                                ResponseView(response: _directResponse, elapsed: _directElapsed),
                                CompareView(ohttp: _factsOf(_ohttpResponse), direct: _factsOf(_directResponse)),
                              ],
                            ),
                          ),
                        ],
                      ),
                    ),
                  );
                },
              ),
            ],
          ),
        ),
      ),
    );
  }
}
