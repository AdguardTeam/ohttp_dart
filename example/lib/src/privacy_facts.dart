import 'dart:convert';

/// What the target server could observe about one request, extracted from
/// the httpbin-style echo response body.
class PrivacyFacts {
  final String? ip;
  final String? country;
  final String? userAgent;
  final int headerCount;
  final bool fingerprintPresent;

  const PrivacyFacts({
    required this.ip,
    required this.country,
    required this.userAgent,
    required this.headerCount,
    required this.fingerprintPresent,
  });
}

/// Parses the gateway target's echo JSON into [PrivacyFacts].
///
/// Understands two echo shapes:
/// - the worker's custom one (`/get`): a `headers` list of `[name, value]`
///   pairs plus top-level `ip`, `country`, and `cf` fields;
/// - the classic httpbin one (`/anything`, httpbin.org): a `headers` map of
///   name to value (string or list of strings), with client info in `origin`
///   and the echoed `Cf-connecting-ip` / `Cf-ipcountry` headers.
///
/// Returns `null` when [body] is not valid JSON or matches neither shape.
PrivacyFacts? extractPrivacyFacts(String body) {
  final Object? decoded;
  try {
    decoded = jsonDecode(body);
  } on FormatException {
    return null;
  }
  if (decoded is! Map<String, dynamic>) {
    return null;
  }
  return switch (decoded['headers']) {
    final List headers => _fromPairListEcho(decoded, headers),
    final Map<String, dynamic> headers => _fromClassicEcho(decoded, headers),
    _ => null,
  };
}

PrivacyFacts _fromPairListEcho(Map<String, dynamic> decoded, List headers) {
  String? userAgent;
  var headerCount = 0;
  for (final header in headers) {
    if (header is! List || header.length < 2) {
      continue;
    }
    headerCount++;
    if ('${header[0]}'.toLowerCase() == 'user-agent') {
      userAgent = '${header[1]}';
    }
  }

  final ip = decoded['ip'];
  final country = decoded['country'];

  return PrivacyFacts(
    ip: ip is String ? ip : null,
    country: country is String ? country : null,
    userAgent: userAgent,
    headerCount: headerCount,
    fingerprintPresent: decoded['cf'] is Map,
  );
}

PrivacyFacts _fromClassicEcho(
  Map<String, dynamic> decoded,
  Map<String, dynamic> headers,
) {
  String? userAgent;
  String? ipHeader;
  String? country;
  var headerCount = 0;
  for (final entry in headers.entries) {
    final value = entry.value;
    final values = value is List ? value : [value];
    headerCount += values.length;
    if (values.isEmpty) {
      continue;
    }
    final first = '${values.first}';
    switch (entry.key.toLowerCase()) {
      case 'user-agent':
        userAgent = first;
      case 'cf-connecting-ip':
        ipHeader = first;
      case 'x-real-ip':
        ipHeader ??= first;
      case 'cf-ipcountry':
        country = first;
    }
  }

  final origin = decoded['origin'];

  return PrivacyFacts(
    ip: origin is String && origin.isNotEmpty ? origin : ipHeader,
    country: country,
    userAgent: userAgent,
    headerCount: headerCount,
    fingerprintPresent: decoded['cf'] is Map,
  );
}
