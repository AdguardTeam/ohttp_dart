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
/// Returns `null` when [body] is not valid JSON or does not have the echo
/// shape (a top-level object with a `headers` list of `[name, value]` pairs).
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
  final headers = decoded['headers'];
  if (headers is! List) {
    return null;
  }

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
