import 'dart:convert';

import 'package:flutter/material.dart';

/// Color palette for [highlightJson], keyed off theme brightness.
class JsonHighlightColors {
  final Color key;
  final Color string;
  final Color number;
  final Color literal;
  final Color punctuation;

  const JsonHighlightColors({
    required this.key,
    required this.string,
    required this.number,
    required this.literal,
    required this.punctuation,
  });

  /// Palette for light backgrounds.
  static const light = JsonHighlightColors(
    key: Color(0xFF3949AB), // indigo 600
    string: Color(0xFF2E7D32), // green 800
    number: Color(0xFFEF6C00), // orange 800
    literal: Color(0xFF6A1B9A), // purple 800
    punctuation: Color(0xFF616161), // grey 700
  );

  /// Palette for dark backgrounds.
  static const dark = JsonHighlightColors(
    key: Color(0xFF9FA8DA), // indigo 200
    string: Color(0xFFA5D6A7), // green 200
    number: Color(0xFFFFCC80), // orange 200
    literal: Color(0xFFCE93D8), // purple 200
    punctuation: Color(0xFFBDBDBD), // grey 400
  );

  static JsonHighlightColors of(Brightness brightness) =>
      brightness == Brightness.dark ? dark : light;
}

/// Builds a syntax-highlighted [TextSpan] for [raw].
///
/// When [raw] is not valid JSON, the whole string is returned as a single
/// unstyled span so the caller's base style applies.
TextSpan highlightJson(String raw, JsonHighlightColors colors) {
  final Object? decoded;
  try {
    decoded = jsonDecode(raw);
  } on FormatException {
    return TextSpan(text: raw);
  }

  final spans = <TextSpan>[];
  _writeValue(decoded, 0, spans, colors);

  return TextSpan(children: spans);
}

TextSpan _punct(String text, JsonHighlightColors colors) => TextSpan(
  text: text,
  style: TextStyle(color: colors.punctuation),
);

void _writeValue(
  Object? value,
  int indent,
  List<TextSpan> spans,
  JsonHighlightColors colors,
) {
  switch (value) {
    case final Map<String, dynamic> map:
      _writeMap(map, indent, spans, colors);
    case final List<dynamic> list:
      _writeList(list, indent, spans, colors);
    case final String string:
      spans.add(
        TextSpan(
          text: jsonEncode(string),
          style: TextStyle(color: colors.string),
        ),
      );
    case final num number:
      spans.add(
        TextSpan(
          text: '$number',
          style: TextStyle(color: colors.number),
        ),
      );
    case final bool boolean:
      spans.add(
        TextSpan(
          text: '$boolean',
          style: TextStyle(color: colors.literal),
        ),
      );
    case null:
      spans.add(
        TextSpan(
          text: 'null',
          style: TextStyle(color: colors.literal),
        ),
      );
    default:
      spans.add(TextSpan(text: '$value'));
  }
}

void _writeMap(
  Map<String, dynamic> map,
  int indent,
  List<TextSpan> spans,
  JsonHighlightColors colors,
) {
  if (map.isEmpty) {
    spans.add(_punct('{}', colors));

    return;
  }

  final pad = '  ' * indent;
  spans.add(_punct('{\n', colors));
  final entries = map.entries.toList();
  for (var i = 0; i < entries.length; i++) {
    spans
      ..add(_punct('$pad  ', colors))
      ..add(
        TextSpan(
          text: jsonEncode(entries[i].key),
          style: TextStyle(color: colors.key),
        ),
      )
      ..add(_punct(': ', colors));
    _writeValue(entries[i].value, indent + 1, spans, colors);
    spans.add(_punct(i < entries.length - 1 ? ',\n' : '\n', colors));
  }
  spans.add(_punct('$pad}', colors));
}

void _writeList(
  List<dynamic> list,
  int indent,
  List<TextSpan> spans,
  JsonHighlightColors colors,
) {
  if (list.isEmpty) {
    spans.add(_punct('[]', colors));

    return;
  }

  final pad = '  ' * indent;
  spans.add(_punct('[\n', colors));
  for (var i = 0; i < list.length; i++) {
    spans.add(_punct('$pad  ', colors));
    _writeValue(list[i], indent + 1, spans, colors);
    spans.add(_punct(i < list.length - 1 ? ',\n' : '\n', colors));
  }
  spans.add(_punct('$pad]', colors));
}
