import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:ohttp_flutter_example/src/json_highlighter.dart';

void main() {
  const colors = JsonHighlightColors.light;

  List<TextSpan> flatten(TextSpan root) {
    final result = <TextSpan>[];
    void visit(InlineSpan span) {
      if (span is TextSpan) {
        if (span.text != null) {
          result.add(span);
        }
        span.children?.forEach(visit);
      }
    }

    visit(root);

    return result;
  }

  Color? colorOf(TextSpan root, String text) =>
      flatten(root).firstWhere((s) => s.text == text).style?.color;

  test('formats nested JSON with 2-space indentation', () {
    final span = highlightJson('{"a":{"b":[1,true,null]},"c":"x"}', colors);
    expect(
      span.toPlainText(),
      '{\n'
      '  "a": {\n'
      '    "b": [\n'
      '      1,\n'
      '      true,\n'
      '      null\n'
      '    ]\n'
      '  },\n'
      '  "c": "x"\n'
      '}',
    );
  });

  test('colors keys, strings, numbers, and literals distinctly', () {
    final span = highlightJson('{"k":"v","n":7,"t":true,"z":null}', colors);
    expect(colorOf(span, '"k"'), colors.key);
    expect(colorOf(span, '"v"'), colors.string);
    expect(colorOf(span, '7'), colors.number);
    expect(colorOf(span, 'true'), colors.literal);
    expect(colorOf(span, 'null'), colors.literal);
  });

  test('escapes string values', () {
    final span = highlightJson('{"s":"a\\"b"}', colors);
    expect(span.toPlainText(), contains(r'"a\"b"'));
  });

  test('renders empty containers inline', () {
    expect(highlightJson('{}', colors).toPlainText(), '{}');
    expect(highlightJson('[]', colors).toPlainText(), '[]');
  });

  test('falls back to a single plain span for invalid JSON', () {
    final span = highlightJson('not json at all', colors);
    expect(span.children, isNull);
    expect(span.style, isNull);
    expect(span.text, 'not json at all');
  });
}
