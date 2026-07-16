import 'package:flutter_test/flutter_test.dart';
import 'package:ohttp_flutter_example/src/path_defaults.dart';

void main() {
  test('swaps one method default for another', () {
    expect(syncedPath('/get', 'POST'), '/post');
    expect(syncedPath('/post', 'DELETE'), '/delete');
    expect(syncedPath('/patch', 'GET'), '/get');
  });

  test('keeps a custom path untouched', () {
    expect(syncedPath('/status/500', 'POST'), '/status/500');
    expect(syncedPath('/anything', 'PUT'), '/anything');
    expect(syncedPath('', 'POST'), '');
  });

  test('keeps the path when switching to the same method', () {
    expect(syncedPath('/get', 'GET'), '/get');
  });

  test('has a default path for every supported method', () {
    expect(methodDefaultPaths.keys, ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
    for (final entry in methodDefaultPaths.entries) {
      expect(syncedPath('/get', entry.key), entry.value);
    }
  });
}
