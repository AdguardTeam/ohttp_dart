/// Default echo path for each HTTP method supported by the httpbin-style
/// gateway target (verified live against httpbin.agrd.workers.dev).
const methodDefaultPaths = <String, String>{
  'GET': '/get',
  'POST': '/post',
  'PUT': '/put',
  'PATCH': '/patch',
  'DELETE': '/delete',
};

/// Returns the path to use after switching to [newMethod].
///
/// Replaces [currentPath] only when it is itself one of the method defaults
/// (i.e. the user has not typed a custom path); custom paths like
/// `/status/500` are returned unchanged.
String syncedPath(String currentPath, String newMethod) {
  if (!methodDefaultPaths.values.contains(currentPath)) {
    return currentPath;
  }

  return methodDefaultPaths[newMethod] ?? currentPath;
}
