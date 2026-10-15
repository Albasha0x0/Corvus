var __d = function (factory, id, deps) { modules[id] = { factory: factory, deps: deps }; };
var __r = function (id) { var m = modules[id]; var exports = {}; m.factory(globalThis, __r, null, null, { exports: exports }, exports, m.deps); return exports; };
var modules = {};
__d(function (global, _$$_REQUIRE, _$$_IMPORT_DEFAULT, _$$_IMPORT_ALL, module, exports, _dependencyMap) {
  var api = _$$_REQUIRE(_dependencyMap[0]);
  exports.login = function login(user, password) {
    return api.post('/v1/login', { user: user, password: password });
  };
}, 0, [1]);
__d(function (global, _$$_REQUIRE, _$$_IMPORT_DEFAULT, _$$_IMPORT_ALL, module, exports, _dependencyMap) {
  exports.post = function post(path, body) {
    return fetch('https://api.example.com' + path, { method: 'POST', body: JSON.stringify(body) });
  };
}, 1, []);
__r(0);
