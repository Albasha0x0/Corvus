'use strict';
function* range(n) {
  for (var i = 0; i < n; i++) yield i;
}
async function load(url) {
  var response = await fetch(url, { headers: { Accept: 'application/json' } });
  if (!response.ok) throw new Error('HTTP ' + response.status);
  return await response.json();
}
function spread(a, b) {
  var all = [...a, ...b];
  var copy = Object.assign({}, { k: 1 }, a);
  return all.length + Object.keys(copy).length;
}
function forIn(o) {
  var keys = [];
  for (var k in o) { if (o.hasOwnProperty(k)) keys.push(k); }
  return keys;
}
function forOf(list) {
  var total = 0;
  for (var x of list) total += x;
  return total;
}
function template(user) {
  return `Hi ${user.name}, you have ${user.count} messages`;
}
function bits(x) { return (x << 3) ^ (x >>> 1) | ~x & 0xff; }
function nested(a) {
  outer: for (var i = 0; i < a.length; i++) {
    for (var j = 0; j < a[i].length; j++) {
      if (a[i][j] < 0) continue outer;
      if (a[i][j] > 100) break outer;
    }
  }
  return i;
}
function big(i) {
  switch (i) {
    case 0: return 'a'; case 1: return 'b'; case 2: return 'c'; case 3: return 'd';
    case 4: return 'e'; case 5: return 'f'; case 6: return 'g'; case 7: return 'h';
    case 8: return 'i'; case 9: return 'j'; case 10: return 'k'; default: return 'z';
  }
}
var api = { token: 'secret-token-123', endpoint: 'https://api.example.com/v2/items' };
print(Array.from(range(3)), spread([1], [2]), forIn({ a: 1 }), forOf([1, 2]), template({ name: 'n', count: 2 }), bits(5), nested([[1]]), big(4), load, api);
