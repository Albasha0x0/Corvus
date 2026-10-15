'use strict';
var counter = 0;
function add(a, b) { return a + b; }
function greet(name) {
  if (name === undefined) { name = "world"; }
  counter++;
  return "Hello, " + name + "!";
}
var obj = { x: 1, y: "two", z: [1, 2, 3], nested: { flag: true } };
function loop(n) {
  var sum = 0;
  for (var i = 0; i < n; i++) {
    if (i % 2 === 0) continue;
    sum += i * 2;
  }
  while (sum > 100) { sum = sum - 7; }
  return sum;
}
function tryIt(f) {
  try { return f(); } catch (e) { print("error: " + e.message); return null; } finally { counter--; }
}
function makeCounter() {
  var c = 0;
  return function () { c += 1; return c; };
}
var re = /ab+c/gi;
var big = 12345678901234567890;
function sw(x) {
  switch (x) { case 1: return "one"; case 2: return "two"; case 3: return "three"; case 4: return "four"; default: return "many"; }
}
var arrow = (p) => p * 3;
function cls() {
  var o = new Date();
  delete obj.x;
  return typeof o + (o instanceof Date) + ("x" in obj);
}
function api() {
  fetch("https://api.example.com/v1/login", { method: "POST", body: JSON.stringify({ user: "u" }) });
}
print(add(1, 2), greet(), loop(10), tryIt(function () { throw new Error("x"); }), makeCounter()(), sw(3), arrow(2), cls(), re.test("abbc"), big);
