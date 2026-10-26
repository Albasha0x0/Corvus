// Prints one line per check; build.js minifies this file into program.min.js with terser.
"use strict";

const path = require("path");
const out = [];
const log = (...parts) => out.push(parts.join(" "));

function counter(start) {
  let count = start;
  return {
    next() { return ++count; },
    reset: function () { count = start; return count; },
  };
}

function shadow(value) {
  const result = [];
  {
    const value = 10;
    result.push(value);
  }
  for (let i = 0; i < 3; i++) {
    const value = i * 2;
    result.push(value);
  }
  result.push(value);
  return result.join(",");
}

function hoisted() {
  const before = typeof later;
  function later() { return "later"; }
  var late = later();
  return before + ":" + late;
}

function destructure(options) {
  const { name, size = 4, nested: { depth } = { depth: 1 }, ...rest } = options;
  const [first, , third = "c", ...others] = name.split("");
  return [name, size, depth, Object.keys(rest).join("+"), first, third, others.length].join("|");
}

function shorthand(alpha, beta) {
  const gamma = alpha + beta;
  return JSON.stringify({ alpha, beta, gamma, sum() { return alpha + beta + gamma; } }) + ({ alpha, beta, gamma }).sum;
}

function errors(input) {
  try {
    if (input < 0) throw new RangeError("negative " + input);
    return "ok " + input;
  } catch (error) {
    return error.name + ": " + error.message;
  } finally {
    log("finally", input);
  }
}

class Account {
  #balance = 0;
  static created = 0;
  constructor(owner, opening) {
    this.owner = owner;
    this.#balance = opening;
    Account.created++;
  }
  deposit(amount) { this.#balance += amount; return this; }
  get balance() { return this.#balance; }
  static describe(account) { return `${account.owner}: ${account.balance.toFixed(2)} of ${Account.created}`; }
}

function closures() {
  const makers = [];
  for (let i = 0; i < 3; i++) makers.push(() => i * i);
  var total = 0;
  makers.forEach(function (make, index) { total += make() + index; });
  return makers.map((make) => make()).join(",") + "=" + total;
}

function labels(rows) {
  let found = -1;
  outer: for (let r = 0; r < rows.length; r++) {
    for (let c = 0; c < rows[r].length; c++) {
      if (rows[r][c] === 0) { found = r * 10 + c; break outer; }
    }
  }
  return found;
}

function asi(a, b) {
  let x = a
  let y = b
  const z = x
  ;[x, y] = [y, x]
  return x - y + z
}

function regexAndDivision(text) {
  const words = text.split(/\s+/g).length;
  const ratio = words / 2 / 1;
  return `${words}/${ratio}`;
}

function switches(kind) {
  switch (kind) {
    case "a":
    case "b": {
      const letter = kind.toUpperCase();
      return letter + letter;
    }
    default:
      return "other:" + kind;
  }
}

async function promises(values) {
  const doubled = await Promise.all(values.map(async (value) => value * 2));
  const settled = await new Promise((resolve) => setTimeout(() => resolve(doubled.reduce((sum, value) => sum + value, 0)), 1));
  return settled;
}

function* generator(limit) {
  for (let n = 0; n < limit; n++) yield n * n;
}

function evaluated(seed) {
  const local = seed * 3;
  return eval("local + 1");
}

log("counter", (() => { const c = counter(5); c.next(); c.next(); return c.next() + "/" + c.reset(); })());
log("shadow", shadow(7));
log("hoisted", hoisted());
log("destructure", destructure({ name: "abcde", extra: 1, more: 2 }));
log("shorthand", shorthand(2, 3));
log("errors", errors(4), errors(-1));
log("class", Account.describe(new Account("ana", 10).deposit(5.5)), Account.describe(new Account("bo", 1)));
log("closures", closures());
log("labels", labels([[1, 2], [3, 0], [0, 1]]));
log("asi", asi(9, 4));
log("regex", regexAndDivision("one two  three four"));
log("switch", switches("a"), switches("z"));
log("generator", [...generator(5)].join(","));
log("eval", evaluated(4));
log("path", path.basename("/a/b/c.txt", ".txt"));
promises([1, 2, 3]).then((total) => {
  log("promises", total);
  console.log(out.join("\n"));
});
