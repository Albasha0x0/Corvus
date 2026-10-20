// Session script loaded into the observed program: stop points hold the hitting thread until the worker posts its
// resume token; watched calls are recorded; module, thread and exception events are forwarded. Observation only: no
// writes to the program.
const points = {};
const hits = {};
let observing = false; // the observers first replay what is already there; open's info() reports that instead

function stopsIn(id, context) {
  const tid = Process.getCurrentThreadId();
  hits[id] = (hits[id] || 0) + 1;
  const frames = [context.pc.toString()].concat(
    Thread.backtrace(context, Backtracer.ACCURATE).slice(0, 31).map(p => p.toString()));
  send({ type: 'stop', point: id, tid, hits: hits[id], registers: JSON.parse(JSON.stringify(context)), frames });
  recv('resume-' + tid, () => {}).wait();
}

function moduleRow(m) {
  return { name: m.name, base: m.base.toString(), size: m.size, path: m.path };
}

// Modules with deferred points (lower-case name or name without extension): their load holds the loading thread, before
// the module's code runs, until the worker posts load-<tid> once the points are set.
const deferredModules = new Set();

function isDeferred(m) {
  const name = m.name.toLowerCase();
  const dot = name.lastIndexOf('.');
  return deferredModules.has(name) || (dot > 0 && deferredModules.has(name.substring(0, dot)));
}

if (typeof Process.attachModuleObserver === 'function') {
  Process.attachModuleObserver({
    onAdded(m) {
      if (!observing) return;
      const held = deferredModules.size > 0 && isDeferred(m);
      const tid = Process.getCurrentThreadId();
      send({ type: 'module', action: 'loaded', module: moduleRow(m), held, tid });
      if (held) recv('load-' + tid, () => {}).wait();
    },
    onRemoved(m) { if (observing) send({ type: 'module', action: 'unloaded', module: moduleRow(m) }); },
  });
}
if (typeof Process.attachThreadObserver === 'function') {
  Process.attachThreadObserver({
    onAdded(t) { if (observing) send({ type: 'thread', action: 'started', tid: t.id }); },
    onRemoved(t) { if (observing) send({ type: 'thread', action: 'ended', tid: t.id }); },
  });
}
observing = true;
// The kinds that usually end the program wait for the worker to receive the event: a message still queued when the
// process dies is lost.
const FATAL_KINDS = new Set(['abort', 'access-violation', 'guard-page', 'illegal-instruction', 'stack-overflow', 'arithmetic']);
Process.setExceptionHandler(d => {
  const tid = Process.getCurrentThreadId();
  const ack = FATAL_KINDS.has(d.type);
  send({ type: 'exception', tid, kind: d.type, address: d.address.toString(), ack,
    memory: d.memory ? { operation: d.memory.operation, address: d.memory.address.toString() } : null });
  if (ack) recv('exception-' + tid, () => {}).wait();
  return false; // the program's own handlers decide
});

// Watched functions: each call's arguments (strings read while the call runs) and return value, sent in batches;
// calls over a watch's rate limit are counted, not recorded, so the program keeps its speed.
const watches = {};
const BATCH_ROWS = 512;
const FLUSH_MS = 100;
const STRING_CHARS = 256;

// Strings are read up to their terminator (a fixed length could run past the end of the page), then cut.
function readArg(kind, p) {
  if (kind === 'proc' && p.compare(ptr(0x10000)) < 0) return p.toString(); // an ordinal
  if (kind !== 'cstr' && kind !== 'wstr' && kind !== 'proc') return p.toString();
  if (p.isNull()) return null;
  try {
    let s;
    if (kind === 'wstr') s = p.readUtf16String();
    else {
      try { s = p.readUtf8String(); } catch (e) { s = p.readCString(); }
    }
    return s === null ? null : s.length > STRING_CHARS ? s.substring(0, STRING_CHARS) + '...' : s;
  } catch (e) {
    return '<unreadable ' + p + '>';
  }
}

function flush(w) {
  if (w.rows.length === 0 && w.skipped === 0) return;
  send({ type: 'calls', watch: w.id, rows: w.rows, skipped: w.skipped });
  w.rows = [];
  w.skipped = 0;
}

setInterval(() => { for (const id in watches) flush(watches[id]); }, FLUSH_MS);

function watch(id, address, args, perSecond) {
  const w = { id, rows: [], skipped: 0, tokens: perSecond, last: Date.now() };
  w.listener = Interceptor.attach(ptr(address), {
    onEnter(a) {
      const now = Date.now();
      w.tokens = Math.min(perSecond, w.tokens + (now - w.last) * perSecond / 1000);
      w.last = now;
      if (w.tokens < 1) { w.skipped++; this.row = null; return; }
      w.tokens -= 1;
      const values = new Array(args.length);
      for (let i = 0; i < args.length; i++) values[i] = args[i] === 'skip' ? null : readArg(args[i], a[i]);
      this.row = [Process.getCurrentThreadId(), now, this.returnAddress.toString(), values];
    },
    onLeave(r) {
      if (this.row === null) return;
      this.row.push(r.toString());
      w.rows.push(this.row);
      if (w.rows.length >= BATCH_ROWS) flush(w);
    },
  });
  watches[id] = w;
}

rpc.exports = {
  // runs before the script is unloaded, also when the program exits: the batches still held are sent
  dispose() {
    for (const id in watches) flush(watches[id]);
  },
  info() {
    return { arch: Process.arch, platform: Process.platform, pointerSize: Process.pointerSize, pid: Process.id,
      modules: Process.enumerateModules().map(moduleRow) };
  },
  set(id, address) {
    // a probe: the onEnter form takes the stack top for a return address, which past a function's start is a saved register
    points[id] = Interceptor.attach(ptr(address), function () { stopsIn(id, this.context); });
    return true;
  },
  clear(id) {
    if (!points[id]) return false;
    points[id].detach();
    delete points[id];
    return true;
  },
  watch(id, address, args, perSecond) {
    watch(id, address, args, perSecond);
    return true;
  },
  deferModule(name) {
    deferredModules.add(name.toLowerCase());
    return true;
  },
  undeferModule(name) {
    return deferredModules.delete(name.toLowerCase());
  },
  unwatch(id) {
    const w = watches[id];
    if (!w) return false;
    w.listener.detach();
    flush(w);
    delete watches[id];
    return true;
  },
  read(address, length) {
    try {
      const b = ptr(address).readByteArray(length);
      return b === null ? null : Array.from(new Uint8Array(b));
    } catch (e) {
      return null;
    }
  },
};
