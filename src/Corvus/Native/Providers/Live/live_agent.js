// Session script loaded into the observed program: stop points hold the hitting thread until the worker posts its
// resume token; watched calls are recorded; module, thread and exception events are forwarded. Observation only: no
// writes to the program.
const points = {};
const hits = {};
let observing = false; // the observers first replay what is already there; open's info() reports that instead
// The replies threads wait for. The worker posts every one of them before it unloads the script (closeBegin): a
// reply still in flight would otherwise never come, and nothing ends recv().wait().
const awaited = new Set();
let closing = false;

// Call before the send the reply answers, so closeBegin sees the wait even if the reply is not yet awaited.
function expect(type) {
  awaited.add(type);
}

function waitFor(type) {
  if (!closing) recv(type, () => {}).wait();
  awaited.delete(type);
}

// Outside Windows a stop also sends the stack from the stack pointer up, for the server to unwind with the modules'
// CFI: Frida's backtrace there starts with the word at the stack pointer, a return address only at a function's start,
// and its accurate walk ends the process at some C runtime start-up functions on x86, so only the stack scan runs.
const STACK_BYTES = 32768;
const BACKTRACER = Process.platform === 'windows' ? Backtracer.ACCURATE : Backtracer.FUZZY;

function stackFrom(sp) {
  if (Process.platform === 'windows') return null;
  try {
    const range = Process.findRangeByAddress(sp);
    if (range === null) return null;
    return sp.readByteArray(Math.min(STACK_BYTES, range.base.add(range.size).sub(sp).toInt32()));
  } catch (e) {
    return null;
  }
}

// A bare point (a coverage count) sends only where it stopped: no stack, no registers.
function stopsIn(id, context, bare) {
  const tid = Process.getCurrentThreadId();
  hits[id] = (hits[id] || 0) + 1;
  expect('resume-' + tid);
  if (bare) send({ type: 'stop', point: id, tid, hits: hits[id], registers: {}, frames: [context.pc.toString()] });
  else {
    const frames = [context.pc.toString()].concat(
      Thread.backtrace(context, BACKTRACER).slice(0, 31).map(p => p.toString()));
    send({ type: 'stop', point: id, tid, hits: hits[id], registers: JSON.parse(JSON.stringify(context)), frames }, stackFrom(context.sp));
  }
  waitFor('resume-' + tid);
}

function moduleRow(m) {
  return { name: m.name, base: m.base.toString(), size: m.size, path: m.path };
}

// Frida's module registry (seen with 17.24.3) misses a DLL the loader maps through a delay-load import, in
// enumerateModules and in the observer's onAdded, until a later load, often after the resume; the loader's
// own list (K32EnumProcessModules, which takes no loader lock, so a thread held inside DllMain does not block it) adds
// those, leaving out the agent's cloaked ranges.
function loadedModules() {
  const rows = Process.enumerateModules().map(moduleRow);
  if (Process.platform !== 'windows') return rows;
  try {
    const k32 = Process.getModuleByName('kernel32.dll');
    const abi = Process.arch === 'ia32' ? 'stdcall' : 'default';
    const enumModules = new NativeFunction(k32.getExportByName('K32EnumProcessModules'), 'int', ['pointer', 'pointer', 'uint32', 'pointer'], abi);
    const fileName = new NativeFunction(k32.getExportByName('K32GetModuleFileNameExW'), 'uint32', ['pointer', 'pointer', 'pointer', 'uint32'], abi);
    const self = ptr(Process.pointerSize === 8 ? '0xffffffffffffffff' : '0xffffffff'); // GetCurrentProcess()
    const capacity = 2048, handles = Memory.alloc(capacity * Process.pointerSize), needed = Memory.alloc(4);
    if (!enumModules(self, handles, capacity * Process.pointerSize, needed)) return rows;
    const known = new Set(rows.map(r => r.base));
    const name = Memory.alloc(2 * 32768);
    const count = Math.min(needed.readU32() / Process.pointerSize, capacity);
    for (let i = 0; i < count; i++) {
      const base = handles.add(i * Process.pointerSize).readPointer();
      if (known.has(base.toString()) || (typeof Cloak !== 'undefined' && Cloak.hasRangeContaining(base))) continue;
      const length = fileName(self, base, name, 32768);
      if (length === 0) continue;
      const path = name.readUtf16String(length);
      const size = base.add(base.add(0x3c).readU32() + 0x50).readU32(); // SizeOfImage, at the same offset in PE32 and PE32+
      rows.push({ name: path.substring(path.lastIndexOf('\\') + 1), base: base.toString(), size, path });
    }
  } catch (e) {
    // the observer's list stands
  }
  return rows;
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
      if (held) expect('load-' + tid);
      send({ type: 'module', action: 'loaded', module: moduleRow(m), held, tid });
      if (held) waitFor('load-' + tid);
    },
    onRemoved(m) { if (observing) send({ type: 'module', action: 'unloaded', module: moduleRow(m) }); },
  });
}
// every thread id reported; an ended thread stays, since the thread list can still name it for a moment
const threads = new Set(Process.enumerateThreads().map(t => t.id));

function threadStarted(id) {
  if (threads.has(id)) return;
  threads.add(id);
  send({ type: 'thread', action: 'started', tid: id });
}

if (typeof Process.attachThreadObserver === 'function') {
  Process.attachThreadObserver({
    onAdded(t) { if (observing) threadStarted(t.id); },
    onRemoved(t) { if (observing) send({ type: 'thread', action: 'ended', tid: t.id }); },
  });
}
function globalExport(name) {
  return typeof Module.findGlobalExportByName === 'function' ? Module.findGlobalExportByName(name) : Module.findExportByName(null, name);
}

// On Linux the observer reports no new thread (glibc starts them through clone3): a pthread_create that succeeds
// reports the thread id the kernel stored in the new thread's descriptor, found at the offset that holds this thread's id
if (Process.platform === 'linux') {
  const create = globalExport('pthread_create'), self = globalExport('pthread_self');
  let tidOffset = -1;
  if (self !== null) {
    const me = new NativeFunction(self, 'pointer', [])(), id = Process.getCurrentThreadId();
    for (let o = 0; o < 0x1000 && tidOffset < 0; o += 4) if (me.add(o).readS32() === id) tidOffset = o;
  }
  if (create !== null && tidOffset >= 0) {
    Interceptor.attach(create, {
      onEnter(a) { this.thread = a[0]; },
      onLeave(r) { if (r.toInt32() === 0) threadStarted(this.thread.readPointer().add(tidOffset).readS32()); },
    });
  }
}
// The accurate backtracer runs dbghelp inside the program, which looks for each module's symbol files in the current
// directory, the image's folder and the path its debug record names: file activity that is not the program's, and
// helper modules loaded at the first stop, where module events wait for the resume. Started here, its search goes to
// the agent's own folder only.
function quietSymbols() {
  try {
    Thread.backtrace(); // loads and initializes dbghelp
    const mods = Process.enumerateModules();
    const agent = mods.find(m => m.name.toLowerCase() === 'frida-agent.dll');
    if (!agent) return;
    const dir = agent.path.substring(0, agent.path.lastIndexOf('\\') + 1).toLowerCase();
    const dbghelp = mods.find(m => m.name.toLowerCase() === 'dbghelp.dll' && m.path.toLowerCase().startsWith(dir));
    if (!dbghelp) return;
    const abi = Process.arch === 'ia32' ? 'stdcall' : 'default';
    const getOptions = new NativeFunction(dbghelp.getExportByName('SymGetOptions'), 'uint32', [], abi);
    const setOptions = new NativeFunction(dbghelp.getExportByName('SymSetOptions'), 'uint32', ['uint32'], abi);
    const setPath = new NativeFunction(dbghelp.getExportByName('SymSetSearchPathW'), 'int', ['pointer', 'pointer'], abi);
    setOptions(getOptions() | 0x80 | 0x200000); // SYMOPT_IGNORE_CVREC | SYMOPT_IGNORE_IMAGEDIR
    setPath(ptr(Process.pointerSize === 8 ? '0xffffffffffffffff' : '0xffffffff'), Memory.allocUtf16String(dir)); // GetCurrentProcess()
  } catch (e) {
    // stacks still come; only the search is not narrowed
  }
}
if (Process.platform === 'windows') quietSymbols();
observing = true;
// The kinds that usually end the program wait for the worker to receive the event: a message still queued when the
// process dies is lost.
const FATAL_KINDS = new Set(['abort', 'access-violation', 'guard-page', 'illegal-instruction', 'stack-overflow', 'arithmetic']);
Process.setExceptionHandler(d => {
  const tid = Process.getCurrentThreadId();
  const ack = FATAL_KINDS.has(d.type);
  if (ack) {
    flushAll(); // calls recorded just before the fault
    expect('exception-' + tid);
  }
  send({ type: 'exception', tid, kind: d.type, address: d.address.toString(), ack,
    memory: d.memory ? { operation: d.memory.operation, address: d.memory.address.toString() } : null });
  if (ack) waitFor('exception-' + tid);
  return false; // the program's own handlers decide
});

// Before the process exits, the last watch batches and the exit status (which the detach reason does not carry outside
// Windows) go out, and the thread waits for the worker to have them, as for a fatal exception. Sent later, from dispose
// during the exit itself, the batches can hold Frida's unload forever, and the program never finishes exiting.
let exiting = false;
function beforeExit(code) {
  const tid = Process.getCurrentThreadId();
  flushAll();
  exiting = true;
  expect('exit-' + tid);
  send({ type: 'exit_status', tid, code, ack: true });
  waitFor('exit-' + tid);
}
if (Process.platform === 'windows') {
  // ExitProcess and a return from main end in RtlExitUserProcess; a probe, so no hook frame is left during the exit
  const exitUser = Process.getModuleByName('ntdll.dll').findExportByName('RtlExitUserProcess');
  if (exitUser !== null)
    Interceptor.attach(exitUser, function () {
      beforeExit(Process.arch === 'x64' ? this.context.rcx.toInt32() : this.context.sp.add(4).readS32());
    });
} else {
  // exit() and a return from main end in _exit
  const _exit = globalExport('_exit');
  if (_exit !== null) Interceptor.attach(_exit, { onEnter(a) { beforeExit(a[0].toInt32()); } });
}

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

function flushAll() {
  for (const id in watches) flush(watches[id]);
}

function flush(w) {
  if (w.rows.length === 0 && w.skipped === 0) return;
  send({ type: 'calls', watch: w.id, rows: w.rows, skipped: w.skipped });
  w.rows = [];
  w.skipped = 0;
}

setInterval(flushAll, FLUSH_MS);

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
  // runs before the script is unloaded; once the program is exiting, beforeExit has sent the batches
  dispose() {
    if (!exiting) flushAll();
  },
  // the replies still awaited, and whether the program is exiting; a wait that starts later returns at once
  closeBegin() {
    closing = true;
    return { awaited: [...awaited], exiting };
  },
  info() {
    return { arch: Process.arch, platform: Process.platform, pointerSize: Process.pointerSize, pid: Process.id,
      modules: loadedModules() };
  },
  set(id, address, bare) {
    // a probe: the onEnter form takes the stack top for a return address, which past a function's start is a saved register
    points[id] = Interceptor.attach(ptr(address), function () { stopsIn(id, this.context, bare === true); });
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
