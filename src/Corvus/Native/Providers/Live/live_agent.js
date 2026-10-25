// Session script loaded into the observed program: stop points hold the hitting thread until the worker posts its
// resume token; watched calls are recorded; module, thread and exception events are forwarded. Observation only: the
// program's code is written only where a stop point or watch is set.
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

// A bare point (a coverage count) sends only where it stopped: no stack, no registers. at is the point's address: the
// hook may run elsewhere, where the registers are the same (a detour's stub, see hookAt, or behind another agent's hook
// on the same function, whose trampoline Gum on ia32 reports as the pc).
function stopsIn(id, context, at, bare) {
  // The point was cleared while this thread was in the hook: a stop reported
  // now would hold it after the clear.
  if (!points[id]) return;
  const tid = Process.getCurrentThreadId();
  hits[id] = (hits[id] || 0) + 1;
  const pc = at.toString();
  expect('resume-' + tid);
  if (bare) send({ type: 'stop', point: id, tid, hits: hits[id], registers: {}, frames: [pc] });
  else {
    const registers = JSON.parse(JSON.stringify(context));
    registers.pc = pc;
    if (Process.arch === 'x64' || Process.arch === 'ia32') registers[Process.arch === 'x64' ? 'rip' : 'eip'] = pc;
    const frames = [pc].concat(Thread.backtrace(context, BACKTRACER).slice(0, 31).map(p => p.toString()));
    send({ type: 'stop', point: id, tid, hits: hits[id], registers, frames }, stackFrom(context.sp));
  }
  waitFor('resume-' + tid);
}

// A counted point reports each hit without holding the thread and clears
// itself at its hit limit, so the program does not wait on the server.
function countsIn(id, at, limit) {
  const p = points[id];
  if (!p || p.spent) return;
  hits[id] = (hits[id] || 0) + 1;
  send({ type: 'stop', point: id, tid: Process.getCurrentThreadId(), hits: hits[id], registers: {}, frames: [at.toString()], counted: true });
  if (hits[id] < limit) return;
  p.spent = true;
  // The hook is undone once this thread has left it, from the script's own
  // thread.
  setTimeout(() => {
    if (points[id] !== p) return;
    p.detach();
    delete points[id];
  }, 0);
}

function moduleRow(m) {
  return { name: m.name, base: m.base.toString(), size: m.size, path: m.path };
}

// Frida's module registry lags the loader up to the next LoadLibrary on every release tested (16.7 to 17.24; frida/frida-gum#1190, fixed in 4e628a8):
// a DLL mapped through a delay-load import is missing from enumerateModules and onAdded until then; the loader's
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

// Managed methods with stop points or watches, by the address of their IL body: the thread that compiles one is held when
// the JIT returns its code, before that code first runs, until the worker posts load-<tid> once the point is set there.
const jitWatched = new Set();
// IL bodies a coverage run counts, by run: each method's first compile is reported (not held) as its first run
const jitCounted = new Map();
let jitHooked = false;

function hookJit(m, running) {
  if (jitHooked) return;
  const getJit = m.findExportByName('getJit');
  if (getJit === null) return;
  jitHooked = true;
  const hookCompiler = jit => Interceptor.attach(jit.readPointer().readPointer(), {
    // ICorJitCompiler slot 0: compileMethod(this, ICorJitInfo*, CORINFO_METHOD_INFO* {ftn, scope, ILCode, ...}, flags, uint8_t** entry, uint32_t* size)
    onEnter(a) {
      this.il = null;
      if (jitWatched.size === 0 && jitCounted.size === 0) return;
      const il = a[2].add(2 * Process.pointerSize).readPointer().toString();
      const run = jitCounted.get(il);
      if (run !== undefined) {
        jitCounted.delete(il);
        send({ type: 'jit_ran', run, il });
      }
      if (!jitWatched.has(il)) return;
      this.il = il;
      this.entry = a[4];
      // the compiling thread's callers tell a compile at a loop (on-stack replacement) from a new version of the method
      this.frames = Thread.backtrace(this.context, Backtracer.FUZZY).slice(0, 64).map(p => p.toString());
    },
    onLeave(r) {
      if (this.il === null || r.toInt32() !== 0) return; // CORJIT_OK
      const tid = Process.getCurrentThreadId();
      expect('load-' + tid);
      send({ type: 'compiled', il: this.il, code: this.entry.readPointer().toString(), frames: this.frames, held: true, tid });
      waitFor('load-' + tid);
    },
  });
  // a running runtime has asked for its JIT already; a starting one asks once, after the library's start-up
  if (running) hookCompiler(new NativeFunction(getJit, 'pointer', [])());
  else {
    const asked = Interceptor.attach(getJit, { onLeave(r) { asked.detach(); hookCompiler(r); } });
  }
}

const JIT_LIBRARY = /^(lib)?clrjit\.(dll|so|dylib)$/i;

// The parts of a PE image's executable sections the file leaves empty (VirtualSize past SizeOfRawData), which the image
// fills at start-up (a packed DLL), with its entry point; null for any other image.
function codeWrittenAtStart(m) {
  if (Process.platform !== 'windows') return null;
  try {
    const nt = m.base.add(m.base.add(0x3c).readU32());
    const count = nt.add(6).readU16(), table = nt.add(24 + nt.add(20).readU16()), entry = nt.add(40).readU32(), empty = [];
    for (let i = 0; i < count; i++) {
      const s = table.add(i * 40), virtual = s.add(8).readU32(), raw = s.add(16).readU32();
      if ((s.add(36).readU32() & 0x20000000) !== 0 && virtual > raw) empty.push({ at: m.base.add(s.add(12).readU32() + raw), size: virtual - raw }); // IMAGE_SCN_MEM_EXECUTE
    }
    return empty.length > 0 && entry !== 0 ? { entry: m.base.add(entry), empty } : null;
  } catch (e) {
    return null; // unreadable headers: an ordinary image
  }
}

function moduleLoaded(m, held, afterEntry, unobserved) {
  const tid = Process.getCurrentThreadId();
  if (held) expect('load-' + tid);
  send({ type: 'module', action: 'loaded', module: moduleRow(m), held, tid, afterEntry, unobserved });
  if (held) waitFor('load-' + tid);
}

// The current thread's stack pointer and stack base (Windows)
let stackPointer = null, stackLimits = null;
if (Process.platform === 'windows') {
  try {
    const k32 = Process.getModuleByName('kernel32.dll'), abi = Process.arch === 'ia32' ? 'stdcall' : 'default';
    const virtualAlloc = new NativeFunction(k32.getExportByName('VirtualAlloc'), 'pointer', ['pointer', 'size_t', 'uint32', 'uint32'], abi);
    const code = virtualAlloc(NULL, Process.pageSize, 0x3000, 0x40); // MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    code.writeByteArray(Process.arch === 'x64' ? [0x48, 0x8d, 0x44, 0x24, 0x08, 0xc3] : [0x8d, 0x44, 0x24, 0x04, 0xc3]); // lea rax/eax, [caller's sp]; ret
    stackPointer = new NativeFunction(code, 'pointer', []);
    stackLimits = new NativeFunction(k32.getExportByName('GetCurrentThreadStackLimits'), 'void', ['pointer', 'pointer'], abi);
  } catch (e) {
    stackPointer = stackLimits = null;
  }
}

// Whether the instruction before p is a call (E8 rel32, or FF /2 in its 2, 3, 6 and 7 byte forms), so p is a return address
function afterCall(p) {
  try {
    const b = new Uint8Array(p.sub(7).readByteArray(7));
    const indirect = i => b[i] === 0xff && (b[i + 1] & 0x38) === 0x10;
    return b[2] === 0xe8 || indirect(5) || indirect(4) || indirect(1) || indirect(0);
  } catch (e) {
    return false;
  }
}

// Where the current thread returns from the outermost call into m's code: the return address and the stack slot that
// holds it; null when no live frame is in m
function returnFrom(m) {
  if (stackPointer === null) return null;
  const limits = Memory.alloc(2 * Process.pointerSize), size = Process.pointerSize;
  stackLimits(limits, limits.add(size));
  const sp = stackPointer(), base = limits.add(size).readPointer(), end = m.base.add(m.size);
  const inM = v => v.compare(m.base) >= 0 && v.compare(end) < 0;
  for (let slot = base.sub(size); slot.compare(sp) >= 0; slot = slot.sub(size)) {
    const v = slot.readPointer();
    if (!inM(v) || !afterCall(v)) continue;
    // the call into m's code pushed its return address above m's own frames
    for (let up = slot.add(size); up.compare(base) < 0; up = up.add(size)) {
      const r = up.readPointer();
      if (!inM(r) && afterCall(r)) return { at: r, slot: up };
    }
    return null;
  }
  return null;
}

// An x64 or x86 program on an ARM64 Windows machine, which runs it under emulation.
const emulated = (() => {
  if (Process.platform !== 'windows' || Process.arch === 'arm64') return false;
  try {
    const isWow64Process2 = new NativeFunction(Process.getModuleByName('kernel32.dll').getExportByName('IsWow64Process2'), 'int',
      ['pointer', 'pointer', 'pointer'], Process.arch === 'ia32' ? 'stdcall' : 'default');
    const process = Memory.alloc(2), native = Memory.alloc(2);
    // The native machine IMAGE_FILE_MACHINE_ARM64 (0xAA64) runs an x64 or x86 program emulated.
    return isWow64Process2(ptr(-1), process, native) !== 0 && native.readU16() === 0xaa64;
  } catch (e) {
    // No IsWow64Process2 (before Windows 10 1709): not an ARM64 machine.
    return false;
  }
})();

let moduleObserver = null;
if (typeof Process.attachModuleObserver === 'function') {
  moduleObserver = Process.attachModuleObserver({
    onAdded(m) {
      if (JIT_LIBRARY.test(m.name)) hookJit(m, !observing);
      if (!observing) return;
      const held = deferredModules.size > 0 && isDeferred(m);
      // a point written before such an image's start-up code runs is overwritten by it: hold once that code returns. The
      // registry can report a DLL first from a load its entry point makes (frida/frida-gum#1190), or after it returned.
      const start = held ? codeWrittenAtStart(m) : null;
      if (start === null) {
        moduleLoaded(m, held, false);
        return;
      }
      // Under emulation a hook in code written at start-up is not run (x64:
      // the translated code runs without it), and the loader's frames are
      // native ARM64 code (x86: CHPE), so its return cannot be hooked.
      if (emulated) {
        moduleLoaded(m, false, false, 'its entry point writes its code, and a stop point there is not seen in a program emulated on an ARM64 machine');
        return;
      }
      const inside = returnFrom(m), tid = Process.getCurrentThreadId();
      if (inside !== null) {
        const returned = Interceptor.attach(inside.at, function () {
          // past the slot once returned (a stdcall entry also pops its arguments); a nested load's return stays below it
          if (this.threadId !== tid || this.context.sp.compare(inside.slot) <= 0) return;
          returned.detach();
          moduleLoaded(m, true, true);
        });
      } else if (start.empty.every(r => new Uint8Array(r.at.readByteArray(r.size)).every(b => b === 0))) { // the entry point has not run yet
        const started = Interceptor.attach(start.entry, { onLeave() { started.detach(); moduleLoaded(m, true, true); } });
      } else { // it has returned already
        moduleLoaded(m, true, true);
        return;
      }
      Interceptor.flush(); // attached inside the observer: in place before the loader goes on
    },
    onRemoved(m) { if (observing) send({ type: 'module', action: 'unloaded', module: moduleRow(m) }); },
  });
}
// The program's thread ids, without Frida's own. On Linux, Process.enumerateThreads and the thread observer's first
// attach read every thread's registers through a helper process that ptrace-attaches it, and a helper whose thread
// never stops waits forever: under load a session's open hung in the script's load that way. Workaround for
// frida/frida-gum#1196, tested on Frida 17.24.3, no fix yet: /proc lists the ids without a helper.
const readTaskDir = (() => {
  if (Process.platform !== 'linux') return null;
  const [open, read, close] = ['opendir', 'readdir64', 'closedir'].map(globalExport);
  if (open === null || read === null || close === null) return null;
  return { open: new NativeFunction(open, 'pointer', ['pointer']), read: new NativeFunction(read, 'pointer', ['pointer']),
    close: new NativeFunction(close, 'int', ['pointer']), path: Memory.allocUtf8String('/proc/self/task') };
})();
function threadIds() {
  if (readTaskDir === null) return Process.enumerateThreads().map(t => t.id);
  const dir = readTaskDir.open(readTaskDir.path), ids = [];
  if (dir.isNull()) return ids;
  // In struct dirent64 d_name follows d_ino (8 bytes), d_off (8), d_reclen (2) and d_type (1) on every architecture.
  for (let entry = readTaskDir.read(dir); !entry.isNull(); entry = readTaskDir.read(dir)) {
    const id = parseInt(entry.add(19).readUtf8String(), 10);
    if (id > 0 && !(typeof Cloak !== 'undefined' && Cloak.hasThread(id))) ids.push(id);
  }
  readTaskDir.close(dir);
  return ids;
}

// every thread id reported; an ended thread stays, since the thread list can still name it for a moment
const threads = new Set(threadIds());

function threadStarted(id) {
  if (threads.has(id)) return;
  threads.add(id);
  send({ type: 'thread', action: 'started', tid: id });
}

// Thread ends: from the observer, or on Linux from a scan of /proc every THREAD_SCAN_MS, which reports each id once.
const THREAD_SCAN_MS = 200;
const endedThreads = new Set();
function scanThreads() {
  const running = new Set(threadIds());
  for (const id of threads) {
    if (running.has(id) || endedThreads.has(id)) continue;
    endedThreads.add(id);
    if (observing) send({ type: 'thread', action: 'ended', tid: id });
  }
}
let threadObserver = null, threadScan = null;
if (readTaskDir !== null) {
  threadScan = setInterval(scanThreads, THREAD_SCAN_MS);
} else if (typeof Process.attachThreadObserver === 'function') {
  threadObserver = Process.attachThreadObserver({
    onAdded(t) { if (observing) threadStarted(t.id); },
    onRemoved(t) { if (observing) send({ type: 'thread', action: 'ended', tid: t.id }); },
  });
}
function stopThreadEvents() {
  if (threadObserver !== null) {
    threadObserver.detach();
    threadObserver = null;
  }
  if (threadScan !== null) {
    clearInterval(threadScan);
    threadScan = null;
  }
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
    // the agent's module is cloaked: enumerateModules leaves it out, the loader still names it
    const abi = Process.arch === 'ia32' ? 'stdcall' : 'default';
    const k32 = Process.getModuleByName('kernel32.dll');
    const handle = new NativeFunction(k32.getExportByName('GetModuleHandleW'), 'pointer', ['pointer'], abi)(Memory.allocUtf16String('frida-agent.dll'));
    if (handle.isNull()) return;
    const file = Memory.alloc(2 * 32768);
    const length = new NativeFunction(k32.getExportByName('GetModuleFileNameW'), 'uint32', ['pointer', 'pointer', 'uint32'], abi)(handle, file, 32768);
    if (length === 0) return;
    const agent = file.readUtf16String(length);
    const dir = agent.substring(0, agent.lastIndexOf('\\') + 1).toLowerCase();
    const dbghelp = Process.enumerateModules().find(m => m.name.toLowerCase() === 'dbghelp.dll' && m.path.toLowerCase().startsWith(dir));
    if (!dbghelp) return;
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
  if (threadScan !== null) scanThreads();
  flushAll();
  exiting = true;
  expect('exit-' + tid);
  send({ type: 'exit_status', tid, code, ack: true });
  waitFor('exit-' + tid);
  // The exit ends Frida's threads at once; one still busy (sending, or serving a close) can leave the agent's heap lock
  // held, and Frida's hook on the DLL unloads of the shutdown then waits on it forever: give them time to finish
  // Workaround for frida/frida-gum#1192: hangs on 17.24.0 to 17.24.3, not on 17.23.3 and earlier; no fix release yet.
  if (Process.platform === 'windows') Thread.sleep(EXIT_DRAIN);
}
const EXIT_DRAIN = 0.3; // seconds
if (Process.platform === 'windows') {
  // ExitProcess and a return from main end in RtlExitUserProcess; a probe, so no hook frame is left during the exit
  const exitUser = Process.getModuleByName('ntdll.dll').findExportByName('RtlExitUserProcess');
  if (exitUser !== null)
    Interceptor.attach(exitUser, function () {
      beforeExit(Process.arch === 'x64' ? this.context.rcx.toInt32() : Process.arch === 'arm64' ? this.context.x0.toInt32() : this.context.sp.add(4).readS32());
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

// Code in a mapped file view (not an image) cannot be made PAGE_EXECUTE_READWRITE, which Gum's hooks write through, and
// Gum ends the process when that fails. There the hook goes on a stub near the code (the instructions a jump replaces,
// copied, then a jump back) and a jump to the stub is written copy-on-write; detaching restores the original bytes.
const MEM_MAPPED = 0x40000, PAGE_EXECUTE_WRITECOPY = 0x80, JMP_BYTES = 5, STUB_BYTES = 128, NEAR = 0x7FFF0000;
let winApi = null;
const stubPages = []; // { base, used }: stubs are carved from pages within a rel32 jump of their code

function stubNear(p) {
  let page = stubPages.find(s => s.used + STUB_BYTES <= Process.pageSize
    && (s.base.compare(p) >= 0 ? s.base.sub(p) : p.sub(s.base)).compare(ptr(NEAR - Process.pageSize)) < 0);
  if (!page) {
    page = { base: Memory.alloc(Process.pageSize, { near: p, maxDistance: NEAR }), used: 0 };
    Memory.protect(page.base, Process.pageSize, 'rwx');
    stubPages.push(page);
  }
  const stub = page.base.add(page.used);
  page.used += STUB_BYTES;
  return stub;
}

function win() {
  if (winApi !== null) return winApi;
  const k = Process.getModuleByName('kernel32.dll');
  winApi = {
    query: new NativeFunction(k.getExportByName('VirtualQuery'), 'size_t', ['pointer', 'pointer', 'size_t']),
    protect: new NativeFunction(k.getExportByName('VirtualProtect'), 'int', ['pointer', 'size_t', 'uint32', 'pointer']),
    flush: new NativeFunction(k.getExportByName('FlushInstructionCache'), 'int', ['pointer', 'pointer', 'size_t']),
    mappedFile: new NativeFunction(k.getExportByName('K32GetMappedFileNameW'), 'uint32', ['pointer', 'pointer', 'pointer', 'uint32']),
    process: new NativeFunction(k.getExportByName('GetCurrentProcess'), 'pointer', []),
  };
  return winApi;
}

function inMappedView(p) {
  if (Process.platform !== 'windows') return false;
  const info = Memory.alloc(48);
  if (win().query(p, info, 48).toNumber() === 0) return false;
  return info.add(Process.pointerSize === 8 ? 40 : 24).readU32() === MEM_MAPPED;
}

function writeCode(p, bytes) {
  const old = Memory.alloc(4);
  if (!win().protect(p, bytes.length, PAGE_EXECUTE_WRITECOPY, old)) throw new Error('the code at ' + p + ' cannot be made writable');
  p.writeByteArray(bytes);
  win().protect(p, bytes.length, old.readU32(), Memory.alloc(4));
  win().flush(win().process(), p, bytes.length);
}

// Where to hook p, and how to undo it: p itself, or for code in a mapped view the stub its detour jumps to.
function hookAt(p) {
  if (!inMappedView(p)) return { at: p, undo() {} };
  if (Process.arch !== 'x64' && Process.arch !== 'ia32') throw new Error('code in a mapped file view is hooked on x86 and x64 only');
  // A copy-on-write page of a shared memory view stops seeing what the owner writes through its other view: the .NET
  // runtime's W^X code heap would run stale code on that page. A file view (a single-file bundle) is never rewritten.
  if (win().mappedFile(win().process(), p, Memory.alloc(1024), 512) === 0)
    throw new Error('the code at ' + p + ' is in a shared memory view (the .NET runtime W^X code heap); start the program in a session, which sets DOTNET_EnableWriteXorExecute=0');
  const stub = stubNear(p);
  const w = new X86Writer(stub, { pc: stub });
  w.putNopPadding(16); // room for Gum's own hook on the stub
  const r = new X86Relocator(p, w);
  let length = 0;
  while (length < JMP_BYTES) {
    const n = r.readOne();
    if (n === 0 || (n < JMP_BYTES && r.eob)) throw new Error('the code at ' + p + ' is too short for a detour');
    length = n;
  }
  r.writeAll();
  w.putJmpAddress(p.add(length));
  w.flush();
  const original = p.readByteArray(length);
  const jump = new Uint8Array(length).fill(0x90);
  jump[0] = 0xE9;
  new DataView(jump.buffer).setInt32(1, stub.sub(p.add(JMP_BYTES)).toInt32(), true);
  writeCode(p, Array.from(jump));
  return { at: stub, undo() { writeCode(p, Array.from(new Uint8Array(original))); } };
}

// A second watch or stop point of one id adds a hook: the method's code after the runtime compiles it again.
function watch(id, address, args, perSecond) {
  const w = watches[id] || { id, rows: [], skipped: 0, tokens: perSecond, last: Date.now(), undo() {} };
  const hook = hookAt(ptr(address));
  const listener = Interceptor.attach(hook.at, {
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
  const prior = w.undo;
  w.undo = () => { hook.undo(); listener.detach(); prior(); };
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
    // Observers go first: a callback on a Frida thread during the unload faults
    // in the script runtime. Workaround for frida/frida-gum#1194: fails on
    // 17.23.3 to 17.24.3; no fix release yet.
    stopThreadEvents();
    if (moduleObserver !== null) {
      moduleObserver.detach();
      moduleObserver = null;
    }
    return { awaited: [...awaited], exiting };
  },
  // On Linux the thread observer keeps a fork from reaching child gating (Frida 17.24): its thread-ended events go there
  followChildren() {
    if (Process.platform === 'linux' && threadObserver !== null) {
      threadObserver.detach();
      threadObserver = null;
    }
    return true;
  },
  info() {
    return { arch: Process.arch, platform: Process.platform, pointerSize: Process.pointerSize, pid: Process.id,
      modules: loadedModules() };
  },
  // A bare point with a hit limit is counted rather than held (countsIn).
  set(id, address, bare, limit) {
    const p = ptr(address), hook = hookAt(p);
    const counted = bare === true && limit > 0;
    // a probe: the onEnter form takes the stack top for a return address, which past a function's start is a saved register
    const listener = Interceptor.attach(hook.at, counted
      ? function () { countsIn(id, p, limit); }
      : function () { stopsIn(id, this.context, p, bare === true); });
    const prior = points[id];
    points[id] = { detach() { hook.undo(); listener.detach(); if (prior) prior.detach(); } };
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
  watchJit(il) {
    jitWatched.add(ptr(il).toString());
    return true;
  },
  countJit(run, ils) {
    for (const il of ils) jitCounted.set(ptr(il).toString(), run);
    return true;
  },
  unwatch(id) {
    const w = watches[id];
    if (!w) return false;
    w.undo();
    flush(w);
    delete watches[id];
    return true;
  },
  // ART prints every thread's Java stack when its Signal Catcher thread takes SIGQUIT. The signal goes to that
  // thread alone: sent to the process, it could reach a Frida thread, which does not block it and would end the
  // program. Null in a process without ART.
  artDump() {
    const named = id => { try { return File.readAllText(`/proc/self/task/${id}/comm`).trim(); } catch (e) { return null; } };
    const catcher = threadIds().find(id => named(id) === 'Signal Catcher');
    if (catcher === undefined) return null;
    const tgkill = new NativeFunction(Process.getModuleByName('libc.so').getExportByName('tgkill'), 'int', ['int', 'int', 'int']);
    return tgkill(Process.id, catcher, 3) === 0 ? catcher : null;
  },
  exportOf(module, name) {
    const m = Process.findModuleByName(module), e = m === null ? null : m.findExportByName(name);
    return e === null ? null : e.toString();
  },
  read(address, length) {
    try {
      const b = ptr(address).readByteArray(length);
      return b === null ? null : Array.from(new Uint8Array(b));
    } catch (e) {
      return null;
    }
  },
  // Ranges with at least this protection ('rw-'); Frida leaves out its own (cloaked) memory.
  ranges(protection) {
    return Process.enumerateRanges({ protection, coalesce: false }).map(r => ({ base: r.base.toString(), size: r.size }));
  },
  // Bytes as binary data, which the RPC sends without a JSON array; null where unreadable.
  readBlock(address, length) {
    try {
      return ptr(address).readByteArray(length);
    } catch (e) {
      return null;
    }
  },
};
