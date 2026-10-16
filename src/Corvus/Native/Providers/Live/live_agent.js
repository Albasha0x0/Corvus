// Session script loaded into the observed program: stop points hold the hitting thread until the worker posts its
// resume token; module, thread and exception events are forwarded. Observation only: no writes to the program.
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

if (typeof Process.attachModuleObserver === 'function') {
  Process.attachModuleObserver({
    onAdded(m) { if (observing) send({ type: 'module', action: 'loaded', module: moduleRow(m) }); },
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
Process.setExceptionHandler(d => {
  send({ type: 'exception', tid: Process.getCurrentThreadId(), kind: d.type, address: d.address.toString(),
    memory: d.memory ? { operation: d.memory.operation, address: d.memory.address.toString() } : null });
  return false; // the program's own handlers decide
});

rpc.exports = {
  info() {
    return { arch: Process.arch, platform: Process.platform, pointerSize: Process.pointerSize, pid: Process.id,
      modules: Process.enumerateModules().map(moduleRow) };
  },
  set(id, address) {
    points[id] = Interceptor.attach(ptr(address), { onEnter() { stopsIn(id, this.context); } });
    return true;
  },
  clear(id) {
    if (!points[id]) return false;
    points[id].detach();
    delete points[id];
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
