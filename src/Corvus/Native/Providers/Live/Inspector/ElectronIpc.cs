namespace Corvus.Native.Providers.Live.Inspector;

/// <summary>IPC recorder for an Electron main process: counts messages by direction, kind, channel and shape, never values.</summary>
internal static class ElectronIpc
{
    // Keys kept; later new keys are counted as dropped.
    public const int MaxKeys = 500;

    /// <summary>The expression: installs the recorder once, then returns {app, rows: [{d, k, c, s, n}], dropped} or {error}.</summary>
    public static readonly string Expression = """
        (() => {
          const req = typeof require === 'function' ? require : process.mainModule && process.mainModule.require.bind(process.mainModule);
          if (typeof process !== 'object' || !process.versions.electron || process.type !== 'browser' || !req) return { error: 'not an Electron main process' };
          const electron = req('electron');
          let ledger = globalThis.__corvusIpcLedger;
          if (!ledger) {
            ledger = { rows: new Map(), dropped: 0 };
            const shape = (v, depth) => {
              if (v === null) return 'null';
              if (Array.isArray(v)) return depth > 3 ? '[...]' : v.length === 0 ? '[]' : '[' + shape(v[0], depth + 1) + ']';
              const t = typeof v;
              if (t !== 'object') return t;
              if (ArrayBuffer.isView(v)) return v.constructor.name;
              if (depth > 3) return '{...}';
              const keys = Object.keys(v).sort();
              return '{' + keys.slice(0, 16).map(k => k + ':' + shape(v[k], depth + 1)).join(',') + (keys.length > 16 ? ',...' : '') + '}';
            };
            const args = a => '(' + a.map(x => shape(x, 0)).join(', ') + ')';
            const count = (d, k, channel, s) => {
              try {
                const c = String(channel).slice(0, 200), key = d + '\u0000' + k + '\u0000' + c + '\u0000' + s;
                const row = ledger.rows.get(key);
                if (row) row.n++;
                else if (ledger.rows.size < MAX_KEYS) ledger.rows.set(key, { d, k, c, s, n: 1 });
                else ledger.dropped++;
              } catch (e) {}
            };
            let proto = null;
            try { proto = process._linkedBinding('electron_browser_web_contents').WebContents.prototype; } catch (e) {}
            if (!proto) { const any = electron.webContents.getAllWebContents()[0]; if (any) proto = Object.getPrototypeOf(any); }
            if (!proto) return { error: 'no WebContents prototype found' };
            const emit = proto.emit;
            proto.emit = function (name, event, channel, ...rest) {
              if (name === 'ipc-message') count('renderer-to-main', 'send', channel, args(rest));
              else if (name === 'ipc-message-sync') count('renderer-to-main', 'sendSync', channel, args(rest));
              return emit.apply(this, arguments);
            };
            const send = proto.send;
            proto.send = function (channel, ...rest) { count('main-to-renderer', 'send', channel, args(rest)); return send.apply(this, arguments); };
            const sendToFrame = proto.sendToFrame;
            if (typeof sendToFrame === 'function')
              proto.sendToFrame = function (frame, channel, ...rest) { count('main-to-renderer', 'send', channel, args(rest)); return sendToFrame.apply(this, arguments); };
            const handlers = electron.ipcMain._invokeHandlers;
            if (handlers && typeof handlers.get === 'function') {
              const get = handlers.get.bind(handlers);
              handlers.get = channel => {
                const h = get(channel);
                if (typeof h !== 'function') return h;
                return function (event, ...rest) {
                  count('renderer-to-main', 'invoke', channel, args(rest));
                  const r = h.apply(this, arguments);
                  Promise.resolve(r).then(v => count('main-to-renderer', 'invoke-result', channel, shape(v, 0)), () => count('main-to-renderer', 'invoke-error', channel, 'error'));
                  return r;
                };
              };
            }
            globalThis.__corvusIpcLedger = ledger;
          }
          let app = null;
          try { app = electron.app.getAppPath(); } catch (e) {}
          return { app, rows: [...ledger.rows.values()], dropped: ledger.dropped };
        })()
        """.Replace("MAX_KEYS", MaxKeys.ToString(System.Globalization.CultureInfo.InvariantCulture), StringComparison.Ordinal);
}
