using System.Collections.Concurrent;
using Iced.Intel;
using Corvus.Native.Pe;

namespace Corvus.Native.Calls;

/// <summary>
/// x86: the bytes an imported function removes from the stack ("ret n" of a stdcall export), read from the DLL that
/// exports it (next to the importing image, else the 32-bit system directory; API set names resolved; forwarders and
/// "jmp [import]" stubs followed). The first return in a linear scan of the export decides; null when none is found.
/// Cached per process; files that cannot be read count as unknown.
/// </summary>
internal static class X86ImportArity
{
    private static readonly ConcurrentDictionary<string, PeFile?> Dlls = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<(string Module, string Name), int?> Cache = new();
    private static readonly Lazy<ApiSetSchema?> ApiSets = new(() =>
    {
        try { return ApiSetSchema.FromSystem(PeFile.Open); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException) { return null; }
    });

    public static int? Pops(NativeImport import, string? importerPath)
    {
        if (import.Name == null) return null;
        return Find(import.Module, import.Name, importerPath, 0);
    }

    private static int? Find(string module, string name, string? importerPath, int depth)
    {
        if (depth > 4) return null;
        var key = (module.ToLowerInvariant(), name);
        if (Cache.TryGetValue(key, out var cached)) return cached;
        int? result = null;
        if (Open(module, importerPath) is { } pe && pe.Arch == NativeArch.X86)
        {
            var export = pe.Exports.FirstOrDefault(e => e.Name == name);
            if (export?.ForwardedTo is { } fwd && fwd.LastIndexOf('.') is var dot and > 0 && fwd[(dot + 1)..] is { Length: > 0 } target && target[0] != '#')
                result = Find(fwd[..dot] + ".dll", target, importerPath, depth + 1);
            else if (export != null)
                result = Scan(pe, export.Rva, importerPath, depth);
        }
        Cache[key] = result;
        return result;
    }

    private static PeFile? Open(string module, string? importerPath)
    {
        var name = module.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || module.Contains('.') ? module : module + ".dll";
        if (ApiSetSchema.IsApiSetName(name)) name = ApiSets.Value?.Resolve(name) ?? name;
        return Dlls.GetOrAdd(name, n =>
        {
            var dirs = new List<string>();
            if (importerPath != null && Path.GetDirectoryName(importerPath) is { Length: > 0 } own) dirs.Add(own);
            var sys = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);
            if (sys.Length > 0) dirs.Add(sys);
            foreach (var dir in dirs)
            {
                var path = Path.Combine(dir, n);
                try { if (File.Exists(path)) return PeFile.Open(path); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException) { }
            }
            return null;
        });
    }

    private static int? Scan(PeFile pe, uint rva, string? importerPath, int depth)
    {
        var bytes = new byte[0x4000];
        int jumps = 0;
        for (int budget = 3000; budget > 0;)
        {
            int n = pe.Read(rva, bytes);
            if (n == 0) return null;
            var decoder = Iced.Intel.Decoder.Create(32, new ByteArrayCodeReader(bytes, 0, n), pe.ImageBase + rva);
            int count = 0;
            bool restarted = false;
            while (decoder.IP < pe.ImageBase + rva + (ulong)n && budget-- > 0)
            {
                decoder.Decode(out var insn);
                count++;
                if (insn.IsInvalid || insn.Mnemonic == Mnemonic.Int3) return null;
                if (insn.Mnemonic == Mnemonic.Ret) return insn.OpCount > 0 ? insn.Immediate16 : 0;
                if (insn.FlowControl == FlowControl.IndirectBranch && insn.Op0Kind == OpKind.Memory && insn.MemoryBase == Register.None
                    && insn.MemoryIndex == Register.None)
                {
                    // a stub: jmp [__imp_X]
                    uint slot = (uint)(insn.MemoryDisplacement64 - pe.ImageBase);
                    var imp = pe.Imports.FirstOrDefault(i => i.SlotRva == slot);
                    return imp?.Name != null ? Find(imp.Module, imp.Name, importerPath, depth + 1) : null;
                }
                if (insn.FlowControl == FlowControl.UnconditionalBranch && insn.Op0Kind == OpKind.NearBranch32 && count <= 8 && jumps++ < 3)
                {
                    rva = (uint)(insn.NearBranchTarget - pe.ImageBase);
                    restarted = true;
                    break;
                }
            }
            if (!restarted) return null;
        }
        return null;
    }
}
