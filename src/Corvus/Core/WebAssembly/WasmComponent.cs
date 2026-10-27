namespace Corvus.Core.WebAssembly;

/// <summary>The core modules of a WebAssembly component (version 0x0d, layer 1), nested components included.</summary>
public static class WasmComponent
{
    private const int MaxDepth = 16, MaxModules = 10_000;

    public static bool Looks(ReadOnlySpan<byte> b) => b.Length >= 8 && b[..4].SequenceEqual("\0asm"u8) && b[6] == 1 && b[7] == 0;

    /// <summary>Each core module: its name ("core0.wasm", "component1/core0.wasm" in a nested component), file offset and length.</summary>
    public static List<(string Name, int Offset, int Length)> CoreModules(byte[] bytes, List<string>? issues = null)
    {
        var modules = new List<(string, int, int)>();
        if (Looks(bytes)) Walk(bytes, 8, bytes.Length, "", 0, modules, issues);
        return modules;
    }

    private static void Walk(byte[] bytes, int p, int end, string prefix, int depth, List<(string, int, int)> modules, List<string>? issues)
    {
        int cores = 0, components = 0;
        while (p < end && modules.Count < MaxModules)
        {
            int start = p;
            byte id = bytes[p++];
            var r = new WasmReader(bytes, p, end);
            if (!r.TryU32(out uint size) || size > end - r.Pos) { issues?.Add($"component section {id} at 0x{start:X} runs past the end"); return; }
            int body = r.Pos;
            if (id == 1) modules.Add(($"{prefix}core{cores++}.wasm", body, (int)size));
            else if (id == 4)
            {
                if (depth >= MaxDepth) issues?.Add($"a component nested deeper than {MaxDepth} levels at 0x{start:X}; not read");
                else if (Looks(bytes.AsSpan(body, (int)size))) Walk(bytes, body + 8, body + (int)size, $"{prefix}component{components}/", depth + 1, modules, issues);
                components++;
            }
            p = body + (int)size;
        }
    }
}
