namespace Corvus.Native.Code;

/// <summary>
/// ARM64 Windows: MSVC shrink-wraps a function's early exit before its prologue, and the .pdata entry starts at the
/// prologue. A function entry that runs straight into such an entry (and branches into its body) is the function's
/// real start; the .pdata start stops being one unless something else names it.
/// </summary>
internal sealed partial class FunctionDiscovery
{
    // .pdata start -> the head that runs into it
    private readonly Dictionary<uint, uint> _heads = [];

    /// <summary>The .pdata function starting at <paramref name="rva"/> that only .pdata names (ARM64), or null.</summary>
    private uint? HeadOf(uint rva) =>
        _ctx.Image.Arch == NativeArch.Arm64 && _ctx.PdataRanges.ContainsKey(rva) && _functions.TryGetValue(rva, out var source) && source == FunctionSource.Pdata ? rva : null;

    /// <summary><paramref name="rva"/> lies in the .pdata ranges of <paramref name="body"/> or the epilogue just after one.</summary>
    private bool InHeadOf(uint? body, uint rva)
    {
        if (body is not { } b || !_ctx.PdataRanges.TryGetValue(b, out var ranges)) return false;
        foreach (var (s, e) in ranges) if (rva >= s && rva < e + 16) return true;
        return false;
    }

    /// <summary>.pdata starts a verified head runs into stop being functions when nothing but .pdata names them.</summary>
    private void DropHeadedPdataStarts()
    {
        foreach (var (body, head) in _heads)
        {
            if (!_functions.ContainsKey(head) || !_functions.TryGetValue(body, out var source) || source != FunctionSource.Pdata) continue;
            _functions.Remove(body);
            _sortedStarts?.Remove(body);
            _ctx.FunctionStarts.Remove(body);
        }
    }
}
