using System.Buffers.Binary;

namespace Corvus.Native.Pe;

public sealed partial class PeFile
{
    private const int CookieSampleFunctions = 2000;
    private const int CookiePrologueBytes = 64;

    private Lazy<uint?> codeSecurityCookie = null!;

    /// <summary>The load config's security cookie as an RVA, or null when it names none or lies outside the image.</summary>
    public uint? LoadConfigSecurityCookieRva =>
        LoadConfig is { SecurityCookie: not 0 } lc && TryVaToRva(lc.SecurityCookie, out var rva) && rva < SizeOfImage ? rva : null;

    /// <summary>
    /// The RVA of the global that sampled x64 prologues load and xor with the frame pointer, or null when no pattern
    /// repeats or the image has no function table.
    /// </summary>
    public uint? CodeSecurityCookieRva => codeSecurityCookie.Value;

    /// <summary>The security cookie global from the load config, else from code; null when neither identifies one.</summary>
    public uint? SecurityCookieRva => LoadConfigSecurityCookieRva ?? CodeSecurityCookieRva;

    private uint? FindCodeSecurityCookie()
    {
        if (Arch != NativeArch.X64 || RuntimeFunctions.Count == 0) return null;
        var functions = RuntimeFunctions;
        int stride = Math.Max(1, functions.Count / CookieSampleFunctions);
        var hits = new Dictionary<uint, int>();
        int sampled = 0;
        Span<byte> code = stackalloc byte[CookiePrologueBytes];
        for (int i = 0; i < functions.Count; i += stride)
        {
            var f = functions[i];
            sampled++;
            if (f.EndRva <= f.BeginRva) continue;
            int n = Read(f.BeginRva, code[..(int)Math.Min(CookiePrologueBytes, f.EndRva - f.BeginRva)]);
            if (CookieLoadTarget(f.BeginRva, code[..n]) is { } target) hits[target] = hits.GetValueOrDefault(target) + 1;
        }
        if (hits.Count == 0) return null;
        var best = hits.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key).First();
        return best.Value >= 2 || sampled == 1 ? best.Key : null;
    }

    // Matches "mov rax, [rip+disp32]; xor rax, rsp|rbp" in either xor encoding
    // and returns the first loaded RVA that lies in writable data.
    private uint? CookieLoadTarget(uint rva, ReadOnlySpan<byte> code)
    {
        for (int i = 0; i + 10 <= code.Length; i++)
        {
            if (code[i] != 0x48 || code[i + 1] != 0x8B || code[i + 2] != 0x05) continue;
            bool xor = code[i + 7] == 0x48 && ((code[i + 8] == 0x33 && code[i + 9] is 0xC4 or 0xC5) || (code[i + 8] == 0x31 && code[i + 9] is 0xE0 or 0xE8));
            if (!xor) continue;
            long target = (long)rva + i + 7 + BinaryPrimitives.ReadInt32LittleEndian(code[(i + 3)..]);
            if (target <= 0 || target >= SizeOfImage || target % 8 != 0) continue;
            var section = SectionAt((uint)target);
            if (section is { IsExecutable: false } && (section.Access & SectionAccess.Write) != 0) return (uint)target;
        }
        return null;
    }
}
