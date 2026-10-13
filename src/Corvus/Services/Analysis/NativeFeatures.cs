using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Calls;
using Corvus.Native.Code;
using Corvus.Native.Msvc;

namespace Corvus.Services.Analysis;

/// <summary>
/// Evaluates <see cref="Features"/> rule features over a native image: "native:" against static and late-bound imports
/// (API set and kernel32 / kernelbase names agree), "str:" against the strings code and data reference, "arg:" against
/// recovered call arguments, "section:" against section names, permissions and entropy, "rtti:" against MSVC RTTI class
/// names. "api:" (managed calls) never matches. Evidence locations are addresses with their function.
/// </summary>
internal sealed class NativeFeatureScan(NativeCodeIndex index, CancellationToken ct)
{
    private const int MaxLocations = 5;
    private const int MaxStringChars = 4096;
    private const int MinEntropyBytes = 4096;
    private readonly CallAnalysis? _calls = CallAnalysis.Supports(index) ? CallAnalysis.For(index) : null;
    private readonly List<string> _notes = [];
    private List<(uint Rva, string Text)>? _strings;
    private List<MsvcRttiClass>? _classes;
    private DynamicImportSet? _dynamic;

    public IReadOnlyList<string> Notes => _notes;

    public NativeCodeIndex Index => index;

    private DynamicImportSet Dynamic => _dynamic ??= _calls?.DynamicImports(ct) ?? new DynamicImportSet();

    private string Va(uint rva) => NativeAddress.Va(index.Image, rva);

    private string Where(uint rva) => index.FunctionAt(rva) is { } f ? $"{f.Name}+0x{rva - f.Start:X} @{Va(rva)}" : $"@{Va(rva)}";

    public Evidence? Evaluate(string feature)
    {
        int colon = feature.IndexOf(':');
        var kind = feature[..colon];
        var pattern = feature[(colon + 1)..];
        var locations = new List<string>();
        int count = 0;
        void Hit(string where, int n = 1)
        {
            count += n;
            if (locations.Count < MaxLocations && !locations.Contains(where)) locations.Add(where);
        }
        ct.ThrowIfCancellationRequested();
        switch (kind)
        {
            case "native":
                Imports(pattern, Hit);
                break;
            case "str":
            {
                var regex = new Regex(pattern, RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
                foreach (var (rva, text) in Strings())
                {
                    try { if (regex.IsMatch(text)) Hit($"\"{Clip(text)}\" @{Va(rva)}" + (FirstReference(rva) is { } r ? $" in {Where(r)}" : "")); }
                    catch (RegexMatchTimeoutException) { }
                }
                break;
            }
            case "arg":
                Arguments(pattern, Hit);
                break;
            case "section":
                Sections(pattern, Hit);
                break;
            case "rtti":
            {
                var regex = new Regex(pattern, RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
                foreach (var c in Classes())
                {
                    try { if (regex.IsMatch(c.Name)) Hit($"class {c.Name}" + (c.Vtables.Count > 0 ? $" (vftable @{Va(c.Vtables[0].VftableRva)})" : "")); }
                    catch (RegexMatchTimeoutException) { }
                }
                break;
            }
        }
        return count == 0 ? null : new Evidence(feature, count, locations);
    }

    private static string Clip(string s) => s.Length <= 80 ? s : s[..80] + "…";

    private uint? FirstReference(uint rva) => index.RefsTo(rva, 1) is [var x] ? x.From : null;

    /// <summary>A rule's module matches an import's: same name, an API set, or kernel32 / kernelbase for each other.</summary>
    internal static bool SameModule(string actual, string expected)
    {
        var a = Path.GetFileNameWithoutExtension(actual.Trim());
        if (a.Equals(expected, StringComparison.OrdinalIgnoreCase)) return true;
        if (ApiSetSchema.IsApiSetName(actual.Trim()) || a.StartsWith("api-ms-", StringComparison.OrdinalIgnoreCase) || a.StartsWith("ext-ms-", StringComparison.OrdinalIgnoreCase))
            return true;
        static bool Kernel(string m) => m.Equals("kernel32", StringComparison.OrdinalIgnoreCase) || m.Equals("kernelbase", StringComparison.OrdinalIgnoreCase);
        return Kernel(a) && Kernel(expected);
    }

    /// <summary>"module!Entry" with '*' wildcards and an optional A / W suffix.</summary>
    private static (string Module, Regex Entry) ParseApi(string pattern)
    {
        int bang = pattern.IndexOf('!');
        var module = bang >= 0 ? pattern[..bang] : "*";
        var entry = bang >= 0 ? pattern[(bang + 1)..] : pattern;
        var regex = new Regex("^" + Regex.Escape(entry).Replace(@"\*", ".*") + "[AW]?$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
        return (module, regex);
    }

    private void Imports(string pattern, Action<string, int> hit)
    {
        var (module, entry) = ParseApi(pattern);
        foreach (var imp in index.Image.Imports)
        {
            if (imp.Name == null || !entry.IsMatch(imp.Name) || (module != "*" && !SameModule(imp.Module, module))) continue;
            var callers = index.Callers(imp);
            var first = callers.Count > 0 ? $", first in {Where(callers[0].From)}" : "";
            hit($"import {imp.Module}!{imp.Name} ({callers.Count} call sites{first})", Math.Max(1, callers.Count));
        }
        foreach (var d in Dynamic.Imports)
        {
            if (!entry.IsMatch(d.Name) || (module != "*" && d.Module != null && !SameModule(d.Module, module))) continue;
            hit($"late-bound {d.FullName} via GetProcAddress in {Where(d.CallSite)}", Math.Max(1, d.PointerCalls.Count));
        }
    }

    /// <summary>"[module!]Api#index=ENTRY": calls whose argument <c>index</c> is a constant with the flag / enumeration entry.</summary>
    private void Arguments(string pattern, Action<string, int> hit)
    {
        if (_calls == null) return;
        int hash = pattern.IndexOf('#'), eq = pattern.IndexOf('=');
        if (hash < 0 || eq < hash || !int.TryParse(pattern.AsSpan(hash + 1, eq - hash - 1), out int argIndex)) return;
        var (module, entry) = ParseApi(pattern[..hash]);
        var wanted = pattern[(eq + 1)..];
        var sites = new Dictionary<uint, CallSiteInfo>();
        foreach (var imp in index.Image.Imports)
        {
            if (imp.Name == null || !entry.IsMatch(imp.Name) || (module != "*" && !SameModule(imp.Module, module))) continue;
            foreach (var s in _calls.CallsTo(imp, 20_000, ct)) sites.TryAdd(s.Rva, s);
        }
        foreach (var d in Dynamic.Imports.Where(d => entry.IsMatch(d.Name)))
            foreach (var call in d.PointerCalls)
                if (_calls.CallAt(call, ct) is { } s) sites.TryAdd(s.Rva, s);
        foreach (var s in sites.Values.OrderBy(s => s.Rva))
        {
            if (argIndex >= s.Arguments.Count || s.Signature == null || argIndex >= s.Signature.Params.Count) continue;
            var a = s.Arguments[argIndex];
            if (a.Kind != ArgKind.Immediate || a.Value is not { } value) continue;
            var e = s.Signature.Params[argIndex].Enum;
            bool match = e != null ? e.Has(value, wanted) : ulong.TryParse(wanted, out var n) && n == value;
            if (match) hit($"{Where(s.Rva)}: {s.Display}", 1);
        }
    }

    private void Sections(string pattern, Action<string, int> hit)
    {
        foreach (var s in index.Image.Sections)
        {
            if (pattern.StartsWith("entropy>", StringComparison.Ordinal)
                && double.TryParse(pattern.AsSpan(8), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var min))
            {
                if (DenseByDesign(s.Name)) continue;
                int size = (int)Math.Min(Math.Min(s.RawSize, s.MappedSize), 64u << 20);
                if (size < MinEntropyBytes) continue;
                double h = Entropy(s.Rva, size);
                if (h > min) hit($"section {s.Name} entropy {h:0.00} ({size:N0} bytes)", 1);
            }
            else if (pattern.StartsWith("name=", StringComparison.Ordinal))
            {
                try { if (Regex.IsMatch(s.Name, pattern[5..], RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1))) hit($"section {s.Name}", 1); }
                catch (RegexMatchTimeoutException) { }
            }
            else if (pattern == "wx" && (s.Access & SectionAccess.Write) != 0 && s.IsExecutable)
                hit($"section {s.Name} is writable and executable", 1);
        }
    }

    /// <summary>
    /// Sections whose high entropy says nothing about packing: resources (compressed images), ELF hash tables and symbol data,
    /// .gnu_debugdata (xz-compressed symbols), Mach-O link edit data.
    /// </summary>
    internal static bool DenseByDesign(string name) =>
        name.Equals(".rsrc", StringComparison.OrdinalIgnoreCase) || name is ".gnu.hash" or ".hash" or ".gnu_debugdata" or ".dynsym" or ".symtab"
        || name.StartsWith(".note", StringComparison.Ordinal) || name.StartsWith("__LINKEDIT", StringComparison.Ordinal);

    private double Entropy(uint rva, int size)
    {
        var bytes = new byte[size];
        int n = index.Image.Read(rva, bytes);
        Span<int> counts = stackalloc int[256];
        for (int i = 0; i < n; i++) counts[bytes[i]]++;
        double h = 0;
        foreach (var c in counts)
            if (c > 0) { double p = (double)c / n; h -= p * Math.Log2(p); }
        return h;
    }

    private List<(uint, string)> Strings()
    {
        if (_strings != null) return _strings;
        _strings = new List<(uint, string)>(index.Strings.Count);
        int i = 0;
        foreach (var s in index.Strings)
        {
            if ((++i & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            _strings.Add((s.Rva, index.ReadString(s, MaxStringChars)));
        }
        return _strings;
    }

    private List<MsvcRttiClass> Classes()
    {
        if (_classes != null) return _classes;
        try { _classes = [.. Native.Itanium.CppRtti.Analyze(index.Image, ct).Classes]; }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _notes.Add($"RTTI not read ({ex.GetType().Name}: {ex.Message})");
            _classes = [];
        }
        return _classes;
    }
}
