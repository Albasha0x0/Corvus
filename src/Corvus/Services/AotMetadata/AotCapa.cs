using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Iced.Intel;
using Corvus.Native;

namespace Corvus.Services;

/// <summary>A method a native call reaches, in .NET form: the type with its namespace ("System.IO.File", "List`1") and the member.</summary>
public sealed record AotCallee(string Namespace, string Type, string Member)
{
    /// <summary>"System.IO.File::WriteAllText", as capa names a .NET API.</summary>
    public string Api => $"{Class}::{Member}";

    /// <summary>The type with its namespace, as capa names a .NET class.</summary>
    public string Class => Namespace.Length > 0 ? $"{Namespace}.{Type}" : Type;
}

/// <summary>A direct call or tail jump at <see cref="Site"/> (RVA) to the function at <see cref="Target"/>, and the method it reaches.</summary>
public sealed record AotCall(uint Site, uint Target, AotCallee Callee);

/// <summary>A native function: start RVA, calls to named methods and loaded string literals.</summary>
public sealed record AotCodeFunction(uint Rva, IReadOnlyList<AotCall> Calls, IReadOnlyList<string> Strings);

/// <summary>Result of <see cref="AotCapa.Read"/>: functions with named calls, and counts of calls read, ambiguous and unnamed.</summary>
public sealed record AotCodeFeatures(IReadOnlyList<AotCodeFunction> Functions, int FunctionsRead, int Calls, int Ambiguous, int Unnamed);

/// <summary>A capa rule that matched: its name and namespace as the rule states them, and the VAs it matched at.</summary>
public sealed record CapaRuleMatch(string Name, string? Namespace, IReadOnlyList<ulong> Addresses);

/// <summary>
/// capa's result for a freeze file; State is "matched", "unavailable" or "unknown" (Note says why); Tested is false for
/// an untested capa version.
/// </summary>
public sealed record CapaResult(string State, string? Checker, bool Tested, IReadOnlyList<CapaRuleMatch> Rules, string? Note);

/// <summary>capa capabilities of a native binary for survey_features: state, version, matched rules, and notes on what was not read.</summary>
public sealed record CapaCapabilities(string State, string? Checker, bool Tested, IReadOnlyList<CapaCapability> Rules, IReadOnlyList<string> Notes);

/// <summary>A capa rule's name and namespace, the functions it matched and the first of them as "VA Ns.Type::Method".</summary>
public sealed record CapaCapability(string Name, string? Namespace, int Matches, IReadOnlyList<string> Methods);

/// <summary>
/// Writes each native function's direct calls to named methods as capa .NET features in a freeze file (version 3), so
/// capa's .NET rules match native code; indirect and virtual calls are not followed.
/// </summary>
public static class AotCapa
{
    /// <summary>The freeze format version capa 10.0.0 reads; it refuses any other.</summary>
    public const int FreezeVersion = 3;
    private static readonly byte[] Magic = "capa0000"u8.ToArray();
    private const int MaxFunctionBytes = (int)AotMetadataService.MaxFunctionSpan;

    /// <summary>
    /// The direct calls of each function in <paramref name="starts"/> (x86, x64, ARM64; other architectures read none); a
    /// function ends at the next start. <paramref name="strings"/> null: literals unknown.
    /// </summary>
    public static AotCodeFeatures Read(INativeImage image, IReadOnlyList<uint> starts, Func<uint, IReadOnlyList<AotCallee>> names,
        Func<uint, IReadOnlyList<string>>? strings, CancellationToken ct)
    {
        var sorted = starts.Distinct().Order().ToArray();
        var known = new HashSet<uint>(sorted);
        var functions = new List<AotCodeFunction>();
        int calls = 0, ambiguous = 0, unnamed = 0;
        var buffer = new byte[MaxFunctionBytes];
        for (int i = 0; i < sorted.Length; i++)
        {
            ct.ThrowIfCancellationRequested();
            uint start = sorted[i];
            if (image.SectionAt(start) is not { } section || (section.Access & SectionAccess.Execute) == 0) continue;
            uint end = Math.Min(i + 1 < sorted.Length ? sorted[i + 1] : uint.MaxValue, section.Rva + section.MappedSize);
            int length = image.Read(start, buffer.AsSpan(0, (int)Math.Min(end - start, (uint)MaxFunctionBytes)));
            var found = new List<AotCall>();
            foreach (var (site, target) in Branches(image, buffer.AsSpan(0, length).ToArray(), start))
            {
                // A jump inside the function is control flow, not a call.
                if (target >= start && target < start + (uint)length || !known.Contains(target)) continue;
                calls++;
                var callees = names(target);
                if (callees.Count == 0) { unnamed++; continue; }
                if (callees.Count > 1) { ambiguous++; continue; }
                found.Add(new AotCall(site, target, callees[0]));
            }
            var loaded = strings?.Invoke(start) ?? [];
            if (found.Count > 0 || loaded.Count > 0) functions.Add(new AotCodeFunction(start, found, loaded));
        }
        return new AotCodeFeatures(functions, sorted.Length, calls, ambiguous, unnamed);
    }

    /// <summary>Direct calls and unconditional jumps in <paramref name="code"/> (at <paramref name="rva"/>): their site and target RVAs.</summary>
    private static IEnumerable<(uint Site, uint Target)> Branches(INativeImage image, byte[] code, uint rva)
    {
        switch (image.Arch)
        {
            case NativeArch.X86 or NativeArch.X64:
                var decoder = Iced.Intel.Decoder.Create(image.Is64Bit ? 64 : 32, new ByteArrayCodeReader(code), rva, DecoderOptions.None);
                while (decoder.IP < rva + (ulong)code.Length)
                {
                    decoder.Decode(out var insn);
                    if (insn.IsInvalid) continue;
                    if (insn.FlowControl is FlowControl.Call or FlowControl.UnconditionalBranch && insn.Op0Kind is OpKind.NearBranch32 or OpKind.NearBranch64)
                        yield return ((uint)insn.IP, (uint)insn.NearBranchTarget);
                }
                break;
            case NativeArch.Arm64:
                for (int at = 0; at + 4 <= code.Length; at += 4)
                {
                    uint word = BinaryPrimitives.ReadUInt32LittleEndian(code.AsSpan(at));
                    // BL and B: opcode in the top six bits, a signed 26-bit word offset.
                    if ((word & 0x7C000000) != 0x14000000) continue;
                    int offset = (int)(word << 6) >> 4;
                    yield return (rva + (uint)at, unchecked(rva + (uint)at + (uint)offset));
                }
                break;
        }
    }

    /// <summary>The freeze file of <paramref name="features"/>: format dotnet, one basic block per function, one instruction per call site.</summary>
    public static byte[] Freeze(INativeImage image, AotCodeFeatures features, string md5, string sha1, string sha256)
    {
        using var json = new MemoryStream();
        using (var w = new Utf8JsonWriter(json))
        {
            ulong Va(uint rva) => image.ImageBase + rva;
            void Address(string name, ulong va)
            {
                w.WriteStartObject(name);
                w.WriteString("type", "absolute");
                w.WriteNumber("value", va);
                w.WriteEndObject();
            }
            void Feature(string type, string value, string? access = null)
            {
                w.WriteStartObject("feature");
                w.WriteString("type", type);
                if (access != null) w.WriteString("access", access);
                w.WriteString(type, value);
                w.WriteEndObject();
            }
            void Global(string type, string value)
            {
                w.WriteStartObject();
                Feature(type, value);
                w.WriteEndObject();
            }
            void Scoped(string scope, ulong owner, ulong at, string type, string value, string? access = null)
            {
                w.WriteStartObject();
                Address(scope, owner);
                Address("address", at);
                Feature(type, value, access);
                w.WriteEndObject();
            }

            w.WriteStartObject();
            w.WriteNumber("version", FreezeVersion);
            Address("base address", image.ImageBase);
            w.WriteStartObject("sample_hashes");
            w.WriteString("md5", md5);
            w.WriteString("sha1", sha1);
            w.WriteString("sha256", sha256);
            w.WriteEndObject();
            w.WriteString("flavor", "static");
            w.WriteStartObject("extractor");
            w.WriteString("name", "corvus aot");
            w.WriteString("version", "");
            w.WriteEndObject();
            w.WriteStartObject("features");
            w.WriteStartArray("global");
            Global("format", "dotnet");
            if (Os(image) is { } os) Global("os", os);
            if (Arch(image) is { } arch) Global("arch", arch);
            w.WriteEndArray();
            w.WriteStartArray("file");
            w.WriteEndArray();
            w.WriteStartArray("functions");
            foreach (var f in features.Functions)
            {
                ulong fva = Va(f.Rva);
                w.WriteStartObject();
                Address("address", fva);
                w.WriteStartArray("features");
                w.WriteEndArray();
                w.WriteStartArray("basic blocks");
                w.WriteStartObject();
                Address("address", fva);
                w.WriteStartArray("features");
                w.WriteEndArray();
                w.WriteStartArray("instructions");
                // capa sorts instructions by address; the strings sit at the function start.
                var sites = f.Calls.GroupBy(c => c.Site).Select(g => (Va: Va(g.Key), Calls: g.ToList(), Strings: (IReadOnlyList<string>)[])).ToList();
                if (f.Strings.Count > 0)
                {
                    int at = sites.FindIndex(s => s.Va == fva);
                    if (at >= 0) sites[at] = sites[at] with { Strings = f.Strings };
                    else sites.Add((fva, [], f.Strings));
                }
                foreach (var (va, calls, texts) in sites.OrderBy(s => s.Va))
                {
                    w.WriteStartObject();
                    Address("address", va);
                    w.WriteStartArray("features");
                    foreach (var c in calls)
                    {
                        if (Accessor(c.Callee.Member) is var (property, access))
                        {
                            Scoped("instruction", va, va, "property", $"{c.Callee.Class}::{property}", access);
                            Scoped("instruction", va, va, "property", $"{c.Callee.Class}::{property}");
                        }
                        else Scoped("instruction", va, va, "api", c.Callee.Api);
                        Scoped("instruction", va, va, "class", c.Callee.Class);
                        if (c.Callee.Namespace.Length > 0) Scoped("instruction", va, va, "namespace", c.Callee.Namespace);
                    }
                    foreach (var text in texts.Distinct()) Scoped("instruction", va, va, "string", text);
                    w.WriteEndArray();
                    w.WriteEndObject();
                }
                w.WriteEndArray();
                w.WriteEndObject();
                w.WriteEndArray();
                w.WriteEndObject();
            }
            w.WriteEndArray();
            w.WriteEndObject();
            w.WriteEndObject();
        }
        using var output = new MemoryStream();
        output.Write(Magic);
        using (var z = new ZLibStream(output, CompressionLevel.Optimal, leaveOpen: true)) json.WriteTo(z);
        return output.ToArray();
    }

    /// <summary>The freeze file for the binary at <paramref name="path"/>, with its hashes.</summary>
    public static byte[] Freeze(INativeImage image, AotCodeFeatures features, string path)
    {
        var bytes = File.ReadAllBytes(path);
        return Freeze(image, features, Convert.ToHexStringLower(MD5.HashData(bytes)), Convert.ToHexStringLower(SHA1.HashData(bytes)),
            Convert.ToHexStringLower(SHA256.HashData(bytes)));
    }

    /// <summary>The capa version the freeze format was tested with.</summary>
    public const string TestedVersion = "10.0.0";
    private static readonly TimeSpan Timeout = TimeSpan.FromMinutes(5);
    private const long MaxOutput = 64L * 1024 * 1024;

    /// <summary>The rules capa (CORVUS_CAPA) matches in <paramref name="freeze"/>; file-scope matches describe the stated format and are omitted.</summary>
    public static CapaResult Match(byte[] freeze, CancellationToken ct)
    {
        var probe = Native.Providers.ExternalTools.Probe(Native.Providers.ExternalTools.Capa);
        if (!probe.Usable) return new CapaResult("unavailable", null, false, [], $"capa {probe.Problem}; {probe.Remediation}");
        var version = probe.Version?.Split(' ', StringSplitOptions.RemoveEmptyEntries).LastOrDefault();
        bool tested = version == TestedVersion;
        var checker = $"capa {version ?? "(version unknown)"}";
        var dir = Native.Providers.PrivateFolder.Temp("capa", $"{Environment.ProcessId}-{Guid.NewGuid():N}");
        try
        {
            Native.Providers.PrivateFolder.Create(dir);
            var file = Path.Combine(dir, "features.frz");
            File.WriteAllBytes(file, freeze);
            var run = Native.Providers.ExternalTools.Run(probe.Path!, Native.Providers.ExternalTools.Arguments(Native.Providers.ExternalTools.Capa, "freeze", ("file", file)),
                Timeout, MaxOutput, ct);
            return Read(run, checker, tested);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new CapaResult("unknown", checker, tested, [], $"capa was not run: {ex.Message}");
        }
        finally
        {
            try { Directory.Delete(dir, true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    /// <summary>The rule matches of capa's JSON result document, or "unknown" with capa's error.</summary>
    internal static CapaResult Read(Native.Providers.ExternalTools.RunResult run, string checker, bool tested)
    {
        string Untested(string note) => tested ? note : $"{note}; the freeze format was tested with capa {TestedVersion}";
        if (run.StartError != null || run.TimedOut || run.Truncated || run.ExitCode != 0)
        {
            var why = run.StartError ?? (run.TimedOut ? $"no answer within {Timeout.TotalMinutes:0} min" : run.Truncated ? $"a result over {MaxOutput >> 20} MiB"
                : $"exit {run.ExitCode}: {LastLine(run.Stderr)}");
            return new CapaResult("unknown", checker, tested, [], Untested($"capa refused the freeze file or failed ({why})"));
        }
        var rules = new List<CapaRuleMatch>();
        try
        {
            using var doc = JsonDocument.Parse(run.Output);
            foreach (var rule in doc.RootElement.GetProperty("rules").EnumerateObject())
            {
                var meta = rule.Value.GetProperty("meta");
                var addresses = new List<ulong>();
                foreach (var m in rule.Value.GetProperty("matches").EnumerateArray())
                    if (m.ValueKind == JsonValueKind.Array && m.GetArrayLength() > 0 && m[0].TryGetProperty("value", out var v) && v.ValueKind == JsonValueKind.Number)
                        addresses.Add(v.GetUInt64());
                if (addresses.Count == 0) continue;
                var ns = meta.TryGetProperty("namespace", out var n) && n.ValueKind == JsonValueKind.String ? n.GetString() : null;
                rules.Add(new CapaRuleMatch(meta.TryGetProperty("name", out var name) ? name.GetString() ?? rule.Name : rule.Name, ns, [.. addresses.Order()]));
            }
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException or FormatException)
        {
            return new CapaResult("unknown", checker, tested, [], Untested($"capa's result could not be read ({ex.Message})"));
        }
        return new CapaResult("matched", checker, tested, [.. rules.OrderBy(r => r.Namespace, StringComparer.Ordinal).ThenBy(r => r.Name, StringComparer.Ordinal)],
            tested ? null : Untested($"{checker} ran"));
    }

    private const int MaxMethodsPerRule = 5;

    /// <summary>
    /// capa capabilities of the native binary beside <paramref name="image"/>'s dump; calls are read under the read lock,
    /// capa runs after it. Unavailable without capa; unknown, with the reason, when the binary is not found or not readable.
    /// </summary>
    public static CapaCapabilities Survey(Core.AssemblyWorkspace workspace, AotNavigator.Image image, AotStringService strings, CancellationToken ct)
    {
        if (image.Dump?.Files.GameAssembly is not { } path)
            return new("unknown", null, false, [], ["the native binary was not found beside the dump; capa reads its code"]);
        var probe = Native.Providers.ExternalTools.Probe(Native.Providers.ExternalTools.Capa);
        if (!probe.Usable) return new("unavailable", null, false, [], [$"capa {probe.Problem}; {probe.Remediation}"]);
        INativeImage binary;
        try { binary = NativeImageLoader.Open(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or ArgumentException or Core.ToolError)
        {
            return new("unknown", null, false, [], [$"{Path.GetFileName(path)}: not a readable native image ({ex.Message})"]);
        }
        var notes = new List<string>
        {
            "direct calls only: indirect and virtual calls are not followed",
            "one basic block per function: rules that need several blocks or a loop do not match",
        };
        var dump = image.Dump!;
        var (features, labels) = workspace.Read(() =>
        {
            var script = image.Script;
            IReadOnlyList<AotCallee> Names(uint rva)
            {
                var list = new List<AotCallee>();
                if (script != null)
                {
                    var (first, count) = script.MethodRange(rva);
                    for (int e = first; e < first + count; e++)
                        if (FromScriptName(script.MethodTypeName(e), script.MethodShortName(e)) is { } c && !list.Contains(c)) list.Add(c);
                }
                if (list.Count == 0)
                    foreach (var m in image.MethodsAt(rva))
                        if (FromMethod(m.Method) is var c && !list.Contains(c)) list.Add(c);
                return list;
            }
            Func<uint, IReadOnlyList<string>>? texts = null;
            try
            {
                if (dump.Files.HasLiterals && dump.References != null)
                    texts = rva => [.. strings.LiteralsUsedBy(dump, rva).Select(l => dump.Values[l.Literal])];
                else notes.Add($"string literals are not read: {dump.ReferenceProblem ?? "the dump lists none"}");
            }
            catch (Core.ToolError ex) { notes.Add($"string literals are not read: {ex.Message}"); }
            var read = Read(binary, image.Starts, Names, texts, ct);
            var named = read.Functions.ToDictionary(f => f.Rva, f => Names(f.Rva) is { Count: > 0 } n
                ? $"{n[0].Api}{(n.Count > 1 ? $" (+{n.Count - 1} sharing its code)" : "")}" : "an unnamed function");
            return (read, named);
        });
        if (features.Ambiguous > 0) notes.Add($"{features.Ambiguous} of {features.Calls} calls reach code several methods share and are left out");
        if (features.Unnamed > 0) notes.Add($"{features.Unnamed} of {features.Calls} calls reach functions no method names");
        var result = Match(Freeze(binary, features, path), ct);
        if (result.Note != null) notes.Add(result.Note);
        var rules = result.Rules.Select(r => new CapaCapability(r.Name, r.Namespace, r.Addresses.Count, [.. r.Addresses.Take(MaxMethodsPerRule)
            .Select(va => $"0x{va:X} {(va >= binary.ImageBase && labels.TryGetValue((uint)(va - binary.ImageBase), out var label) ? label : "a function")}")])).ToList();
        return new(result.State, result.Checker, result.Tested, rules, notes);
    }

    private static string LastLine(string text) =>
        text.ReplaceLineEndings("\n").Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).LastOrDefault() is { } line
            ? line[..Math.Min(line.Length, 500)] : "no message";

    /// <summary>A property accessor as capa reports it: get_X reads property X, set_X writes it; null for other methods.</summary>
    private static (string Property, string Access)? Accessor(string member) =>
        member.Length > 4 && member.StartsWith("get_", StringComparison.Ordinal) ? (member[4..], "read")
        : member.Length > 4 && member.StartsWith("set_", StringComparison.Ordinal) ? (member[4..], "write") : null;

    /// <summary>capa's os feature for the binary's format: PE windows, ELF android, else null.</summary>
    private static string? Os(INativeImage image) => image.Format switch
    {
        ImageFormat.Pe => "windows",
        ImageFormat.Elf => "android",
        _ => null,
    };

    private static string? Arch(INativeImage image) => image.Arch switch
    {
        NativeArch.X86 => "i386",
        NativeArch.X64 => "amd64",
        NativeArch.Arm64 => "aarch64",
        _ => null,
    };

    /// <summary>A script.json name split at "$$" in .NET form ("Ns", "Type`1", "Method"); null when either part is empty.</summary>
    public static AotCallee? FromScriptName(string type, string member)
    {
        if (type.Length == 0 || member.Length == 0) return null;
        member = AotNames.StripArgs(member);
        var plain = new StringBuilder();
        int depth = 0, arity = 0;
        foreach (char ch in type)
        {
            if (ch == '<') { if (depth++ == 0) arity = 1; continue; }
            if (ch == '>') { if (--depth == 0) plain.Append('`').Append(arity); continue; }
            if (depth == 1 && ch == ',') arity++;
            if (depth == 0) plain.Append(ch);
        }
        var name = plain.ToString();
        int dot = name.LastIndexOf('.');
        return dot < 0 ? new AotCallee("", name, member) : new AotCallee(name[..dot], name[(dot + 1)..], member);
    }

    /// <summary>A dummy method in .NET form: the outermost type's namespace, nested types joined by '/', as capa names them.</summary>
    public static AotCallee FromMethod(dnlib.DotNet.MethodDef method)
    {
        var type = method.DeclaringType;
        var outer = type;
        while (outer.DeclaringType != null) outer = outer.DeclaringType;
        var full = type.FullName;
        var ns = outer.Namespace?.String ?? "";
        return new AotCallee(ns, ns.Length > 0 && full.StartsWith(ns + ".", StringComparison.Ordinal) ? full[(ns.Length + 1)..] : full, method.Name);
    }
}
