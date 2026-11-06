using System.Text;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native.Pe;

namespace Corvus.Services.Analysis.Hunts;

/// <summary>Reads the facts of a summarized file that <see cref="KqlHunts"/> writes queries for.</summary>
public static partial class HuntFacts
{
    /// <summary>Strings found per kind; a scan past it stops and is named in a note.</summary>
    public const int MaxPerKind = 200;

    // Libraries the loader always takes from the system folder, so a copy beside a program is not loaded.
    private static readonly HashSet<string> KnownDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "advapi32.dll", "clbcatq.dll", "combase.dll", "comdlg32.dll", "coml2.dll", "difxapi.dll", "gdi32.dll", "gdiplus.dll", "imagehlp.dll",
        "imm32.dll", "kernel32.dll", "kernelbase.dll", "msctf.dll", "msvcrt.dll", "normaliz.dll", "nsi.dll", "ntdll.dll", "ole32.dll",
        "oleaut32.dll", "psapi.dll", "rpcrt4.dll", "sechost.dll", "setupapi.dll", "shcore.dll", "shell32.dll", "shlwapi.dll", "user32.dll",
        "wldap32.dll", "ws2_32.dll",
        // The runtime bootstrap that every managed image imports.
        "mscoree.dll",
    };

    [GeneratedRegex(@"\\\\\.\\pipe\\[^\s\\<>|]+(?:\\[^\s\\<>|]+)*", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Pipe();

    [GeneratedRegex(@"^(?:(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|SOFTWARE|Software)\\|(?:SYSTEM|System)\\CurrentControlSet\\)[^""]+$", RegexOptions.CultureInvariant)]
    private static partial Regex RegistryPath();

    [GeneratedRegex(@"^[A-Za-z0-9_\-][A-Za-z0-9_.\-]{0,63}\.dll$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BareDll();

    [GeneratedRegex(@"^[A-Za-z]:\\[^\s""<>|*?]+\.[A-Za-z0-9]{1,5}$", RegexOptions.CultureInvariant)]
    private static partial Regex WindowsFile();

    /// <summary>The facts of <paramref name="summary"/> and the notes naming what was not read; the strings of an image over the file-input size limit are not scanned.</summary>
    public static (List<HuntFact> Facts, List<string> Notes) Of(InspectionService.FileSummary summary, FileInput input, CancellationToken ct)
    {
        var facts = new List<HuntFact>();
        var notes = new List<string>();
        bool pe = input.Head.Length >= 2 && input.Head[0] == 'M' && input.Head[1] == 'Z';
        // Regions are read once, from the bytes the strings come from.
        var hot = input.Streamed || !IsExecutable(input) ? null : HighEntropyWindows(input.Image, ct);
        int compressed = 0;
        var imports = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (summary.File.Sha1.Length > 0) facts.Add(new(HuntKind.Sha1, summary.File.Sha1, IndicatorEvidence.Computed));
        if (summary.File.Certificate is { Present: true, Signer: { Length: > 0 } signer })
            facts.Add(new(HuntKind.Signer, signer, IndicatorEvidence.Computed));
        else if (summary.File.Certificate is { Present: true })
            notes.Add("The signer is unknown: the embedded certificate names none.");
        else if (pe)
            notes.Add("The signer is unknown: the file has no embedded signature, and catalog signatures are not read.");
        foreach (var i in IndicatorList.Of(summary).Indicators.Where(i => i.Type is "url" or "domain" or "ipv4" or "ipv6"))
        {
            if (hot != null && i.Sources.All(src => src == "native") && StringOffset(i.FirstLocation) is { } at && InHot(hot, at)) { compressed++; continue; }
            facts.Add(new(i.Type, i.Value, i.Evidence));
        }
        foreach (var a in summary.Assemblies)
        {
            if (a.Values.Total > a.Values.Top.Count)
                notes.Add($"{a.Path}: {a.Values.Top.Count} of {a.Values.Total} extracted values were read for pipes, files and mutexes; extract_strings lists all.");
            foreach (var v in a.Values.Top)
            {
                var kind = v.Type switch { "named_pipe" => HuntKind.NamedPipe, "file_path" => HuntKind.FilePath, "registry_key" => HuntKind.RegistryKey, "mutex" => HuntKind.Mutex, _ => null };
                if (kind != null) facts.Add(new(kind, v.Value, IndicatorList.AssemblyEvidence(v)));
            }
        }
        if (!pe)
        {
            notes.Add("The version resource, imports and strings are read for PE images only.");
            if (compressed > 0) notes.Add(CompressedNote(compressed));
            if (!IsExecutable(input)) notes.Add("The file is not an executable image: unpack_container lists its entries to hunt each one.");
            return (facts, notes);
        }
        if (input.Streamed)
        {
            notes.Add($"The image is streamed ({input.Length:N0} bytes): its version resource, imports and strings were not read.");
            return (facts, notes);
        }
        var image = input.Image;
        try
        {
            var file = PeFile.FromBytes(image, input.Path);
            if (file.VersionInfo?.Get("OriginalFilename") is { Length: > 0 } original) facts.Add(new(HuntKind.OriginalFileName, original, IndicatorEvidence.Decoded));
            foreach (var module in file.Imports.Select(i => i.Module).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                imports.Add(module);
                if (SideLoadable(module)) facts.Add(new(HuntKind.DllName, module, IndicatorEvidence.Reference));
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            notes.Add($"The version resource and imports are unknown, the image did not parse: {ex.Message}");
        }
        facts.AddRange(Strings(image, hot!, imports, ref compressed, notes, ct));
        if (compressed > 0) notes.Add(CompressedNote(compressed));
        return (facts, notes);
    }

    /// <summary>False for a note on the signer alone; every other note names facts that were not read.</summary>
    public static bool LimitsFacts(string note) => !note.StartsWith("The signer is unknown", StringComparison.Ordinal);

    /// <summary>True for a PE or ELF image, the files whose process and image-load events the SHA-1 queries read.</summary>
    public static bool IsExecutable(FileInput input) =>
        input.Head.Length >= 2 && input.Head[0] == 'M' && input.Head[1] == 'Z' || Corvus.Native.NativeImageLoader.Detect(input.Head) == Corvus.Native.NativeFileKind.Elf;

    // Strings inside data this compressed are noise, not names the program uses.
    private const int WindowBytes = 4_096;

    private static string CompressedNote(int count) =>
        $"{count:N0} string fact(s) lie in compressed or high-entropy regions (entropy {Corvus.Native.PackerDetection.HighEntropy} or more per {WindowBytes}-byte window) and have no query.";

    private static bool[] HighEntropyWindows(byte[] image, CancellationToken ct)
    {
        var hot = new bool[(image.Length + WindowBytes - 1) / WindowBytes];
        for (int w = 0; w < hot.Length; w++)
        {
            ct.ThrowIfCancellationRequested();
            var span = image.AsSpan(w * WindowBytes, Math.Min(WindowBytes, image.Length - w * WindowBytes));
            hot[w] = span.Length == WindowBytes && Blob.Entropy(span) >= Corvus.Native.PackerDetection.HighEntropy;
        }
        return hot;
    }

    private static bool InHot(bool[] hot, long offset) => offset / WindowBytes < hot.Length && hot[offset / WindowBytes];

    [GeneratedRegex(@"file offset 0x([0-9a-f]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex OffsetText();

    private static long? StringOffset(string location) =>
        OffsetText().Match(location) is { Success: true } m && long.TryParse(m.Groups[1].Value, System.Globalization.NumberStyles.HexNumber, null, out var at) ? at : null;

    // A pipe path written inside quotes ends before the closing quote.
    private static string Unquoted(string run, Match m) =>
        m.Index > 0 && run[m.Index - 1] is '"' or '\'' && m.Value.IndexOf(run[m.Index - 1], StringComparison.Ordinal) is var q and > 0
            ? m.Value[..q] : m.Value.TrimEnd(Values.TrailingPunctuation);

    private static bool SideLoadable(string name) =>
        BareDll().IsMatch(name) && !KnownDlls.Contains(name) && !name.StartsWith("api-ms-", StringComparison.OrdinalIgnoreCase)
        && !name.StartsWith("ext-ms-", StringComparison.OrdinalIgnoreCase);

    private static readonly HashSet<string> BuildFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdb", ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inl", ".ipp", ".cs", ".rs", ".obj", ".asm",
        ".hlsl", ".hlsli", ".fx", ".idl", ".def", ".rc", ".lib",
    };

    // A printable byte before a name joins its run, so Fd3d10.dll beside
    // d3d10.dll reads as a second library.
    private static bool HasStrayByte(string name, HashSet<string> names)
    {
        var tail = name[1..];
        return names.Contains(tail) || KnownDlls.Contains(tail) || tail.StartsWith("api-ms-", StringComparison.OrdinalIgnoreCase)
            || tail.StartsWith("ext-ms-", StringComparison.OrdinalIgnoreCase);
    }

    // Pipe paths, registry keys, library names without a folder and file paths among the printable ASCII and UTF-16 runs.
    private static IEnumerable<HuntFact> Strings(byte[] image, bool[] hot, HashSet<string> imports, ref int compressed, List<string> notes, CancellationToken ct)
    {
        var found = new Dictionary<(string, string), HuntFact>();
        int capped = 0, inHot = 0;
        void Add(string kind, string value)
        {
            if (found.Count(f => f.Key.Item1 == kind) >= MaxPerKind) { capped++; return; }
            found.TryAdd((kind, value), new(kind, value, IndicatorEvidence.String));
        }
        foreach (var (run, offset) in Runs(image, ct))
        {
            if (InHot(hot, offset)) { inHot++; continue; }
            foreach (Match m in Pipe().Matches(run)) Add(HuntKind.NamedPipe, Unquoted(run, m));
            if (RegistryPath().IsMatch(run)) Add(HuntKind.RegistryKey, Values.BeforeMessage(run));
            if (BareDll().IsMatch(run) && SideLoadable(run)) Add(HuntKind.DllName, run);
            // Debug and assertion paths name the build machine, not a file the
            // program writes.
            else if (WindowsFile().IsMatch(run) && !BuildFiles.Contains(Path.GetExtension(run))) Add(HuntKind.FilePath, run);
        }
        compressed += inHot;
        if (capped > 0) notes.Add($"{capped:N0} pipe, registry, library and file strings past {MaxPerKind} per kind were not read.");
        var names = new HashSet<string>(imports, StringComparer.OrdinalIgnoreCase);
        names.UnionWith(found.Keys.Where(k => k.Item1 == HuntKind.DllName).Select(k => k.Item2));
        return found.Values.Where(f => f.Kind != HuntKind.DllName || !HasStrayByte(f.Value, names));
    }

    private static IEnumerable<(string Text, int Offset)> Runs(byte[] image, CancellationToken ct)
    {
        // Wide strings are read at both parities of the file offset.
        foreach (var (step, start) in new[] { (1, 0), (2, 0), (2, 1) })
        {
            var run = new StringBuilder();
            int begin = 0;
            for (int i = start; i + step <= image.Length; i += step)
            {
                if ((i & 0xFFFFF) == 0) ct.ThrowIfCancellationRequested();
                bool text = image[i] is >= 0x20 and < 0x7F && (step == 1 || image[i + 1] == 0);
                if (text && run.Length < 2_048) { if (run.Length == 0) begin = i; run.Append((char)image[i]); continue; }
                if (run.Length >= 5) yield return (run.ToString(), begin);
                run.Clear();
                if (text) { begin = i; run.Append((char)image[i]); }
            }
            if (run.Length >= 5) yield return (run.ToString(), begin);
        }
    }
}
