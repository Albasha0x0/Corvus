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

    [GeneratedRegex(@"\\\\\.\\pipe\\[^\s\\""'<>|]+(?:\\[^\s\\""'<>|]+)*", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Pipe();

    [GeneratedRegex(@"^[A-Za-z0-9_.\-]{1,64}\.dll$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BareDll();

    [GeneratedRegex(@"^[A-Za-z]:\\[^\s""'<>|*?]+\.[A-Za-z0-9]{1,5}$", RegexOptions.CultureInvariant)]
    private static partial Regex WindowsFile();

    /// <summary>The facts of <paramref name="summary"/> and the notes naming what was not read; the strings of an image over the file-input size limit are not scanned.</summary>
    public static (List<HuntFact> Facts, List<string> Notes) Of(InspectionService.FileSummary summary, FileInput input, CancellationToken ct)
    {
        var facts = new List<HuntFact>();
        var notes = new List<string>();
        if (summary.File.Sha1.Length > 0) facts.Add(new(HuntKind.Sha1, summary.File.Sha1, IndicatorEvidence.Decoded));
        if (summary.File.Certificate is { Present: true, Signer: { Length: > 0 } signer })
            facts.Add(new(HuntKind.Signer, signer, IndicatorEvidence.Decoded));
        foreach (var i in IndicatorList.Of(summary).Indicators.Where(i => i.Type is "url" or "domain" or "ipv4" or "ipv6"))
            facts.Add(new(i.Type, i.Value, i.Evidence));
        foreach (var a in summary.Assemblies)
        {
            if (a.Values.Total > a.Values.Top.Count)
                notes.Add($"{a.Path}: {a.Values.Top.Count} of {a.Values.Total} extracted values were read for pipes, files and mutexes; extract_strings lists all.");
            foreach (var v in a.Values.Top)
            {
                var kind = v.Type switch { "named_pipe" => HuntKind.NamedPipe, "file_path" => HuntKind.FilePath, "mutex" => HuntKind.Mutex, _ => null };
                if (kind != null) facts.Add(new(kind, v.Value, IndicatorList.AssemblyEvidence(v)));
            }
        }
        if (input.Head.Length < 2 || input.Head[0] != 'M' || input.Head[1] != 'Z')
        {
            notes.Add("The version resource, imports and strings are read for PE images only.");
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
            var pe = PeFile.FromBytes(image, input.Path);
            if (pe.VersionInfo?.Get("OriginalFilename") is { Length: > 0 } original) facts.Add(new(HuntKind.OriginalFileName, original, IndicatorEvidence.Decoded));
            foreach (var module in pe.Imports.Select(i => i.Module).Distinct(StringComparer.OrdinalIgnoreCase))
                if (SideLoadable(module)) facts.Add(new(HuntKind.DllName, module, IndicatorEvidence.Reference));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            notes.Add($"The version resource and imports are unknown, the image did not parse: {ex.Message}");
        }
        facts.AddRange(Strings(image, notes, ct));
        return (facts, notes);
    }

    private static bool SideLoadable(string name) =>
        BareDll().IsMatch(name) && !KnownDlls.Contains(name) && !name.StartsWith("api-ms-", StringComparison.OrdinalIgnoreCase)
        && !name.StartsWith("ext-ms-", StringComparison.OrdinalIgnoreCase);

    // Pipe paths, library names without a folder and file paths among the printable ASCII and UTF-16 runs.
    private static IEnumerable<HuntFact> Strings(byte[] image, List<string> notes, CancellationToken ct)
    {
        var found = new Dictionary<(string, string), HuntFact>();
        int capped = 0;
        void Add(string kind, string value)
        {
            if (found.Count(f => f.Key.Item1 == kind) >= MaxPerKind) { capped++; return; }
            found.TryAdd((kind, value), new(kind, value, IndicatorEvidence.String));
        }
        foreach (var run in Runs(image, ct))
        {
            foreach (Match m in Pipe().Matches(run)) Add(HuntKind.NamedPipe, m.Value);
            if (BareDll().IsMatch(run) && SideLoadable(run)) Add(HuntKind.DllName, run);
            // A debug path names the build machine, not a file the program writes.
            else if (WindowsFile().IsMatch(run) && !run.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase)) Add(HuntKind.FilePath, run);
        }
        if (capped > 0) notes.Add($"{capped:N0} pipe, library and file strings past {MaxPerKind} per kind were not read.");
        return found.Values;
    }

    private static IEnumerable<string> Runs(byte[] image, CancellationToken ct)
    {
        // Wide strings are read at both parities of the file offset.
        foreach (var (step, start) in new[] { (1, 0), (2, 0), (2, 1) })
        {
            var run = new StringBuilder();
            for (int i = start; i + step <= image.Length; i += step)
            {
                if ((i & 0xFFFFF) == 0) ct.ThrowIfCancellationRequested();
                bool text = image[i] is >= 0x20 and < 0x7F && (step == 1 || image[i + 1] == 0);
                if (text && run.Length < 2_048) { run.Append((char)image[i]); continue; }
                if (run.Length >= 5) yield return run.ToString();
                run.Clear();
                if (text) run.Append((char)image[i]);
            }
            if (run.Length >= 5) yield return run.ToString();
        }
    }
}
