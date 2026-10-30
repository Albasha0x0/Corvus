using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>view=certificate: a PEM, DER, PKCS #7 or PKCS #12 file's certificates, chains with local trust verdicts, and other blocks.</summary>
internal sealed class CertificateFileView : IFileSummaryView
{
    private const int DefaultLimit = 50, MaxLimit = 1000, MaxRows = 500;

    public sealed record Facts(string Format, long Total, long Offset, long? Next, IReadOnlyList<CertificateEntry> Certificates,
        IReadOnlyList<CertificateChain> Chains, IReadOnlyList<CertificateFileItem> Items, IReadOnlyList<string> Notes);

    public string Name => "certificate";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (file.Streamed || !CertificateFile.Looks(file.Head, file.Length, file.Path)) return null;
        bool asked = file.Options.View == Name;
        CertificateFile f;
        try { f = CertificateFile.Read(file.Bytes, checkMachine: asked, ct); }
        catch (InvalidDataException ex)
        {
            if (!asked) return null;
            throw new ToolError(ErrorCode.MalformedInput, $"{Path.GetFileName(file.Path)}: not a readable certificate file: {ex.Message}");
        }
        int limit = Math.Clamp(file.Options.Limit ?? DefaultLimit, 1, MaxLimit);
        int offset = (int)Math.Min(Math.Max(0, file.Options.Offset), f.Certificates.Count);
        var page = f.Certificates.Skip(offset).Take(limit).ToList();
        long? next = offset + page.Count < f.Certificates.Count ? offset + page.Count : null;
        var notes = new List<string>(f.Notes.Take(MaxRows));
        if (next != null) notes.Add($"offset={next} lists the next certificates");
        if (f.Chains.Count > MaxRows) notes.Add($"chains: the first {MaxRows} of {f.Chains.Count:N0}");
        if (f.Items.Count > MaxRows) notes.Add($"other blocks: the first {MaxRows} of {f.Items.Count:N0}");
        return new FileView(new Facts(f.Format, f.Certificates.Count, offset, next, page, f.Chains.Take(MaxRows).ToList(), f.Items.Take(MaxRows).ToList(), notes),
            Highlights(f)) { Indicators = IndicatorList.FromCertificates("certificate", f.Certificates, ct) };
    }

    private static List<string> Highlights(CertificateFile f)
    {
        var kinds = f.Items.GroupBy(i => i.Kind).Select(g => $"{g.Count()} {g.Key}{(g.Count() > 1 && !g.Key.EndsWith('s') ? "s" : "")}");
        var list = new List<string>
        {
            $"{f.Format}: {f.Certificates.Count} certificate(s) in {f.Chains.Count} chain(s)" + (f.Items.Count > 0 ? $"; {string.Join(", ", kinds)}" : "") + ".",
        };
        foreach (var chain in f.Chains.Take(3))
        {
            var leaf = f.Certificates[chain.Path[0]];
            list.Add($"{leaf.Subject} ({leaf.Key}, until {leaf.NotAfter:yyyy-MM-dd}): {chain.Path.Count} certificate(s), {chain.End}" +
                (chain.Problems.Count > 0 ? $"; {chain.Problems[0]}" : "") + ".");
        }
        if (f.Items.Any(i => i.Kind == "private key")) list.Add("The file holds a private key; its bytes are not shown.");
        return list;
    }
}
