using System.Diagnostics;
using System.Text;
using Corvus.Core;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// The byte-fidelity contract over the sweep's libraries (see <see cref="SweepCatalog"/>): saving with no edits writes
/// the original file, and writing the module again (as any edit makes save_assembly do) gives byte-identical method
/// bodies and signatures, or lists each one that differs. Compared independently of the writer's own check. Libraries
/// are checked in parallel, largest first, each in its own workspace; nothing here is timed.
/// </summary>
[Trait("Speed", "Slow")]
public sealed class SaveFidelitySweepTests(ITestOutputHelper output)
{
    private sealed record Row(SweepCatalog.Entry Entry, int Methods, int Kept, int Changed, int Unexplained, bool OriginalSaved, bool SameSurvey, TimeSpan Write, string? Example);

    [SweepFact]
    public void LibrariesSaveByteIdenticallyOrReportEveryDifference()
    {
        using var dir = new TempDir();
        var entries = SweepCatalog.Entries(SweepCatalog.Full).Where(e => e.Path != null).ToList();
        var results = new Row[entries.Count];
        var largestFirst = Enumerable.Range(0, entries.Count).OrderByDescending(i => new FileInfo(entries[i].Path!).Length);
        Parallel.ForEach(largestFirst, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
            i => results[i] = Check(entries[i], dir.File($"{i}-{Path.GetFileName(entries[i].Path!)}")));
        var rows = results.ToList();

        output.WriteLine(Table(rows));
        Assert.NotEmpty(rows);
        var failures = rows.Where(r => !r.OriginalSaved || r.Unexplained > 0 || !r.SameSurvey)
            .Select(r => $"{r.Entry.Origin} {r.Entry.Name}: {(r.OriginalSaved ? "" : "unmodified save differs from the original; ")}" +
                         $"{(r.SameSurvey ? "" : "the unmodified save lists other members than a rewrite; ")}{r.Unexplained} unreported difference(s), e.g. {r.Example}").ToList();
        Assert.True(failures.Count == 0, "save fidelity:\n" + string.Join("\n", failures));
    }

    /// <summary>One library; its unmodified save goes to <paramref name="target"/>.</summary>
    private static Row Check(SweepCatalog.Entry entry, string target)
    {
        var original = File.ReadAllBytes(entry.Path!);
        using var workspace = new AssemblyWorkspace(new ServerOptions { BackgroundIndexing = false, WatchFiles = false });
        var edits = new Services.EditService(workspace, null!, null!);
        var asm = workspace.Load(entry.Path!);

        // No edits: the original file, byte for byte.
        workspace.Read(() => edits.Save(asm, target, overwrite: true));
        bool originalSaved = File.ReadAllBytes(target).AsSpan().SequenceEqual(original);
        File.Delete(target);
        var survey = workspace.Read(asm.SurveyOriginal);

        // Written again: every body and signature as in the original, or listed as changed.
        var start = Stopwatch.GetTimestamp();
        using var ms = new MemoryStream();
        var report = workspace.Read(() => asm.Write(ms));
        var time = Stopwatch.GetElapsedTime(start);
        var written = ms.ToArray();
        var differ = SaveFidelity.Differences(original, written);
        var unexplained = differ.Except(SaveFidelity.Listed(report, changesBytes: true)).ToList();
        int methods = asm.Module.GetTypes().Sum(t => t.Methods.Count);
        // The unmodified save lists the same invalid members that a rewrite keeps (or cannot keep); a dropped ReadyToRun
        // section is about the module, not a member.
        bool sameSurvey = survey.Issues.Select(i => i.Token).ToHashSet()
            .SetEquals(report.Issues.Where(i => i.Reason != SaveIssueReason.PrecompiledCodeDropped).Select(i => i.Token));
        return new Row(entry, methods, report.Kept.Count(), report.Changed.Count(), unexplained.Count, originalSaved, sameSurvey, time,
            unexplained.Count > 0 ? $"0x{unexplained[0]:X8}" : report.Changed.FirstOrDefault()?.ToString());
    }

    private static string Table(List<Row> rows)
    {
        var sb = new StringBuilder();
        sb.AppendLine("| Origin | Assembly | Methods | Unmodified save | Kept invalid | Changed (reported) | Unreported | Write |");
        sb.AppendLine("|---|---|---:|---|---:|---:|---:|---:|");
        foreach (var r in rows)
            sb.AppendLine($"| {r.Entry.Origin} | {r.Entry.Name} | {r.Methods:N0} | {(r.OriginalSaved ? "identical" : "DIFFERS")} | {r.Kept:N0} | {r.Changed:N0} | {r.Unexplained:N0} | {r.Write.TotalMilliseconds:N0} ms |");
        foreach (var r in rows.Where(r => r.Changed > 0)) sb.AppendLine($"{r.Entry.Name}: e.g. {r.Example}");
        return sb.ToString();
    }
}
