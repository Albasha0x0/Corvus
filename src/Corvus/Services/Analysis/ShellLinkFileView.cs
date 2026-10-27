using Corvus.Core;
using Corvus.Core.Documents;

namespace Corvus.Services.Analysis;

/// <summary>view=lnk: a Windows shortcut's target, arguments, paths, times, tracker machine id, extra data and findings.</summary>
internal sealed class ShellLinkFileView : IFileSummaryView
{
    public sealed record Overlay(string Offset, long Size, string Kind, string Sha256);

    public sealed record Facts(string? Target, string? Arguments, string? WorkingDirectory, string? IconLocation, int IconIndex, string? Description,
        string? RelativePath, string ShowCommand, string? HotKey, DateTime? Created, DateTime? Accessed, DateTime? Modified, long TargetSize, string Attributes,
        string? LocalPath, string? NetworkPath, string? IdListPath, string? EnvironmentTarget, string? IconEnvironment, string? DriveType, string? VolumeSerial,
        string? VolumeLabel, string? MachineId, string? MacAddress, string? Droid, string? KnownFolder, int? SpecialFolder, string? ShimLayer,
        string? InstallerDescriptor, IReadOnlyList<string> Flags, IReadOnlyList<string> ExtraBlocks, Overlay? AppendedData, IReadOnlyList<MacroFinding> Findings,
        IReadOnlyList<string> Notes);

    public string Name => "lnk";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (!ShellLink.Looks(file.Head) || file.Length > 64L << 20) return null;
        var l = ShellLink.Read(file.Bytes, System.IO.Path.GetFileName(file.Path));
        var findings = ShellLinkRules.Scan(l);
        var facts = new Facts(l.Target, l.Arguments, l.WorkingDirectory, l.IconLocation, l.IconIndex, l.Name, l.RelativePath, l.ShowCommand, l.HotKey,
            l.Created, l.Accessed, l.Modified, l.TargetSize, Attributes(l.Attributes), l.LocalPath, l.NetworkPath, l.IdListPath, l.EnvironmentTarget,
            l.IconEnvironment, l.DriveType, l.VolumeSerial, l.VolumeLabel, l.MachineId, l.MacAddress, l.Droid, l.KnownFolder, l.SpecialFolder, l.ShimLayer,
            l.InstallerDescriptor, l.FlagNames, l.ExtraBlocks,
            l.Overlay.Length > 0 ? new Overlay($"0x{l.OverlayOffset:X}", l.Overlay.Length, Blob.Identify(l.Overlay), Blob.Sha256(l.Overlay)) : null, findings, l.Notes);
        var h = new List<string> { $"Shortcut to {l.Target ?? "(no target)"}{(l.Arguments is { Length: > 0 } a ? " " + ShellLinkRules.Clip(a) : "")}." };
        if (l.MachineId != null) h.Add($"Made on machine {l.MachineId}{(l.MacAddress != null ? $" ({l.MacAddress})" : "")}.");
        h.AddRange(findings.Where(x => x.Type == "Suspicious").Select(x => $"Worth reviewing: {x.Description}."));
        return new FileView(facts, h);
    }

    private static string Attributes(uint a)
    {
        var names = new List<string>();
        if ((a & 0x01) != 0) names.Add("read-only");
        if ((a & 0x02) != 0) names.Add("hidden");
        if ((a & 0x04) != 0) names.Add("system");
        if ((a & 0x10) != 0) names.Add("directory");
        if ((a & 0x20) != 0) names.Add("archive");
        if ((a & 0x80) != 0) names.Add("normal");
        return string.Join(", ", names);
    }
}
