using Corvus.Core;

namespace Corvus.Setup;

internal static partial class ToolCli
{
    // ---- rules ----

    /// <summary>
    /// rules list: installed and known packs; rules fetch &lt;pack&gt;: download,
    /// check and install one; rules import &lt;archive&gt; [pack]: check and
    /// install one from a local archive.
    /// </summary>
    private static async Task<int> RulesAsync(CliArgs a, CliIo io, CancellationToken cancellationToken)
    {
        var verb = a.Positionals.Count > 0 ? a.Positionals[0].ToLowerInvariant() : "list";
        switch (verb)
        {
            case "list" when a.Positionals.Count <= 1:
                var installed = RulePacks.Installed(RulePacks.Root);
                io.Out.WriteLine(installed.Count == 0 ? $"No rule packs installed in {RulePacks.Root}." : $"Installed in {RulePacks.Root}:");
                foreach (var p in installed) io.Out.WriteLine($"  {p.Label}: {p.RuleFiles:N0} rule file{(p.RuleFiles == 1 ? "" : "s")}, {p.Folder}");
                io.Out.WriteLine("Known (corvus rules fetch <pack> downloads from GitHub; corvus rules import <archive> reads a local copy; SHA-256 checked):");
                foreach (var p in RulePacks.Known) io.Out.WriteLine($"  {p.Name} {p.Version}: {p.Description} License: {p.License}.");
                return Exit.Ok;
            case "fetch" when a.Positionals.Count == 2:
                var pack = RulePacks.Find(a.Positionals[1])
                           ?? throw new UsageException($"Unknown rule pack '{a.Positionals[1]}'. Known: {string.Join(", ", RulePacks.Known.Select(p => p.Name))}.");
                try
                {
                    using var handler = new SocketsHttpHandler { ConnectTimeout = TimeSpan.FromSeconds(30) };
                    var (installedPack, downloaded) = await RulePacks.FetchAsync(pack, RulePacks.Root, handler, ReferencePacks.Offline, cancellationToken);
                    io.Out.WriteLine($"{(downloaded ? "Installed" : "Already installed:")} {pack.Name} {pack.Version}, {installedPack.RuleFiles:N0} rule file{(installedPack.RuleFiles == 1 ? "" : "s")} " +
                                     $"(license: {pack.License}) in {installedPack.Folder}.");
                    io.Out.WriteLine($"Scan with: corvus search_container path=<file> kind=yara query=pack:{pack.Name}");
                    return Exit.Ok;
                }
                catch (ToolError e)
                {
                    io.Error.WriteLine(e.Message + (e.Remediation is { Length: > 0 } next ? $" Next: {next}" : ""));
                    return e.Code == ErrorCode.Unsupported ? Exit.Environment : Exit.ToolError;
                }
                catch (HttpRequestException e)
                {
                    io.Error.WriteLine($"{pack.Url}: {e.Message}; nothing was installed.");
                    return Exit.ToolError;
                }
            case "import" when a.Positionals.Count is 2 or 3:
                try
                {
                    var (imported, installedNow) = RulePacks.Import(a.Positionals[1], RulePacks.Root, a.Positionals.Count == 3 ? a.Positionals[2] : null);
                    io.Out.WriteLine($"{(installedNow ? "Installed" : "Already installed:")} {imported.Label}, {imported.RuleFiles:N0} rule file{(imported.RuleFiles == 1 ? "" : "s")} in {imported.Folder}.");
                    io.Out.WriteLine($"Scan with: corvus search_container path=<file> kind=yara query=pack:{imported.Name}");
                    return Exit.Ok;
                }
                catch (ToolError e)
                {
                    io.Error.WriteLine(e.Message + (e.Remediation is { Length: > 0 } next ? $" Next: {next}" : ""));
                    return Exit.ToolError;
                }
            default:
                throw new UsageException("rules takes list, fetch <pack>, or import <archive> [pack].");
        }
    }
}
