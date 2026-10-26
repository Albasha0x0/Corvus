using Corvus.DocsSite;

// DocsSite <repository> <output> [--source <url>]: exit 1 when a link or anchor does not resolve.
if (args.Length is not (2 or 4) || (args.Length == 4 && args[2] != "--source"))
{
    Console.Error.WriteLine("usage: DocsSite <repository> <output> [--source <url of the tree at this commit>]");
    return 2;
}
var report = Site.Build(args[0], args[1], args.Length == 4 ? args[3] : null);
Console.WriteLine($"{report.Pages.Count} pages, {report.Copied.Count} files copied to {Path.GetFullPath(args[1])}");
foreach (var broken in report.Broken) Console.Error.WriteLine($"unresolved link: {broken}");
return report.Broken.Count == 0 ? 0 : 1;
