using Corvus.Services.Web;
using Corvus.Services.Web.Scripts;

namespace Corvus.Services.Analysis;

/// <summary>
/// view=flight: a React Server Components payload, from a raw response (Next.js .rsc, text/x-component) or the
/// self.__next_f pushes of a page: rows by tag, client module references with their chunk files, server action ids,
/// hints, errors and the element tree (<see cref="FlightData"/>). Nothing is fetched or run.
/// </summary>
internal sealed class FlightFileView : IFileSummaryView
{
    private const long MaxPayload = 32L << 20;

    public string Name => "flight";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (file.Length > MaxPayload || file.Streamed || file.Kind is not ("text" or "data" or "html")) return null;
        var text = ScriptText.Decode(file.Bytes, out _);
        if (!FlightData.Applies(text) || FlightData.Read(text, ct) is not { } p) return null;
        var list = new List<string>
        {
            $"React Server Components payload ({p.Source}): {p.Rows} rows, {p.ClientModules.Count} client module reference(s), {p.Actions.Count} server action(s), " +
            $"{p.Elements} element(s); view=flight lists them.",
        };
        if (p.Errors.Count > 0) list.Add($"Errors: {string.Join("; ", p.Errors.Take(3))}.");
        return new FileView(p, list);
    }
}
