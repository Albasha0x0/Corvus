using Corvus.Core;
using Corvus.Native.Code;

namespace Corvus.Services.Analysis;

// Provider interfaces of the containers family, found by Core.Providers (type scan): a new view, search kind or rule set is a class in its own file.

/// <summary>A view's facts: <see cref="Detail"/> is its record (serialized as the view's detail), highlights feed the overview.</summary>
public sealed record FileView(object Detail, IReadOnlyList<string> Highlights);

/// <summary>A summarize_file view (view=&lt;Name&gt;); the overview lists the views that apply and gathers their highlights.</summary>
public interface IFileSummaryView
{
    /// <summary>The view= value, lowercase.</summary>
    string Name { get; }

    /// <summary>The view of <paramref name="file"/>, or null when it does not apply. Reads only; never runs the file.</summary>
    FileView? Inspect(FileInput file, CancellationToken ct);
}

/// <summary>A file inside a container: its inner path, Blob.Identify kind, where it came from and its bytes.</summary>
public sealed record ContainerItem(string Path, string Kind, string Origin, byte[] Bytes);

/// <summary>What a search kind searches: every file of the container (nested ones opened) and an archive's entries.</summary>
public sealed record ContainerScope(string Source, string Container, IReadOnlyList<ContainerItem> Items, IReadOnlyList<ContainerEntry>? Entries)
{
    /// <summary>kind=endpoint: a capture whose requests are joined to the code's endpoints.</summary>
    public string? Capture { get; init; }
}

/// <summary>A search_container match: the inner path, the name the query matched and the kind.</summary>
public sealed record ContainerMatch(string Path, string Name, string Kind)
{
    public string? Assembly { get; init; }
    public string? Detail { get; init; }

    /// <summary>kind=endpoint: the method that names the endpoint (DEX id, .NET member, native function).</summary>
    public string? Member { get; init; }

    /// <summary>kind=endpoint: where in <see cref="Member"/> (code offset, IL offset, address), or "annotation" / "attribute".</summary>
    public string? Location { get; init; }

    /// <summary>kind=endpoint: code, capture, or code+capture.</summary>
    public string? Seen { get; init; }
}

/// <summary>search_container kinds beyond the managed ones (type, method, field, property, event).</summary>
public interface IContainerSearchKind
{
    /// <summary>The kind= values answered, lowercase.</summary>
    IReadOnlyList<string> Kinds { get; }

    /// <summary>Matches of <paramref name="kind"/>; <paramref name="matches"/> tests a name against the query.</summary>
    IEnumerable<ContainerMatch> Search(ContainerScope scope, string kind, Func<string, bool> matches, CancellationToken ct);

    /// <summary>A kind that reads the file itself, streamed at any size, and pages its own rows in file order; null searches the container's files.</summary>
    UnpackService.ContainerSearch? SearchFile(string path, string query, int offset, int limit, CancellationToken ct) => null;
}

/// <summary>What survey_features rules run over: a managed module's scan or a native image's code index.</summary>
public sealed record SurveySubject(ModuleScan? Managed, NativeCodeIndex? Native)
{
    /// <summary>An Android app's DEX code and package files, or an Apple app's Info.plist; selects the platform's rules.</summary>
    public MobileSubject? Mobile { get; init; }
}

/// <summary>
/// survey_features rules beyond the built-in set (<see cref="Features.Rules"/>), in the same feature syntax; a provider may
/// add feature kinds ("kind:pattern") and evaluate them itself.
/// </summary>
public interface ISurveyRuleProvider
{
    IEnumerable<Features.Rule> Rules { get; }

    /// <summary>Feature kinds this provider evaluates, beyond api, native, str, arg, section and rtti.</summary>
    IReadOnlyCollection<string> Kinds => [];

    /// <summary>Evidence for one feature of a kind in <see cref="Kinds"/>, or null when it does not match.</summary>
    Evidence? Evaluate(SurveySubject subject, string feature, CancellationToken ct) => null;
}
