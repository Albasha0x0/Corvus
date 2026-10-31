using Corvus.Core;
using Corvus.Native.Providers;

namespace Corvus.Tools;

/// <summary>showDecompile on the native edit tools: the pseudocode of the edited function before and after the edit.</summary>
internal static class DecompileDiff
{
    public const string Description = "after: pseudocode after the edit; diff: its unified diff.";

    public static readonly string[] Modes = ["none", "after", "diff"];

    /// <summary>"after", "diff" or null (none).</summary>
    public static string? Parse(string? mode) => (mode ?? "").Trim().ToLowerInvariant() switch
    {
        "" or "none" or "false" => null,
        "after" => "after",
        "diff" or "true" => "diff",
        _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown showDecompile '{mode}'.", "use none, after or diff"),
    };

    /// <summary>The function whose pseudocode shows an edit at <paramref name="rva"/>: the one containing it, else the first that references it; null when none.</summary>
    public static async Task<uint?> FunctionFor(INativeDecompilerSession session, uint rva, CancellationToken ct)
    {
        try { return (await session.DecompileAsync(rva, ct)).StartRva; }
        catch (ToolError e) when (e.Code is ErrorCode.NotFound or ErrorCode.InvalidArgument or ErrorCode.Failed) { }
        foreach (var x in await session.GetXrefsToAsync(rva, ct))
            if (x.FromFunctionRva is { } f) return f;
        return null;
    }

    /// <summary>The function's pseudocode, or the reason there is none.</summary>
    public static async Task<(string? Text, string? Error)> Text(INativeDecompilerSession session, uint? function, CancellationToken ct)
    {
        if (function is not { } f) return (null, "no function contains or references the address");
        try { return ((await session.DecompileAsync(f, ct)).Text, null); }
        catch (ToolError e) when (e.Code is not (ErrorCode.Cancelled or ErrorCode.Timeout)) { return (null, e.Message); }
    }

    /// <summary>The section appended to the tool's result.</summary>
    public static string Render(string mode, (string? Text, string? Error) before, (string? Text, string? Error) after, string name)
    {
        if (after.Text == null) return $"\n\nPseudocode: not available ({after.Error}).";
        if (mode == "after" || before.Text == null) return $"\n\nPseudocode of {name} after the edit:\n{after.Text}";
        return $"\n\nPseudocode of {name}, before and after:\n{TextDiff.Unified(before.Text, after.Text, "before", "after")}";
    }
}
