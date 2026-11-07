using Corvus.Core;
using Corvus.Native.Code;
using Corvus.Native.Diff;

namespace Corvus.Services.Analysis;

/// <summary>
/// A native frame of crash text placed in the new build. Class is changed, added, unchanged or unknown; Function, Section
/// and Offset are set only where the new build was confirmed.
/// </summary>
public sealed record CrashFrame(int Index, string Class, string? Module, string? Offset, string? Section, string? Function, string Detail)
{
    /// <summary>The frame as one line: class, module and offset, function, section and detail.</summary>
    public override string ToString() =>
        $"{Class}: {UpdateReviewer.Line(Module)}{(Offset != null ? "+" + Offset : "")}{(Function != null ? " " + UpdateReviewer.Line(Function) : "")}" +
        $"{(Section != null ? " in " + UpdateReviewer.Line(Section) : "")}; {UpdateReviewer.Line(Detail)}";
}

/// <summary>Where the native frames of crash text fall in the update: Total frames were read and Frames keeps the first of them.</summary>
public sealed record ReviewCrash(string? ExceptionCode, int Total, IReadOnlyList<CrashFrame> Frames, IReadOnlyList<string> Notes)
{
    /// <summary>The frames beyond the kept ones were not placed.</summary>
    public bool Capped => Total > Frames.Count;
}

/// <summary>Places the frames of crash text in the functions an update adds or changes.</summary>
internal static class CrashLocator
{
    /// <summary>Native frames placed per text; further frames are counted.</summary>
    public const int MaxFrames = 200;

    public const string Changed = "changed", Added = "added", Unchanged = "unchanged", Unknown = "unknown";

    /// <summary>
    /// Parses crash text given inline or as a file; refuses both or neither, text over the size limit and text with no native frame.
    /// </summary>
    public static (ParsedStackText Parsed, List<string> Notes) Read(string? text, string? path)
    {
        var notes = new List<string>();
        if (text != null && text.Length == 0)
            throw new ToolError(ErrorCode.InvalidArgument, "crashText is empty.", path != null ? "omit crashText to read crashPath" : "pass the crash text or crashPath");
        bool hasText = text != null, hasPath = !string.IsNullOrWhiteSpace(path);
        if (hasText == hasPath)
            throw new ToolError(ErrorCode.InvalidArgument, hasText ? "pass crashText or crashPath, not both." : "view=review with crash text needs crashText or crashPath.");
        if (hasText && text!.Length > StackTextService.MaxTextChars)
            throw new ToolError(ErrorCode.LimitExceeded, $"crashText is {text.Length} characters; the limit is {StackTextService.MaxTextChars}.",
                "save it to a file and pass crashPath (its last 8 MiB are read)");
        var parsed = StackTextFormats.Parse(StackTextService.Input(text, path, notes), "auto");
        if (!parsed.Frames.Any(f => f.Kind == "native"))
            throw new ToolError(ErrorCode.InvalidArgument,
                parsed.Frames.Count > 0 ? "the crash text has managed frames only; this compares native builds." : "no native frame (module with offset or address) was recognized in the crash text.",
                "pass an Application Error event, a WER report or a debugger stack");
        notes.AddRange(parsed.Notes);
        int managed = parsed.Frames.Count(f => f.Kind != "native");
        if (managed > 0) notes.Add($"{managed} managed frame(s) in the crash text were not placed.");
        if (parsed.Unrecognized > 0) notes.Add($"{parsed.Unrecognized} line(s) of the crash text were not recognized.");
        return (parsed, notes);
    }

    /// <summary>
    /// Places each native frame of <paramref name="parsed"/> in the new build. A frame is placed only when the text names a module
    /// of the builds and its time stamp equals the new build's; any other frame is unknown, with the reason.
    /// </summary>
    public static ReviewCrash Locate(ParsedStackText parsed, LoadedNative oldBuild, LoadedNative newBuild, NativeCodeIndex newIndex, MatchResult match, IReadOnlyList<string> notes)
    {
        var bases = StackTextService.Bases(null, parsed);
        var names = new[] { Path.GetFileName(oldBuild.FilePath), Path.GetFileName(newBuild.FilePath) };
        uint? oldStamp = oldBuild.Pe?.Coff.TimeDateStamp, newStamp = newBuild.Pe?.Coff.TimeDateStamp;
        var native = parsed.Frames.Where(f => f.Kind == "native").ToList();
        var frames = native.Take(MaxFrames).Select((f, i) => Place(i, f)).ToList();
        var all = new List<string>(notes);
        if (native.Count > MaxFrames) all.Add($"{native.Count - MaxFrames} frame(s) past the first {MaxFrames} were not placed: the limit is {MaxFrames} frames.");
        var code = parsed.Exception?.Code is { } c ? $"0x{c:X8}" : null;
        return new ReviewCrash(code, native.Count, frames, all);

        CrashFrame Place(int index, TextFrame f)
        {
            CrashFrame Unplaced(string? module, string detail, string? offset = null, string? section = null) =>
                new(index, Unknown, module, offset, section, null, detail);
            if (f.Outside)
                return Unplaced(null, f.Address is { } outside ? $"the fault is outside any module: 0x{outside:X} is an address, not an offset" : "the fault is outside any module");
            var module = StackTextService.ModuleOf(f, bases, parsed);
            if (module == null) return Unplaced(null, "no module for this address");
            if (!names.Any(n => StackTextService.SameModule(n, module)))
                return Unplaced(module, $"no build given for {module}; the builds are {string.Join(" and ", names.Distinct())}");
            // Only a fault frame of an event or report carries a time stamp of its own, and its offset is the faulting
            // address, not a return address. A module list entry or another event's stamp is never borrowed, and the
            // frames of a stack never reach the function lookup, so no return-address adjustment is needed.
            if (f.Described?.TimeDateStamp is not { } want || want == 0)
                return Unplaced(module, $"the frame gives no time stamp of its own for {module}, so its build is not confirmed");
            if (newStamp is not { } have || have == 0)
                return Unplaced(module, "the new build has no PE time stamp to compare with the text's");
            if (oldStamp == have)
                return Unplaced(module, $"the old and new builds have the same time stamp 0x{have:X8}, so the text cannot be tied to the new build");
            if (want != have)
                return Unplaced(module, $"different build: the text's {module} has time stamp 0x{want:X8}, the new build 0x{have:X8}, the old build "
                    + (oldStamp is { } o ? $"0x{o:X8}" : "none") + (want == oldStamp ? " (the text is from the old build)" : ""));

            ulong? rva = f.Offset;
            if (rva == null && f.Address is { } a && bases.FirstOrDefault(kv => StackTextService.SameModule(kv.Key, module)) is { Key: not null } kb && a >= kb.Value)
                rva = a - kb.Value;
            if (rva == null)
                return Unplaced(module, f.OffsetUnreadable ? "the fault offset in the text is unreadable"
                    : f.Symbol != null ? "the text gives a function name, not an offset in the build" : $"no load address for {module}");

            var image = newIndex.Image;
            string at = $"0x{rva:X}";
            if (rva >= image.SizeOfImage) return Unplaced(module, $"offset {at} is past the end of the new build (size 0x{image.SizeOfImage:X})", at);
            uint r = (uint)rva.Value;
            var section = image.Sections.FirstOrDefault(s => s.Contains(r));
            if (section == null) return Unplaced(module, $"offset {at} is in no section", at);
            if (!section.IsExecutable) return Unplaced(module, $"offset {at} is in {section.Name}, not code", at, section.Name);
            if (newIndex.FunctionAt(r) is not { } function)
                return Unplaced(module, $"offset {at} in {section.Name} is outside any known function", at, section.Name);

            var name = Format.Within(newIndex.NameAt(function.Start) ?? function.Name, function.Start, r);
            CrashFrame Placed(string cls, string detail) => new(index, cls, module, at, section.Name, name, detail);
            CrashFrame Held(string detail) => new(index, Unknown, module, at, section.Name, name, detail);
            if (!match.New.ByStart.TryGetValue(function.Start, out var n)) return Held("the function is not in the function match");
            if (match.ByNew[n] is not { } pair)
            {
                var reason = match.UnmatchedReason(false, n);
                return reason == "new_in_this_build" ? Placed(Added, "no function of the old build matches it")
                    : Held($"no function of the old build matches it ({reason}), so it may be added or changed");
            }
            var (before, after) = (match.Old.Functions[pair.Old], match.New.Functions[pair.New]);
            if (before.Failed || after.Failed)
                return Held($"the function was not decoded in the {(before.Failed ? "old" : "new")} build, so a change is unknown");
            var oldName = match.Old.Index.NameAt(before.Start) ?? before.Function.Name;
            var basis = $"matched to {oldName} of the old build by {pair.Basis}";
            return before.BytesHash == after.BytesHash ? Placed(Unchanged, $"same bytes as the old build's function; {basis}") : Placed(Changed, basis);
        }
    }
}
