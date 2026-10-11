using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Providers;
using Corvus.Services;

namespace Corvus.Tools;

/// <summary>
/// The image's anchored notes as engine markers (Ghidra bookmarks of category Corvus, IDA marked positions), pushed once per
/// change of the notes; and the search over the names and comments in effect for an image.
/// </summary>
internal static class NoteMarks
{
    /// <summary>Characters of a note's text in its marker.</summary>
    private const int MarkText = 120;

    private static readonly ConditionalWeakTable<INativeDecompilerSession, StrongBox<string?>> Pushed = new();

    /// <summary>The marks for the image's native notes (dropped and refuted ones left out), in address order.</summary>
    public static IReadOnlyList<NativeMark> Marks(LoadedNative native, NotesService notes) =>
        notes.Read(native.OriginalSha256.ToLowerInvariant())
            .Where(n => n.Anchor.Kind == NoteAnchor.Native && n.Anchor.Rva is not null && n.Status is not ("dropped" or "refuted"))
            .OrderBy(n => n.Anchor.Rva).ThenBy(n => n.Created)
            .Select(n => new NativeMark(n.Anchor.Rva!.Value, $"[{n.Kind}/{n.Status}] {Format.Clip(n.Text.ReplaceLineEndings(" "), MarkText)} ({n.Id})"))
            .ToList();

    /// <summary>Pushes the marks when they changed since the database last took them; the number pushed, or null when nothing changed or the engine has no marks.</summary>
    public static async Task<NativeMarkResult?> EnsureAsync(LoadedNative native, INativeDecompilerSession session, NotesService notes, CancellationToken ct)
    {
        if (EngineControl.Of(session) is not { } control) return null;
        var marks = Marks(native, notes);
        var stamp = Stamp(marks);
        var box = Pushed.GetOrCreateValue(session);
        if (box.Value == stamp) return null;
        if (box.Value == null && await session.GetStampAsync(EngineControl.MarksStampKey, ct) == stamp)
        {
            box.Value = stamp;
            return null;
        }
        if (box.Value == null && marks.Count == 0) // nothing pushed before and nothing to push
        {
            box.Value = stamp;
            return null;
        }
        var result = await control.SetMarksAsync(marks, stamp, ct);
        box.Value = stamp;
        return result;
    }

    /// <summary>"notes: 3 marks in ida" for a decompile header, or null.</summary>
    public static string? Describe(NativeMarkResult? result, string engine) =>
        result == null ? null : $"notes: {result.Set} mark(s) in {engine}" + (result.Failed > 0 ? $", {result.Failed} not placed ({result.Failures[0]})" : "");

    private static string Stamp(IReadOnlyList<NativeMark> marks)
    {
        var text = string.Join("\n", marks.Select(m => $"{m.Rva:X}\t{m.Text}"));
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)))[..32];
    }

    /// <summary>A name or comment in effect for an image: its source (user or a layer), kind and text.</summary>
    public sealed record AnnotationMatch(uint Rva, string Source, string Kind, string Text);

    /// <summary>The user's names and comments and every name layer's, whose text matches <paramref name="filter"/>, in address order.</summary>
    public static IReadOnlyList<AnnotationMatch> Search(LoadedNative native, NativeCodeService code, NameFilter filter)
    {
        code.RestoreImported(native);
        var ann = native.AnnotationsOrNull ?? code.Annotations(native);
        var all = new List<AnnotationMatch>();
        all.AddRange(ann.Names().Select(n => new AnnotationMatch(n.Rva, "user", "name", n.Name)));
        all.AddRange(ann.Comments().Select(c => new AnnotationMatch(c.Rva, "user", "comment", c.Comment)));
        foreach (var layer in NativeNameLayers.OfOrNull(native)?.Layers ?? [])
        {
            all.AddRange(layer.Names.Select(n => new AnnotationMatch(n.Key, layer.Source.Id(), "name", n.Value)));
            all.AddRange(layer.Comments.Select(c => new AnnotationMatch(c.Key, layer.Source.Id(), "comment", c.Value)));
        }
        return all.Where(m => filter.IsMatch(m.Text)).OrderBy(m => m.Rva).ThenBy(m => m.Source, StringComparer.Ordinal).ThenBy(m => m.Kind, StringComparer.Ordinal).ToList();
    }
}
