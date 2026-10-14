using System.Text;
using Corvus.Core;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

/// <summary>Readable text of the dump and live-process records: one line per row, the summary as short labelled lines.</summary>
internal static class DumpText
{
    public static string Summary(MinidumpService.DumpReport r)
    {
        var sb = new StringBuilder();
        var c = r.Counts!;
        sb.AppendLine($"{r.Id}: {(c.FullMemory ? "full-memory" : "minidump")}, written {r.TimeUtc}, {r.FileSize:N0} bytes");
        sb.AppendLine($"  path: {r.Path}");
        if (r.DumpType is { Count: > 0 } flags) sb.AppendLine($"  type: {string.Join(", ", flags)}");
        if (r.System is { } s) sb.AppendLine($"System: {s.Architecture}, {s.Os}, {Plural(s.Processors, "processor")}{(s.BuildString != null ? $", build {s.BuildString}" : "")}");
        if (r.Process is { } p)
            sb.AppendLine($"Process {p.ProcessId?.ToString() ?? "?"}: {p.MainModule ?? "(no main module)"}" + (p.CreateTimeUtc != null ? $", started {p.CreateTimeUtc}" : "") +
                          (p.Integrity != null ? $", integrity {p.Integrity}" : "") + (p.Wow64 ? ", WoW64" : "") + (p.Runtime != null ? $", runtime {p.Runtime}" : ""));
        if (r.Exception is { } e)
        {
            sb.AppendLine($"Exception {e.Code}{(e.Name != null ? $" ({e.Name})" : "")} on thread {e.ThreadId}: {e.Description}");
            sb.AppendLine($"  at {e.Address} {e.Symbol ?? e.Module ?? "(no module)"}{(e.SymbolSource != null ? $" [{e.SymbolSource}]" : "")}");
            if (e.Instruction != null) sb.AppendLine($"  instruction: {e.Instruction}, from {e.InstructionSource}");
            if (e.Parameters.Count > 0) sb.AppendLine($"  parameters: {string.Join(", ", e.Parameters)}");
            if (e.ThrownTypes is { Count: > 0 } thrown) sb.AppendLine($"  thrown: {string.Join(", ", thrown)}");
            if (e.Registers != null) sb.AppendLine($"  registers: {e.Registers}");
            if (!e.Continuable) sb.AppendLine("  not continuable");
        }
        if (r.FaultingModule is { } m) sb.AppendLine("Faulting module: " + Module(m));
        if (r.FaultingThread is { } t) sb.AppendLine("Faulting thread: " + Thread(t));
        if (r.Managed is { } mg)
        {
            sb.AppendLine($".NET: {mg.Runtime}; DAC {mg.Dac.Status}{(mg.Dac.Path != null ? $" ({mg.Dac.Path})" : "")}: {mg.Dac.Detail}");
            var counts = new List<string>();
            if (mg.AppDomains is { } ad) counts.Add(Plural(ad, "app domain"));
            if (mg.ManagedThreads is { } mt) counts.Add(Plural(mt, "managed thread"));
            if (mg.Heap is { } h) counts.Add(h.Walkable ? $"heap walkable, {Plural(h.Segments, "segment")}, {h.Bytes:N0} bytes" : $"heap: {h.Reason}");
            if (counts.Count > 0) sb.AppendLine("  " + string.Join("; ", counts));
            if (mg.Exception is { } x) ManagedException(sb, x, "  ");
            foreach (var n in mg.Notes) sb.AppendLine("  note: " + n);
        }
        sb.AppendLine($"Counts: {Plural(c.Modules, "module")}, {Plural(c.Threads, "thread")}, {Plural(c.UnloadedModules, "unloaded module")}, " +
                      $"{Plural(c.MemoryRegions, "memory region")}, {Plural(c.MemoryRanges, "captured range")} ({c.CapturedBytes:N0} bytes), {Plural(c.Handles, "handle")} " +
                      "(view=modules, threads, memory, unloaded list them)");
        if (r.HandleTypes is { Count: > 0 } ht) sb.AppendLine("Handles: " + string.Join(", ", ht));
        foreach (var x in r.Issues ?? []) sb.AppendLine("Issue: " + x);
        foreach (var x in r.Notes ?? []) sb.AppendLine("Note: " + x);
        return sb.ToString();
    }

    private static void ManagedException(StringBuilder sb, MinidumpService.ManagedExceptionSummary x, string pad)
    {
        sb.AppendLine($"{pad}exception {x.Type}: {x.Message} ({x.HResult}, object {x.Address}{(x.ThreadId is { } tid ? $", thread {tid}" : "")})");
        foreach (var f in x.Stack)
            sb.AppendLine($"{pad}  at {f.Function}" + (f.Token != null ? $" {f.Token}" : "") + (f.IlOffset is { } il ? $" IL_{il:X4}" : "") +
                          (f.Assembly ?? f.Module) switch { { } a => $" [{a}]", _ => "" } + (f.BuildCheck is { } b and not "match" ? $" ({b})" : "") +
                          (f.Statement != null ? $": {f.Statement}" : ""));
        foreach (var inner in x.Inner) ManagedException(sb, inner, pad + "  inner ");
    }

    public static string Module(MinidumpService.ModuleSummary m) =>
        $"{m.Base} {m.Name} size {m.Size}" + (m.FileVersion != null ? $" v{m.FileVersion}" : "") + (m.Built != null ? $" built {m.Built}" : $" stamp {m.TimeDateStamp}") +
        (m.PdbName != null ? $", pdb {m.PdbName}{(m.PdbGuid != null ? $" {m.PdbGuid}/{m.PdbAge}" : "")}" : "") +
        $"; local {m.LocalImage}{(m.LocalPath == null ? $" ({m.LocalDetail})" : m.LocalPath.Equals(m.Path, StringComparison.OrdinalIgnoreCase) ? "" : $" ({m.LocalPath})")}" + (m.Managed == true ? ", .NET" : "") + $"\n{m.Path}";

    public static string Thread(MinidumpService.ThreadSummary t) =>
        $"{t.Id}{(t.Name != null ? $" \"{t.Name}\"" : "")}{(t.Faulting ? " [faulting]" : "")}: {t.Location ?? t.InstructionPointer ?? "no context"}" +
        $" (ip {t.InstructionPointer ?? "?"}, sp {t.StackPointer ?? "?"}, stack {t.StackStart}-{t.StackEnd}, teb {t.Teb}" +
        (t.StartAddress != null ? $", start {t.StartAddress}" : "") + (t.SuspendCount > 0 ? $", suspended {t.SuspendCount}" : "") + $", priority {t.Priority})";

    /// <summary>#index address symbol [source], managed token and IL offset with the assembly, how it was found, the statement and a note.</summary>
    public static string Frame(MinidumpService.StackFrame f) =>
        $"#{f.Index} {f.Address} {f.Symbol ?? (f.Module != null ? $"{f.Module}+{f.ModuleOffset}" : "?")}" + (f.SymbolSource is { } src and not "none" ? $" [{src}]" : "") +
        (f.Token != null ? $" {f.Token}{(f.IlOffset is { } il ? $" IL_{il:X4}" : "")}" : "") + (f.Assembly != null ? $" in {f.Assembly}" : "") +
        (f.BuildCheck is { } b and not "match" ? $" (build {b})" : "") + $"  {f.Kind}, {f.Method}" + (f.Basis != null ? $", {f.Basis}" : "") + $", sp {f.StackPointer}" +
        (f.Statement != null ? $"\n{f.Statement}" : "") + (f.Note != null ? $"\nnote: {f.Note}" : "");

    /// <summary>#index resolved name [source] (build check) in image or assembly; the raw line when it differs; folded names; statement; next step.</summary>
    public static string TextFrame(StackTextService.SymbolizedFrame f)
    {
        var sb = new StringBuilder($"#{f.Index} ");
        sb.Append(f.Resolved ?? f.Raw.Trim());
        if (f.Source is { } src and not "none") sb.Append($" [{src}]");
        if (f.Token != null) sb.Append($" {f.Token}{(f.IlOffset is { } il ? $" IL_{il:X4}" : "")}");
        if ((f.Image ?? f.Assembly) is { } where) sb.Append($" in {where}");
        if (f.BuildCheck != "match") sb.Append($" (build {f.BuildCheck}{(f.BuildDetail != null ? $": {f.BuildDetail}" : "")})");
        if (f.Resolved != null) sb.Append($"\nline {f.Line}: {f.Raw.Trim()}");
        if (f.Folded is { Count: > 0 } folded) sb.Append($"\n+{folded.Count} more in {f.Image}: {string.Join(" < ", folded)}");
        if (f.Statement != null) sb.Append($"\n{f.Statement}");
        if (f.NextStep != null) sb.Append($"\nnext: {f.NextStep}");
        return sb.ToString();
    }

    public static string Bucket(MinidumpService.DumpBucket b) =>
        $"{b.Count} x {b.Signature}  [{b.Kind}] {b.FirstTime} .. {b.LastTime}; representative {b.Representative}" +
        (b.Sample.Count > 1 ? $"; sample {string.Join(", ", b.Sample)}" : "") +
        (b.ModuleVersions.Count > 0 ? $"; versions {string.Join(", ", b.ModuleVersions.Select(v => $"{v.Key} x{v.Value}"))}" : "") +
        (b.Offsets.Count > 1 ? $"; offsets {string.Join(", ", b.Offsets.Select(v => $"{v.Key} x{v.Value}"))}" : "");

    public static string HeapRow(MinidumpService.HeapRow r) => r.Address != null
        ? $"{r.Address}  {r.Type}  {r.Size:N0} bytes{(r.Value != null ? $"  {Format.Literal(r.Value)}" : "")}"
        : $"{r.Type}  {r.Count:N0} object{(r.Count == 1 ? "" : "s")}, {r.Size:N0} bytes{(r.Assembly != null ? $"  [{r.Assembly}] {r.Token}" : "")}";

    /// <summary>The process line every inspect_process view starts with, the handle guarantee and the notes.</summary>
    public static string LiveHeader(LiveProcessService.LiveReport r) =>
        $"pid {r.ProcessId} {r.Name}: {r.Architecture}{(r.Wow64 ? " (WoW64)" : "")}{(r.Runtime != null ? $", {r.Runtime}" : "")}{(r.StillRunning ? "" : ", exited")}" +
        $"{(r.StartTimeUtc != null ? $", started {r.StartTimeUtc}" : "")}\n" + (r.Path != null ? $"  path: {r.Path}\n" : "") +
        $"handles: {r.HandlesOpened} opened, {r.HandlesClosed} closed{(r.Detached ? " (all closed)" : " (NOT all closed)")}; read-only access:\n" +
        string.Concat(r.Access.Select(a => $"  {a}\n")) + string.Concat(r.Notes.Select(n => $"note: {n}\n"));

    public static string LiveSummary(LiveProcessService.LiveReport r)
    {
        var sb = new StringBuilder();
        if (r.Counts is { } c)
            sb.AppendLine($"Counts: {Plural(c.Modules, "module")}, {Plural(c.Threads, "thread")}, {Plural(c.Regions, "committed region")} of {c.RegionsTotal} " +
                          "(view=modules, threads, regions, stacks list them)");
        if (r.MainModule is { } m) sb.AppendLine("Main module: " + Module(m).Replace("\n", "\n  "));
        if (r.LargestRegions is { Count: > 0 } regions)
        {
            sb.AppendLine("Largest committed regions:");
            foreach (var x in regions) sb.AppendLine("  " + Memory(x));
        }
        return sb.ToString();
    }

    public static string LiveThread(LiveProcessService.ThreadRow t) =>
        $"{t.Id}{(t.Name != null ? $" \"{t.Name}\"" : "")}: {t.Location ?? t.InstructionPointer ?? t.Error ?? "no context"}" +
        $" (ip {t.InstructionPointer ?? "?"}, sp {t.StackPointer ?? "?"}, stack {t.StackLow}-{t.StackHigh}, teb {t.Teb}" +
        (t.StartAddress != null ? $", start {t.StartSymbol ?? t.StartAddress}" : "") + (t.SuspendCount > 0 ? $", suspended {t.SuspendCount}" : "") + $", priority {t.Priority})" +
        (t.Registers != null ? $"\nregisters: {t.Registers}" : "") + (t.Error != null && t.Location != null ? $"\nerror: {t.Error}" : "");

    public static string Memory(MinidumpService.MemoryRow m) =>
        $"{m.Base}-{m.End} {m.Size}" + (m.State != null ? $" {m.State}" : "") + (m.Protection != null ? $" {m.Protection}" : "") + (m.Type != null ? $" {m.Type}" : "") +
        (m.Module != null ? $" {m.Module}" : "") + (m.Captured is { } cap && m.State != "free" ? $" captured {cap:N0}" : "");
}
