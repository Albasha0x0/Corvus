using System.Text;
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

    public static string Memory(MinidumpService.MemoryRow m) =>
        $"{m.Base}-{m.End} {m.Size}" + (m.State != null ? $" {m.State}" : "") + (m.Protection != null ? $" {m.Protection}" : "") + (m.Type != null ? $" {m.Type}" : "") +
        (m.Module != null ? $" {m.Module}" : "") + (m.Captured is { } cap && m.State != "free" ? $" captured {cap:N0}" : "");
}
