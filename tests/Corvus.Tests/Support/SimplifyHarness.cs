using System.Diagnostics;
using System.Globalization;
using PEReaderExtensions = System.Reflection.Metadata.PEReaderExtensions;
using System.Reflection.PortableExecutable;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ICSharpCode.Decompiler.Metadata;
using Corvus.Core;
using Corvus.Services.Simplify;

namespace Corvus.Tests;

/// <summary>Runs simplify_methods over every method and checks limits, and that dnlib and the decompiler read back exactly the written bodies.</summary>
internal static class SimplifyHarness
{
    /// <summary>Per-method allocation ceiling: far above the evaluator's 16 MB simulated memory, far below a runaway.</summary>
    public const long MethodAllocationLimit = 512L * 1024 * 1024;

    /// <summary>Slack over the per-method time limit (the limit is checked between steps, not preemptively).</summary>
    public static readonly TimeSpan TimeSlack = TimeSpan.FromSeconds(2);

    public sealed class Outcome
    {
        public required string Name { get; init; }
        public required List<MethodChange> Changes { get; init; }
        /// <summary>Time spent in the engine only (loading, writing and checking excluded).</summary>
        public required TimeSpan Elapsed { get; init; }
        /// <summary>The whole library path: load, read the bodies, simplify, save (checking excluded).</summary>
        public required TimeSpan Total { get; init; }
        public required (string Method, TimeSpan Time) Slowest { get; init; }
        public required (string Method, long Bytes) Hungriest { get; init; }
        public byte[]? Image { get; init; }
        /// <summary>Crashes, limit overruns and round-trip mismatches; empty when the run is clean.</summary>
        public List<string> Problems { get; } = new();
        public int Methods => Changes.Count;
        public int Changed => Changes.Count(c => c.Changed);
        public bool TimedOut(string method) => Changes.Any(c => c.Rejected?.Reason == FallbackReason.TimeLimit && Label(c.Method) == method);

        /// <summary>Fallback reason codes with counts: calls kept (bail-outs), rewrites skipped and methods left unchanged.</summary>
        public Dictionary<string, int> Fallbacks() => Changes
            .SelectMany(c => c.Bailouts.Concat(c.Skipped).Select(b => b.Reason).Concat(c.Rejected is { } r ? [r.Reason] : Array.Empty<FallbackReason>()))
            .GroupBy(SimplifyManifest.CodeOf).ToDictionary(g => g.Key, g => g.Count());
    }

    /// <summary>Loads <paramref name="path"/> into a fresh workspace, simplifies every method, writes and checks the image.</summary>
    public static Outcome Run(string path, SimplifyOptions? options = null, CancellationToken ct = default)
    {
        long start = Stopwatch.GetTimestamp();
        using var workspace = new AssemblyWorkspace(new ServerOptions { BackgroundIndexing = false, WatchFiles = false });
        var asm = workspace.Load(path);
        return workspace.Write(() => Run(asm, options ?? new SimplifyOptions(), start, ct));
    }

    private static Outcome Run(LoadedAssembly asm, SimplifyOptions options, long start, CancellationToken ct)
    {
        var methods = asm.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody).ToList();
        if (asm.HasUnreadableBodies) methods.Clear(); // as simplify_methods: nothing is rewritten
        var simplifier = new MethodSimplifier(asm.Module, options);
        var changes = new List<MethodChange>(methods.Count);
        var problems = new List<string>();
        var limit = options.EffectiveLimits.MethodTimeLimit + TimeSlack;
        var wallLimit = options.EffectiveLimits.MethodTimeLimit * MethodMeter.WallFactor + TimeSlack;
        var elapsed = TimeSpan.Zero;
        (string, TimeSpan) slowest = ("", TimeSpan.Zero);
        (string, long) hungriest = ("", 0);

        foreach (var m in methods)
        {
            ct.ThrowIfCancellationRequested();
            long allocated = GC.GetAllocatedBytesForCurrentThread();
            long methodStart = Stopwatch.GetTimestamp();
            var cpuStart = ThreadCpuClock.Now();
            List<MethodChange> result;
            try
            {
                result = simplifier.Run([m], ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                problems.Add($"crash: {Label(m)}: {ex}");
                continue;
            }
            var time = Stopwatch.GetElapsedTime(methodStart);
            var cpu = ThreadCpuClock.Now() - cpuStart;
            long bytes = GC.GetAllocatedBytesForCurrentThread() - allocated;
            elapsed += time;
            if (time > slowest.Item2) slowest = (Label(m), time);
            if (bytes > hungriest.Item2) hungriest = (Label(m), bytes);
            // The limit is the method's CPU time, so a loaded machine's waits do not count; wall time has a wider bound.
            if (cpu > limit || time > wallLimit)
                problems.Add($"time: {Label(m)} took {cpu.TotalSeconds:0.00} s of CPU time, {time.TotalSeconds:0.00} s of wall time (limit {options.EffectiveLimits.MethodTimeLimit.TotalSeconds:0.##} s)");
            if (bytes > MethodAllocationLimit) problems.Add($"memory: {Label(m)} allocated {bytes / (1024 * 1024)} MB");
            foreach (var c in result)
            {
                changes.Add(c);
                if (c.Rejected?.Reason == FallbackReason.Unexpected) problems.Add($"crash: {Label(m)}: {c.Rejected}");
            }
        }

        // The image must contain the rewritten bodies and the untouched originals.
        foreach (var c in changes.Where(c => c.Changed)) c.Method.Body = c.NewBody!;
        var expected = methods.ToDictionary(m => m.MDToken.Raw);

        byte[]? image = null;
        try
        {
            image = asm.WriteToBytes();
        }
        catch (Exception ex)
        {
            problems.Add($"save: {ex.GetType().Name}: {ex.Message}");
        }
        var total = Stopwatch.GetElapsedTime(start);
        if (image != null) problems.AddRange(CheckImage(image, expected, changes));

        var outcome = new Outcome
        {
            Name = asm.AssemblyName, Changes = changes, Elapsed = elapsed, Total = total, Slowest = slowest, Hungriest = hungriest, Image = image,
        };
        outcome.Problems.AddRange(problems);
        return outcome;
    }

    /// <summary>Reloads the image with dnlib and with the decompiler's reader; every body must be the one written.</summary>
    private static IEnumerable<string> CheckImage(byte[] image, Dictionary<uint, MethodDef> expected, List<MethodChange> changes)
    {
        var problems = new List<string>();
        var rewritten = changes.Where(c => c.Changed).Select(c => c.Method.MDToken.Raw).ToHashSet();
        try
        {
            using var module = ModuleDefMD.Load(image);
            int seen = 0;
            foreach (var m in module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
            {
                if (!expected.TryGetValue(m.MDToken.Raw, out var source)) continue;
                seen++;
                var body = Describe(source.Body);
                var actual = Describe(m.Body);
                if (actual != body)
                {
                    problems.Add($"reload: {Label(m)} differs from the body written{FirstDifference(body, actual)}");
                    if (problems.Count > 20) break;
                    continue;
                }
                if (rewritten.Contains(m.MDToken.Raw))
                {
                    bool hasReturn = m.MethodSig.RetType.RemovePinnedAndModifiers().ElementType != ElementType.Void;
                    if (new BodyGraph(m.Body).Verify(hasReturn, out var error) == null) problems.Add($"reload: {Label(m)} does not verify: {error}");
                }
            }
            // Untouched bodies keep their original bytes, invalid ones (empty, branches outside the code) included.
            int missing = expected.Count - seen;
            if (missing != 0) problems.Add($"reload: {missing} method bodies missing");
        }
        catch (Exception ex)
        {
            problems.Add($"reload (dnlib): {ex.GetType().Name}: {ex.Message}");
        }

        try
        {
            using var pe = new PEFile("roundtrip", new MemoryStream(image), PEStreamOptions.PrefetchEntireImage);
            var reader = pe.Metadata;
            foreach (var handle in reader.MethodDefinitions)
            {
                var def = reader.GetMethodDefinition(handle);
                // Native methods of mixed-mode images point at machine code.
                if ((def.ImplAttributes & System.Reflection.MethodImplAttributes.CodeTypeMask) != System.Reflection.MethodImplAttributes.IL) continue;
                int rva = def.RelativeVirtualAddress;
                if (rva != 0) PEReaderExtensions.GetMethodBody(pe.Reader, rva).GetILBytes();
            }
        }
        catch (Exception ex)
        {
            problems.Add($"reload (decompiler reader): {ex.GetType().Name}: {ex.Message}");
        }
        return problems;
    }

    /// <summary>
    /// Methods whose bodies differ between two images of the same input; an empty list means the outputs agree method
    /// by method (byte equality of the images is checked separately).
    /// </summary>
    public static List<string> DifferingMethods(byte[] a, byte[] b)
    {
        using var ma = ModuleDefMD.Load(a);
        using var mb = ModuleDefMD.Load(b);
        var bodies = mb.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody).ToDictionary(m => m.MDToken.Raw, m => Describe(m.Body));
        return ma.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody)
            .Where(m => !bodies.TryGetValue(m.MDToken.Raw, out var other) || other != Describe(m.Body))
            .Select(Label).ToList();
    }

    public static string Label(MethodDef m) => $"{m.DeclaringType?.FullName}::{m.Name} [0x{m.MDToken.Raw:X8}]";

    /// <summary>A body as text: opcodes, operands (branch targets and locals by index), handlers and locals.</summary>
    public static string Describe(CilBody body)
    {
        var index = new Dictionary<Instruction, int>(body.Instructions.Count);
        for (int i = 0; i < body.Instructions.Count; i++) index[body.Instructions[i]] = i;
        string At(Instruction? i) => i == null ? "end" : index.TryGetValue(i, out int k) ? k.ToString(CultureInfo.InvariantCulture) : "?";
        var sb = new StringBuilder();
        foreach (var ins in body.Instructions)
        {
            sb.Append(ins.OpCode.Name);
            sb.Append(' ').Append(ins.Operand switch
            {
                null => "",
                Instruction t => "@" + At(t),
                IList<Instruction> ts => "(" + string.Join(",", ts.Select(At)) + ")",
                Local l => "V" + l.Index,
                Parameter p => "A" + p.Index,
                string s => "\"" + s + "\"",
                IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
                var other => other.ToString(),
            });
            sb.Append('\n');
        }
        foreach (var eh in body.ExceptionHandlers)
            sb.Append($"{eh.HandlerType} try {At(eh.TryStart)}-{At(eh.TryEnd)} filter {At(eh.FilterStart)} handler {At(eh.HandlerStart)}-{At(eh.HandlerEnd)} {eh.CatchType?.FullName}\n");
        sb.Append("locals ").Append(string.Join(",", body.Variables.Select(v => v.Type?.FullName)));
        return sb.ToString();
    }

    private static string FirstDifference(string expected, string actual)
    {
        var e = expected.Split('\n');
        var a = actual.Split('\n');
        for (int i = 0; i < Math.Max(e.Length, a.Length); i++)
        {
            var x = i < e.Length ? e[i] : "<none>";
            var y = i < a.Length ? a[i] : "<none>";
            if (x != y) return $" at line {i}: wrote '{x}', read '{y}'";
        }
        return "";
    }
}
