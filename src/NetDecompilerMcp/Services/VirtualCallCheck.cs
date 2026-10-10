using System.ComponentModel;
using System.Diagnostics;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Msvc;
using NetDecompilerMcp.Native.Providers;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Compares the virtual call resolution of a code index with what IDA makes of the same call instructions. A sample of
/// functions with virtual call sites is decompiled after the RTTI class types are pushed (their methods' this typed as
/// the class): a call Hex-Rays shows through a member of a &lt;class&gt;_vftable struct names a static class and slot, whose
/// vftable entry is IDA's target; calls it resolved to a function and IDA's own code references from the call instruction
/// count too. Per site: agree (IDA's target is among ours), compatible (IDA's class is a base of our receiver class: its
/// target is the implementation ours overrides), disagree, ida_only (we have no target), ours_only (IDA has none), both_none.
/// </summary>
public static class VirtualCallCheck
{
    [Description("A site where IDA's target is not among ours.")]
    public sealed record Disagreement(
        [property: Description("VA of the call instruction.")] string Address,
        [property: Description("The calling function.")] string Function,
        [property: Description("Our targets (names), or our status when unresolved.")] IReadOnlyList<string> Ours,
        [property: Description("IDA's targets (names).")] IReadOnlyList<string> Ida,
        [property: Description("How IDA got them: the vftable struct type and member offset, direct, or xref.")] string IdaEvidence);

    [Description("Agreement of the RTTI virtual call resolution with IDA (Hex-Rays with the RTTI class types pushed, and IDA's code references).")]
    public sealed record Report(
        [property: Description("The engine compared with.")] string Engine,
        [property: Description("Functions with virtual call sites chosen (evenly spaced: those with resolved sites, then half as many with only unresolved ones).")] int FunctionsSampled,
        [property: Description("Functions the decompiler finished.")] int FunctionsDecompiled,
        [property: Description("Functions the decompiler failed on.")] int FunctionsFailed,
        [property: Description("Functions not reached within the time budget.")] int FunctionsSkipped,
        [property: Description("Virtual call sites in the decompiled functions.")] int SitesChecked,
        [property: Description("IDA's target is one of ours.")] int Agree,
        [property: Description("IDA names the slot of a base class of our receiver class (or of an abstract class: a pure virtual stub): the implementation ours override.")] int Compatible,
        [property: Description("IDA's target is not among ours.")] int Disagree,
        [property: Description("IDA's vftable member offset differs from the slot the call instruction reads: its types do not model the instruction (not counted as agreement or disagreement).")] int IdaInconsistent,
        [property: Description("IDA has a target, we have none.")] int IdaOnly,
        [property: Description("We have targets, IDA has none.")] int OursOnly,
        [property: Description("Neither has a target.")] int BothNone,
        [property: Description("(agree + compatible) / (agree + compatible + disagree): the sites where IDA's view is consistent with ours; null when no site has targets on both sides.")] double? AgreementRate,
        [property: Description("agree / (agree + compatible + disagree): IDA's target itself among ours.")] double? StrictAgreementRate,
        [property: Description("Up to 20 disagreeing sites.")] IReadOnlyList<Disagreement> Disagreements,
        [property: Description("Up to 10 sites where IDA has a target and we have none (Ours holds our reason).")] IReadOnlyList<Disagreement> IdaOnlySites,
        [property: Description("What limited the check.")] IReadOnlyList<string> Notes,
        [property: Description("Wall time in seconds (decompilation dominates).")] double Seconds);

    private const int Batch = 25;

    public static async Task<Report> RunAsync(LoadedNative native, NativeCodeIndex index, INativeDecompilerSession session, NativeTypePush? types,
        int sampleFunctions, double seconds, IProgress<string>? progress, CancellationToken ct)
    {
        var clock = Stopwatch.StartNew();
        var notes = new List<string>();
        var rtti = native.GetAnalysis(n => MsvcRtti.Analyze(n.Image, ct: ct));
        if (types != null) await types.EnsureAsync(native, session, ct).ConfigureAwait(false);
        else notes.Add("no type push: IDA sees the methods untyped");

        // vftable struct names as the type push defines them -> (class, vftable)
        var batch = NativeTypePush.Build(native, null, rtti, ct);
        var structs = new Dictionary<string, (string Class, NativeVftableType Vftable)>(StringComparer.Ordinal);
        foreach (var c in batch.Classes)
            foreach (var v in c.Vftables)
                structs.TryAdd(v.Offset == 0 ? c.Name + "_vftable" : $"{c.Name}_vftable_{v.Offset:X}", (c.Name, v));
        // the class identifiers the push gave (NativeTypePush.Build: by base count, then name; a repeated identifier gets a suffix)
        var classByIdent = new Dictionary<string, MsvcRttiClass>(StringComparer.Ordinal);
        var polymorphic = rtti.Classes.Where(c => c.Vtables.Count > 0).ToList();
        var named = new HashSet<string>(StringComparer.Ordinal);
        foreach (var c in polymorphic.OrderBy(c => c.Bases.Count).ThenBy(c => c.Name, StringComparer.Ordinal).Take(NativeTypePush.MaxClasses))
        {
            if (!named.Add(c.Name)) continue;
            var id = Il2CppLayout.Identifier(c.Name.Replace("::", "__"));
            for (int i = 2; classByIdent.ContainsKey(id); i++) id = $"{Il2CppLayout.Identifier(c.Name.Replace("::", "__"))}_{i}";
            classByIdent[id] = c;
        }
        var byTd = polymorphic.GroupBy(c => c.TypeDescriptorRva).ToDictionary(g => g.Key, g => g.First());

        // the sample: functions with resolved sites, then half as many with only unresolved ones, evenly spaced
        var sitesByFunction = index.VirtualCalls.Sites.GroupBy(s => s.Function).ToDictionary(g => g.Key, g => g.ToList());
        var resolved = sitesByFunction.Where(kv => kv.Value.Any(s => s.Status != VirtualCallStatus.Unresolved)).Select(kv => kv.Key).Order().ToList();
        var unresolved = sitesByFunction.Where(kv => kv.Value.All(s => s.Status == VirtualCallStatus.Unresolved)).Select(kv => kv.Key).Order().ToList();
        int n = Math.Clamp(sampleFunctions, 1, 5000);
        var sample = Spread(resolved, n).Concat(Spread(unresolved, Math.Max(1, n / 2))).ToList();

        var deadline = DateTime.UtcNow.AddSeconds(Math.Clamp(seconds, 5, 3600));
        var ida = new Dictionary<uint, List<NativeCallTarget>>();
        var done = new HashSet<uint>();
        int decompiled = 0, failed = 0, skipped = 0;
        bool decompiler = true;
        for (int i = 0; i < sample.Count; i += Batch)
        {
            ct.ThrowIfCancellationRequested();
            var chunk = sample.Skip(i).Take(Batch).ToList();
            double left = (deadline - DateTime.UtcNow).TotalSeconds;
            if (left <= 1) { skipped += sample.Count - i; break; }
            progress?.Report($"cross-checking virtual calls with {session.ProviderId}: {i}/{sample.Count} functions");
            if (types != null) await types.EnsureMethodsAsync(native, session, chunk, ct).ConfigureAwait(false);
            var sites = chunk.SelectMany(f => sitesByFunction[f]).Select(s => s.Rva).ToList();
            var r = await session.GetCallTargetsAsync(chunk, sites, left, ct).ConfigureAwait(false);
            decompiler &= r.DecompilerAvailable;
            decompiled += r.Decompiled;
            failed += r.Failed.Count;
            skipped += r.Skipped;
            // the functions the decompiler finished: the chunk without the failed ones and the tail it had no time for
            var failedHere = r.Failed.Select(x => x.Function).ToHashSet();
            foreach (var f in chunk.Take(Math.Max(0, chunk.Count - r.Skipped)))
                if (!failedHere.Contains(f) || !r.DecompilerAvailable) done.Add(f);
            foreach (var t in r.Targets)
            {
                if (!ida.TryGetValue(t.Site, out var list)) ida[t.Site] = list = [];
                list.Add(t);
            }
        }
        if (!decompiler) notes.Add($"the {session.ProviderId} decompiler is not available: only IDA's code references are compared");

        // IDA follows a call through the CFG dispatch or check pointer to the function the pointer holds in the file (the
        // no-op dispatcher): not a target of the call
        var dispatchers = new HashSet<uint>();
        if (native.Image is Native.Pe.PeFile { LoadConfig: { } lc })
        {
            var b = new byte[8];
            foreach (var va in new[] { lc.GuardCfDispatchFunctionPointer, lc.GuardCfCheckFunctionPointer, lc.GuardXfgDispatchFunctionPointer,
                         lc.GuardXfgCheckFunctionPointer, lc.GuardXfgTableDispatchFunctionPointer })
            {
                if (va <= index.Image.ImageBase || va - index.Image.ImageBase >= index.Image.SizeOfImage) continue;
                int size = index.Image.Is64Bit ? 8 : 4;
                if (index.Image.Read((uint)(va - index.Image.ImageBase), b.AsSpan(0, size)) != size) continue;
                ulong target = size == 8 ? BitConverter.ToUInt64(b) : BitConverter.ToUInt32(b);
                if (target > index.Image.ImageBase && target - index.Image.ImageBase < index.Image.SizeOfImage) dispatchers.Add((uint)(target - index.Image.ImageBase));
            }
        }

        string Name(uint rva) => index.NameAt(rva) ?? $"sub_{rva:X}";
        string Va(uint rva) => NativeAddress.Va(index.Image, rva);
        int ptr = index.Image.Is64Bit ? 8 : 4;
        int agree = 0, compatible = 0, disagree = 0, idaOnly = 0, oursOnly = 0, bothNone = 0, checkedSites = 0;
        var disagreements = new List<Disagreement>();
        var idaOnlySites = new List<Disagreement>();
        int idaInconsistent = 0;
        bool IsPure(uint rva) => index.FunctionByStart(rva) is { } fn
            && ((fn.Flags & FunctionFlags.NoReturn) != 0 || fn.ThunkImport?.Name is "_purecall" or "purecall" || fn.KnownName is "_purecall" or "__purecall");
        foreach (var f in sample)
        {
            if (!done.Contains(f)) continue;
            foreach (var s in sitesByFunction[f])
            {
                checkedSites++;
                var ours = index.VirtualTargets(s.Rva);
                var idaTargets = new HashSet<uint>();
                var evidence = new List<string>();
                MsvcRttiClass? idaClass = null;
                bool mismatch = false;
                foreach (var t in ida.GetValueOrDefault(s.Rva) ?? [])
                {
                    if (t.Kind is "xref" or "direct" && t.Target is uint direct)
                    {
                        if (dispatchers.Contains(direct)) continue;
                        idaTargets.Add(direct);
                        evidence.Add(t.Kind);
                    }
                    else if (t.Kind == "vftable" && t.TypeName != null && structs.TryGetValue(t.TypeName, out var st) && t.MemberOffset is int m
                             && m >= 0 && m % ptr == 0 && m / ptr < st.Vftable.Slots.Count)
                    {
                        // the slot is what the instruction reads: a member at another offset means IDA's types do not model it
                        if (m != s.Slot * ptr) { mismatch = true; continue; }
                        idaTargets.Add(st.Vftable.Slots[m / ptr]);
                        evidence.Add($"{t.TypeName}+0x{m:X}");
                        idaClass ??= classByIdent.GetValueOrDefault(st.Class);
                    }
                }
                if (idaTargets.Count == 0)
                {
                    if (mismatch) idaInconsistent++;
                    else if (ours.Count > 0) oursOnly++;
                    else bothNone++;
                    continue;
                }
                if (ours.Count == 0)
                {
                    idaOnly++;
                    if (idaOnlySites.Count < 10)
                        idaOnlySites.Add(new Disagreement(Va(s.Rva), index.FunctionAt(s.Rva)?.Name ?? Va(f), [VirtualCallSet.ReasonCode(s.Reason) ?? "unresolved"],
                            idaTargets.Take(8).Select(Name).ToList(), string.Join(", ", evidence.Distinct())));
                    continue;
                }
                if (ours.Any(idaTargets.Contains)) { agree++; continue; }
                // IDA names the slot of a less derived class: a pure virtual stub, or an implementation that our receiver's class overrides
                var receiver = byTd.GetValueOrDefault(s.ClassTypeDescriptor);
                if (idaTargets.All(IsPure) || idaClass != null && receiver != null && !ReferenceEquals(idaClass, receiver)
                    && receiver.Bases.Any(b => b.TypeDescriptorRva == idaClass.TypeDescriptorRva))
                {
                    compatible++;
                    continue;
                }
                disagree++;
                if (disagreements.Count < 20)
                    disagreements.Add(new Disagreement(Va(s.Rva), index.FunctionAt(s.Rva)?.Name ?? Va(f), ours.Take(8).Select(Name).ToList(),
                        idaTargets.Take(8).Select(Name).ToList(), string.Join(", ", evidence.Distinct())));
            }
        }
        int both = agree + compatible + disagree;
        if (skipped > 0) notes.Add($"{skipped} sampled functions were not decompiled within {seconds:0} s");
        return new Report(session.ProviderId, sample.Count, decompiled, failed, skipped, checkedSites, agree, compatible, disagree, idaInconsistent, idaOnly,
            oursOnly, bothNone, both > 0 ? Math.Round((double)(agree + compatible) / both, 4) : null, both > 0 ? Math.Round((double)agree / both, 4) : null,
            disagreements, idaOnlySites, notes, Math.Round(clock.Elapsed.TotalSeconds, 1));
    }

    /// <summary>Up to <paramref name="count"/> items spread evenly over <paramref name="items"/>.</summary>
    private static IEnumerable<uint> Spread(List<uint> items, int count)
    {
        if (items.Count <= count) return items;
        return Enumerable.Range(0, count).Select(i => items[(int)((long)i * items.Count / count)]);
    }
}
