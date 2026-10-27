using System.Text.Json;
using Corvus.Core;
using Corvus.Native.Code;
using Corvus.Native.Diff;

namespace Corvus.Native.Patching;

/// <summary>A patch to migrate: where it was in the old build, its pre-patch and replacement bytes, and its origin.</summary>
public sealed record MigratablePatch(uint Rva, byte[] Original, byte[] Replacement, string Description, string? Assembly, bool IsStub = false)
{
    public bool FromAsm => Assembly != null;

    /// <summary>A stub patch's new code (null when unknown, e.g. a patch set exported before it was recorded).</summary>
    public byte[]? StubCode { get; init; }
    /// <summary>A stub patch's patch_asm text of the new code (null for raw bytes).</summary>
    public string? StubAssembly { get; init; }
    /// <summary>A stub patch's mode: replace, before or after.</summary>
    public string? StubMode { get; init; }
    /// <summary>A stub patch that placed its stub in a new section (the file grew).</summary>
    public bool Grown { get; init; }
}

/// <summary>One patch's migration outcome: where it mapped, whether it would be reapplied, and why not.</summary>
public sealed record PatchMigrationStep(
    MigratablePatch Patch,
    uint? NewRva,
    double Confidence,
    int? Tier,
    bool Apply,
    string Status,
    string Reason,
    string Detail,
    byte[]? NewReplacement);

/// <summary>Maps byte patches to a new build, verifies their original bytes (address bytes masked for patch_asm patches) and prepares them through the normal patch path; applies nothing itself.</summary>
public static class PatchMigration
{
    /// <summary>Reads the patches of an exported JSON patch set (<see cref="PatchExport"/> json), by old RVA.</summary>
    public static List<MigratablePatch> FromJson(string json)
    {
        List<MigratablePatch> patches = [];
        JsonDocument doc;
        try { doc = JsonDocument.Parse(json); }
        catch (JsonException ex) { throw new ToolError(ErrorCode.InvalidArgument, $"The patch set is not valid JSON: {ex.Message}", "pass a file written by export_native_patches with format=json"); }
        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("kind", out var kind) || kind.GetString() is not (PatchExport.JsonKind or PatchExport.LegacyJsonKind))
                throw new ToolError(ErrorCode.InvalidArgument, $"The JSON is not a patch set (kind {PatchExport.JsonKind}).", "pass a file written by export_native_patches with format=json");
            if (!root.TryGetProperty("patches", out var arr) || arr.ValueKind != JsonValueKind.Array)
                return patches;
            foreach (var p in arr.EnumerateArray())
            {
                uint rva = (uint)Convert.ToInt64(p.GetProperty("rva").GetString()!, 16);
                var original = Convert.FromHexString(p.GetProperty("original").GetString()!);
                var replacement = Convert.FromHexString(p.GetProperty("replacement").GetString()!);
                var description = p.TryGetProperty("description", out var d) ? d.GetString() ?? "" : "";
                string? assembly = p.TryGetProperty("origin", out var o) && o.GetString() == "asm" && p.TryGetProperty("assembly", out var a) ? a.GetString() : null;
                bool hasStub = p.TryGetProperty("stub", out var st) && st.ValueKind == JsonValueKind.Object;
                bool isStub = p.TryGetProperty("origin", out var o2) && o2.GetString() == "stub" || hasStub;
                string? Text(string name) => hasStub && st.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
                patches.Add(new MigratablePatch(rva, original, replacement, description, assembly, isStub)
                {
                    StubCode = Text("newCode") is { } code ? Convert.FromHexString(code) : null,
                    StubAssembly = Text("newAssembly"),
                    StubMode = Text("mode"),
                    Grown = Text("placement")?.StartsWith("new section", StringComparison.Ordinal) ?? false,
                });
            }
        }
        return patches;
    }

    public static MigratablePatch From(NativePatch patch) =>
        new(patch.Rva, patch.Original, patch.Replacement, patch.Description, patch.Assembly, patch.Stub != null)
        {
            StubCode = patch.Stub?.NewCode,
            StubAssembly = patch.Stub?.NewAssembly,
            StubMode = patch.Stub?.Mode,
            Grown = patch.Growth != null,
        };

    /// <summary>Plans each patch's migration; without <paramref name="prepareStub"/> stub patches are refused extended_patch.</summary>
    public static List<PatchMigrationStep> Plan(
        MatchResult match,
        IReadOnlyList<MigratablePatch> patches,
        Action<uint, byte[], string?> prepare,
        CancellationToken ct,
        Func<uint, MigratablePatch, byte[]>? prepareStub = null)
    {
        var mapper = new AddressMapper(match);
        return Plan(mapper.Map, match.Old.Index, match.New.Index, patches, prepare, ct, prepareStub);
    }

    /// <summary>Replays a patch set on its own build; a patch already there is already_present.</summary>
    public static List<PatchMigrationStep> PlanSameBuild(NativeCodeIndex index, IReadOnlyList<MigratablePatch> patches, Action<uint, byte[], string?> prepare,
        CancellationToken ct) =>
        Plan((rva, _) => new MappedAddress(rva, rva, 1, "same_build", "the build the patch set was made for", null, []), index, index, patches, prepare, ct, null);

    /// <summary>The SHA-256 of the file a json patch set was made for, or null.</summary>
    public static string? ImageSha256(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.TryGetProperty("image", out var image) && image.TryGetProperty("sha256", out var sha) ? sha.GetString() : null;
        }
        catch (JsonException) { return null; }
    }

    private static List<PatchMigrationStep> Plan(
        Func<uint, CancellationToken, MappedAddress> map,
        NativeCodeIndex oldIndex,
        NativeCodeIndex newIndex,
        IReadOnlyList<MigratablePatch> patches,
        Action<uint, byte[], string?> prepare,
        CancellationToken ct,
        Func<uint, MigratablePatch, byte[]>? prepareStub)
    {
        var oldDecoder = TryDecoder(oldIndex);
        var newDecoder = TryDecoder(newIndex);
        var steps = new List<PatchMigrationStep>(patches.Count);

        foreach (var patch in patches)
        {
            ct.ThrowIfCancellationRequested();
            if (patch.IsStub && prepareStub != null)
            {
                steps.Add(PlanStub(map, newIndex, oldDecoder, newDecoder, patch, prepareStub, ct));
                continue;
            }
            if (patch.IsStub)
            {
                // A stub patch does not map byte-for-byte, so it must be re-created on the new build.
                steps.Add(Refuse(patch, null, 0, null, "extended_patch", "a patch-site extension (relocation stub) must be re-applied on the new build with patch_asm/patch_bytes extend=true"));
                continue;
            }
            var mapped = map(patch.Rva, ct);
            int? tier = mapped.Pair?.Tier;
            if (mapped.NewRva is not { } newRva)
            {
                // The mapper's reason is the refusal reason.
                steps.Add(Refuse(patch, null, mapped.Confidence, tier, mapped.Reason, mapped.Detail));
                continue;
            }

            var found = new byte[patch.Original.Length];
            int read = newIndex.Image.Read(newRva, found);
            if (read < found.Length)
            {
                steps.Add(Refuse(patch, newRva, mapped.Confidence, tier, "not_mapped", $"only {read} of {found.Length} bytes are mapped at the new address"));
                continue;
            }

            var (matches, mask) = patch.FromAsm
                ? MaskedEqual(oldDecoder, patch.Rva, patch.Original, newDecoder, newRva, found)
                : (patch.Original.AsSpan().SequenceEqual(found), null);
            if (!matches && found.AsSpan().SequenceEqual(patch.Replacement))
            {
                steps.Add(Refuse(patch, newRva, mapped.Confidence, tier, "already_present", "the replacement bytes are already there"));
                continue;
            }
            if (!matches)
            {
                steps.Add(Refuse(patch, newRva, mapped.Confidence, tier, "original_bytes_differ",
                    $"expected {Hex(patch.Original, mask)} at the new address, found {Hex(found, mask)}" + (mask != null ? " (?? = relocated / RIP-relative bytes ignored)" : "")));
                continue;
            }

            byte[] replacement;
            string? assembly = patch.Assembly;
            if (patch.FromAsm)
            {
                try
                {
                    replacement = X86Assembler.Assemble(newIndex.Image.Arch, newIndex.Image.ImageBase + newRva, patch.Assembly!,
                        name => { try { return newIndex.Image.ImageBase + NativeCodeIndexAddress(newIndex, name); } catch (ToolError) { return null; } }).Bytes;
                }
                catch (ToolError ex)
                {
                    steps.Add(Refuse(patch, newRva, mapped.Confidence, tier, "assemble_failed", $"re-assembling the recorded instructions at the new address failed: {ex.Message}"));
                    continue;
                }
            }
            else replacement = (byte[])patch.Replacement.Clone();

            try { prepare(newRva, replacement, assembly); }
            catch (ToolError ex)
            {
                steps.Add(Refuse(patch, newRva, mapped.Confidence, tier, ReasonFor(ex), ex.Message));
                continue;
            }
            steps.Add(new PatchMigrationStep(patch, newRva, mapped.Confidence, tier, true, "apply", "mapped",
                $"{mapped.Reason}: {mapped.Detail}", replacement));
        }
        return steps;
    }

    /// <summary>Migrates a stub-extended patch through <paramref name="prepareStub"/>, whose failure code is the refusal reason.</summary>
    private static PatchMigrationStep PlanStub(Func<uint, CancellationToken, MappedAddress> map, NativeCodeIndex newIndex, MaskedDecoder? oldDecoder, MaskedDecoder? newDecoder,
        MigratablePatch patch, Func<uint, MigratablePatch, byte[]> prepareStub, CancellationToken ct)
    {
        if (patch.StubCode == null)
            return Refuse(patch, null, 0, null, "stub_code_unknown", "the patch set does not record the stub's new code; re-apply it with extend=true");
        var mapped = map(patch.Rva, ct);
        int? tier = mapped.Pair?.Tier;
        if (mapped.NewRva is not { } newRva) return Refuse(patch, null, mapped.Confidence, tier, mapped.Reason, mapped.Detail);
        var found = new byte[patch.Original.Length];
        int read = newIndex.Image.Read(newRva, found);
        if (read < found.Length)
            return Refuse(patch, newRva, mapped.Confidence, tier, "not_mapped", $"only {read} of {found.Length} bytes are mapped at the new address");
        var (matches, mask) = MaskedEqual(oldDecoder, patch.Rva, patch.Original, newDecoder, newRva, found);
        if (!matches)
            return Refuse(patch, newRva, mapped.Confidence, tier, "displaced_bytes_differ",
                $"the instructions the stub displaces were {Hex(patch.Original, mask)}, the new site has {Hex(found, mask)}" + (mask != null ? " (?? = address bytes ignored)" : ""));
        byte[] site;
        try { site = prepareStub(newRva, patch); }
        catch (ToolError ex)
        {
            var code = System.Text.RegularExpressions.Regex.Match(ex.Message, "^([a-z0-9_]+): ") is { Success: true } m ? m.Groups[1].Value : ReasonFor(ex);
            return Refuse(patch, newRva, mapped.Confidence, tier, code, ex.Message);
        }
        return new PatchMigrationStep(patch, newRva, mapped.Confidence, tier, true, "apply", "mapped", $"{mapped.Reason}: {mapped.Detail}; stub re-created", site);
    }

    private static uint NativeCodeIndexAddress(NativeCodeIndex index, string name)
    {
        if (name.StartsWith("sub_", StringComparison.OrdinalIgnoreCase) && NativeAddress.Number(name[4..]) is { } n)
        {
            if (n < index.Image.SizeOfImage && index.FunctionByStart((uint)n) != null) return (uint)n;
            if (n >= index.Image.ImageBase && n - index.Image.ImageBase < index.Image.SizeOfImage) return (uint)(n - index.Image.ImageBase);
        }
        return NativeAddress.Parse(index.Image, name, index.AddressesOfName);
    }

    private static MaskedDecoder? TryDecoder(NativeCodeIndex index)
    {
        try { return new MaskedDecoder(index.Image); }
        catch (NotSupportedException) { return null; }
    }

    /// <summary>Whether two byte spans match with address bytes masked; exact when either side does not decode.</summary>
    private static (bool Equal, bool[]? Mask) MaskedEqual(MaskedDecoder? oldDec, uint oldRva, byte[] oldBytes, MaskedDecoder? newDec, uint newRva, byte[] newBytes)
    {
        if (oldDec == null || newDec == null) return (oldBytes.AsSpan().SequenceEqual(newBytes), null);
        var mask = new bool[oldBytes.Length];
        Fill(oldDec, oldRva, oldBytes, mask);
        Fill(newDec, newRva, newBytes, mask);
        for (int i = 0; i < oldBytes.Length; i++)
            if (!mask[i] && oldBytes[i] != newBytes[i]) return (false, mask);
        return (true, mask.Any(m => m) ? mask : null);
    }

    private static void Fill(MaskedDecoder decoder, uint rva, byte[] bytes, bool[] mask)
    {
        var insns = new List<MaskedInsn>();
        decoder.Decode(rva, rva + (uint)bytes.Length, insns);
        foreach (var insn in insns)
        {
            int at = (int)(insn.Rva - rva);
            for (int i = 0; i < insn.Length; i++)
                if (at + i >= 0 && at + i < mask.Length && insn.IsWild(i)) mask[at + i] = true;
        }
    }

    /// <summary>Maps a prepare-path <see cref="ToolError"/> to a short refusal reason.</summary>
    private static string ReasonFor(ToolError ex) =>
        ex.Message.Contains("relocation slot", StringComparison.OrdinalIgnoreCase) || (ex.Remediation?.Contains("RIP-relative", StringComparison.OrdinalIgnoreCase) ?? false)
            ? "relocation_slot_unavailable"
        : ex.Message.Contains("middle of an instruction", StringComparison.OrdinalIgnoreCase) ? "mid_instruction"
        : ex.Message.Contains("past the end", StringComparison.OrdinalIgnoreCase) ? "past_function_end"
        : ex.Code == ErrorCode.Conflict ? "conflicts_with_existing_patch"
        : "cannot_prepare";

    private static PatchMigrationStep Refuse(MigratablePatch patch, uint? newRva, double confidence, int? tier, string reason, string detail) =>
        new(patch, newRva, confidence, tier, false, "refused", reason, detail, null);

    private static string Hex(byte[] bytes, bool[]? mask)
    {
        var chars = new List<string>(bytes.Length);
        for (int i = 0; i < bytes.Length; i++) chars.Add(mask != null && mask[i] ? "??" : bytes[i].ToString("X2"));
        return string.Join("", chars);
    }
}
