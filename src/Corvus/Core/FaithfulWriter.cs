using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.MD;
using dnlib.DotNet.Writer;
using DnMethodBody = dnlib.DotNet.Writer.MethodBody;
using Metadata = dnlib.DotNet.Writer.Metadata;
using Parameter = dnlib.DotNet.Parameter;

namespace Corvus.Core;

/// <summary>Writes an edited module keeping untouched bodies and signatures byte-for-byte; reports untouched parts that still differ.</summary>
/// <remarks>dnlib re-encodes every body and signature, which alters bodies it cannot represent; stored bytes are put back.</remarks>
internal sealed class FaithfulWriter
{
    private static readonly FieldInfo MethodToBody = typeof(Metadata).GetField("methodToBody", BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("dnlib's Metadata.methodToBody field is missing: the faithful writer needs updating for this dnlib version.");

    private readonly ModuleDefMD _module;
    private readonly RawImage _original;
    private readonly Func<ModuleDefMD> _pristine;
    private readonly List<SaveIssue> _issues = new();
    private readonly CollectingLogger _logger = new();

    /// <summary>Original methods (rid) written with their stored body, byte-for-byte.</summary>
    private readonly HashSet<int> _keptBodies = new();
    /// <summary>Original methods whose body an edit changed, and methods whose stored body cannot be read.</summary>
    private readonly HashSet<int> _editedBodies = new();
    private readonly HashSet<int> _unreadable = new();
    /// <summary>Signature rows (token) an edit changed: written as dnlib encodes them, not compared.</summary>
    private readonly HashSet<uint> _editedSignatures = new();
    /// <summary>Members whose writer errors are moot: their bytes were replaced with the original ones.</summary>
    private readonly HashSet<object> _restored = new(ReferenceEqualityComparer.Instance);

    private FaithfulWriter(ModuleDefMD module, RawImage original, Func<ModuleDefMD> pristine)
    {
        _module = module;
        _original = original;
        _pristine = pristine;
    }

    /// <summary>Writes the module to <paramref name="output"/>; <paramref name="pristine"/> loads the unedited original to tell edits apart.</summary>
    internal static SaveReport Write(ModuleDefMD module, RawImage? original, string? unreadable, Func<ModuleDefMD> pristine, Stream output)
    {
        if (original == null)
        {
            // Nothing to keep or compare with: the original's metadata cannot be read independently of dnlib.
            bool dropped = WriteModule(module, new CollectingLogger(), null, output);
            return new SaveReport([new SaveIssue(SaveIssueReason.Reencoded, 0, "module",
                $"the original image cannot be read for comparison ({unreadable}): the whole module is written as dnlib encodes it, unchecked"),
                .. dropped ? [PrecompiledCodeDropped(module)] : Array.Empty<SaveIssue>()]);
        }
        var writer = new FaithfulWriter(module, original, pristine);
        using var image = new MemoryStream();
        if (WriteModule(module, writer._logger, writer.OnWriterEvent, image)) writer._issues.Add(PrecompiledCodeDropped(module));
        var bytes = image.ToArray();
        writer.Verify(bytes);
        output.Write(bytes);
        return new SaveReport(writer._issues.OrderBy(i => i.ChangesBytes ? 0 : 1).ThenBy(i => i.Token).ToList());
    }

    /// <summary>The module as dnlib writes it (PreserveAll, errors collected, nothing kept from the original).</summary>
    internal static void WritePlain(ModuleDefMD module, Stream output) => WriteModule(module, new CollectingLogger(), null, output);

    /// <returns>True when the ReadyToRun code was dropped (<see cref="PrecompiledCodeDropped"/>).</returns>
    private static bool WriteModule(ModuleDefMD module, ILogger logger, EventHandler2<ModuleWriterEventArgs>? onEvent, Stream output)
    {
        bool dropPrecompiled = !module.IsILOnly && IsReadyToRun(module) && !HeadersHaveRoomForASection(module);
        if (module.IsILOnly || dropPrecompiled)
        {
            var opts = new ModuleWriterOptions(module) { Logger = logger };
            opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
            if (dropPrecompiled)
            {
                // The IL every method keeps runs without its precompiled code; the runtime compiles it at run time.
                opts.Cor20HeaderOptions.Flags = (module.Cor20HeaderFlags | ComImageFlags.ILOnly) & ~ComImageFlags.ILLibrary;
                opts.PEHeadersOptions.Machine = WithoutTargetOs(module.Machine);
            }
            if (onEvent != null) opts.WriterEvent += onEvent;
            module.Write(output, opts);
        }
        else
        {
            // Mixed-mode image: the native writer preserves native code and sections.
            var opts = new NativeModuleWriterOptions(module, optimizeImageSize: false) { Logger = logger };
            opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
            if (onEvent != null) opts.WriterEvent += onEvent;
            module.NativeWrite(output, opts);
        }
        return dropPrecompiled;
    }

    private static SaveIssue PrecompiledCodeDropped(ModuleDefMD module) => new(SaveIssueReason.PrecompiledCodeDropped, 0, "module",
        $"the ReadyToRun code ({module.Machine}) was dropped: the image's headers have no room for the section the native writer adds (builds for Linux and macOS fill them), so the module is written as IL only");

    private static bool IsReadyToRun(ModuleDefMD module) =>
        (module.Cor20HeaderFlags & ComImageFlags.ILLibrary) != 0 && module.Metadata.ImageCor20Header.ManagedNativeHeader.VirtualAddress != 0;

    private const int SectionHeaderSize = 40;

    /// <summary>The native writer adds a section; its header goes between the section table and the first section's data.</summary>
    private static bool HeadersHaveRoomForASection(ModuleDefMD module)
    {
        var sections = module.Metadata.PEImage.ImageSectionHeaders;
        if (sections.Count == 0) return true;
        long tableEnd = (long)(uint)sections[^1].EndOffset;
        long firstData = sections.Where(s => s.SizeOfRawData != 0).Select(s => (long)s.PointerToRawData).DefaultIfEmpty(long.MaxValue).Min();
        return firstData - tableEnd >= SectionHeaderSize;
    }

    /// <summary>ReadyToRun images for other systems XOR the machine with the system's value (Apple, FreeBSD, Linux, NetBSD, SunOS).</summary>
    private static readonly ushort[] TargetOsMachineValues = [0x4644, 0xADC4, 0x7B79, 0x1993, 0x1992];

    private static dnlib.PE.Machine WithoutTargetOs(dnlib.PE.Machine machine)
    {
        foreach (var os in TargetOsMachineValues)
            if ((dnlib.PE.Machine)((ushort)machine ^ os) is var plain && plain is dnlib.PE.Machine.AMD64 or dnlib.PE.Machine.ARM64 or dnlib.PE.Machine.ARMNT or dnlib.PE.Machine.I386)
                return plain;
        return machine;
    }

    /// <summary>Invalid bodies and signatures of an unedited module, without writing it; an unedited save keeps all bytes.</summary>
    internal static SaveReport Survey(ModuleDefMD module, RawImage original)
    {
        var issues = new List<SaveIssue>();
        for (int rid = 1; rid <= original.MethodCount; rid++)
        {
            uint token = (uint)MetadataTokens.GetToken(MetadataTokens.MethodDefinitionHandle(rid));
            try
            {
                var row = original.Method(rid);
                if (row.Rva == 0 || !row.IsIL) continue;
                var body = original.ReadBody(row.Rva, out var error);
                var problem = body == null ? error : original.Problem(body, rid);
                if (problem != null) issues.Add(new SaveIssue(SaveIssueReason.InvalidBody, token, Label(module.ResolveToken(token), token), problem));
            }
            catch (Exception ex) when (ex is BadImageFormatException or ArgumentException or InvalidOperationException or IndexOutOfRangeException)
            {
                issues.Add(new SaveIssue(SaveIssueReason.InvalidBody, token, $"0x{token:X8}", $"the method row cannot be read: {ex.Message}"));
            }
        }
        foreach (var table in RawImage.SignatureTables)
        {
            for (int rid = 1; rid <= original.Metadata.GetTableRowCount(table); rid++)
            {
                uint token = (uint)MetadataTokens.GetToken(MetadataTokens.EntityHandle(table, rid));
                try
                {
                    var stored = original.Blob(original.Signature(table, rid));
                    var row = module.ResolveToken(token);
                    var (encoded, unmatched) = SignatureComparer.Encode(row);
                    if (!unmatched && encoded.AsSpan().SequenceEqual(stored)) continue;
                    issues.Add(new SaveIssue(SaveIssueReason.MalformedSignature, token, Label(row, token),
                        encoded.Length == 0 ? $"signature blob {Hex(stored)} does not decode (dnlib would write an empty blob)"
                        : $"signature blob {Hex(stored)} does not decode as written (dnlib would write {Hex(encoded)})"));
                }
                catch (Exception ex) when (ex is BadImageFormatException or ArgumentException or InvalidOperationException or IndexOutOfRangeException)
                {
                    issues.Add(new SaveIssue(SaveIssueReason.MalformedSignature, token, $"0x{token:X8}", $"the signature cannot be read: {ex.Message}"));
                }
            }
        }
        return new SaveReport(issues);
    }

    private void OnWriterEvent(object? sender, ModuleWriterEventArgs e)
    {
        if (e.Event == ModuleWriterEvent.MDEndWriteMethodBodies) KeepBodies(e.Writer.Metadata);
        else if (e.Event == ModuleWriterEvent.MDEndCreateTables) KeepSignatures(e.Writer.Metadata);
    }

    private void KeepBodies(Metadata metadata)
    {
        var toBody = (Dictionary<MethodDef, DnMethodBody>)MethodToBody.GetValue(metadata)!;
        var chunks = metadata.MethodBodyChunks;
        var replaced = new List<DnMethodBody>();
        int count = _original.MethodCount;
        foreach (var type in _module.GetTypes())
        foreach (var method in type.Methods)
        {
            int rid = (int)method.Rid;
            // Added by an edit.
            if (rid == 0 || rid > count) continue;
            try
            {
                var row = _original.Method(rid);
                if (row.Rva == 0 || !row.IsIL) continue;
                toBody.TryGetValue(method, out var written);
                var stored = _original.ReadBody(row.Rva, out var error);
                if (stored != null && written != null && stored.SameBytes(written.Code, written.ExtraSections))
                {
                    Kept(method, rid, stored);
                    continue;
                }
                if (!Unchanged(method, rid))
                {
                    _editedBodies.Add(rid);
                    continue;
                }
                if (stored == null)
                {
                    _unreadable.Add(rid);
                    var what = written == null ? "written without a body" : $"written as decoded ({method.Body?.Instructions.Count ?? 0} instruction(s), {written.Code.Length + (written.ExtraSections?.Length ?? 0)} bytes)";
                    _issues.Add(new SaveIssue(SaveIssueReason.UnreadableBody, method.MDToken.Raw, Label(method), $"{error}; {what}"));
                    continue;
                }
                toBody[method] = chunks.Add(new DnMethodBody(stored.Code, stored.Sections, stored.LocalVarSigToken));
                if (written != null) replaced.Add(written);
                Kept(method, rid, stored);
            }
            catch (Exception ex) when (ex is BadImageFormatException or ArgumentException or InvalidOperationException or IndexOutOfRangeException)
            {
                // Left as dnlib wrote it; the read-back comparison reports it if it differs.
            }
        }

        // Unused dnlib encodings are removed only now: the chunk list deduplicates by content, so an earlier removal could be reused.
        var used = new HashSet<DnMethodBody>(toBody.Values, ReferenceEqualityComparer.Instance);
        foreach (var body in replaced.Distinct(ReferenceEqualityComparer.Instance).Cast<DnMethodBody>())
        {
            if (used.Contains(body)) continue;
            try { chunks.Remove(body); }
            // Old body locations are reused, so the orphan only costs space.
            catch (InvalidOperationException) { }
        }
    }

    private void Kept(MethodDef method, int rid, RawImage.Body stored)
    {
        _keptBodies.Add(rid);
        _restored.Add(method);
        if (_original.Problem(stored, rid) is { } problem)
            _issues.Add(new SaveIssue(SaveIssueReason.InvalidBody, method.MDToken.Raw, Label(method), problem));
    }

    /// <summary>Whether a method's current body is the one it was loaded with (same instructions, operands, handlers, locals).</summary>
    private bool Unchanged(MethodDef method, int rid)
    {
        var original = _pristine().ResolveMethod((uint)rid);
        if (original == null) return false;
        return BodyComparer.Same(method.Body, original.Body);
    }

    private void KeepSignatures(Metadata metadata)
    {
        var tables = metadata.TablesHeap;
        var originalBlob = _original.Heap(HeapIndex.Blob);
        Dictionary<uint, byte[]>? added = null;
        var referenced = ReferencedByEditedCode();

        foreach (var table in RawImage.SignatureTables)
        {
            int rows = Math.Min(_original.Metadata.GetTableRowCount(table), RowCount(tables, table));
            for (int rid = 1; rid <= rows; rid++)
            {
                try
                {
                    uint now = SignatureColumn(tables, table, (uint)rid);
                    var handle = _original.Signature(table, rid);
                    uint was = (uint)MetadataTokens.GetHeapOffset(handle);
                    if (now == was) continue;
                    var stored = _original.Blob(handle);
                    ReadOnlySpan<byte> written;
                    if (now < originalBlob.Length) written = BlobAt(originalBlob, (int)now);
                    else
                    {
                        added ??= metadata.BlobHeap.GetAllRawData().ToDictionary(p => p.Key, p => p.Value);
                        written = added.TryGetValue(now, out var raw) ? BlobAt(raw, 0) : default;
                    }
                    uint token = (uint)MetadataTokens.GetToken(MetadataTokens.EntityHandle(table, rid));
                    bool same = written.SequenceEqual(stored);
                    // Shared with edited code: left as dnlib wrote it, and reported if it differs.
                    if (!same && referenced.Contains(token)) continue;
                    var current = _module.ResolveToken(token);
                    if (!SignatureComparer.Same(current, _pristine().ResolveToken(token)))
                    {
                        _editedSignatures.Add(token);
                        continue;
                    }
                    SetSignatureColumn(tables, table, (uint)rid, was);
                    if (current != null) _restored.Add(current);
                    if (!same)
                        _issues.Add(new SaveIssue(SaveIssueReason.MalformedSignature, token, Label(current, token),
                            written.IsEmpty ? $"signature blob {Hex(stored)} does not decode (dnlib would write an empty blob)"
                            : $"signature blob {Hex(stored)} does not decode as written (dnlib would write {Hex(written)})"));
                }
                catch (Exception ex) when (ex is BadImageFormatException or ArgumentException or InvalidOperationException or IndexOutOfRangeException)
                {
                    // Left as dnlib wrote it; the read-back comparison reports it if it differs.
                }
            }
        }
    }

    /// <summary>Tokens of signature rows used by code that dnlib encodes: edited and added method bodies.</summary>
    private HashSet<uint> ReferencedByEditedCode()
    {
        var tokens = new HashSet<uint>();
        foreach (var type in _module.GetTypes())
        foreach (var method in type.Methods)
        {
            int rid = (int)method.Rid;
            if (rid != 0 && rid <= _original.MethodCount && !_editedBodies.Contains(rid)) continue;
            if (method.Body is not { } body) continue;
            if (body.LocalVarSigTok != 0) tokens.Add(body.LocalVarSigTok);
            foreach (var ins in body.Instructions)
            {
                if (ins.Operand is IMDTokenProvider { MDToken.Rid: not 0 } p) tokens.Add(p.MDToken.Raw);
                else if (ins.Operand is MethodSig { OriginalToken: not 0 } sig) tokens.Add(sig.OriginalToken);
            }
        }
        return tokens;
    }

    private static ReadOnlySpan<byte> BlobAt(ReadOnlySpan<byte> heap, int offset)
    {
        if (offset >= heap.Length) return default;
        byte b = heap[offset];
        int length, header;
        if ((b & 0x80) == 0) { length = b; header = 1; }
        else if ((b & 0xC0) == 0x80 && offset + 1 < heap.Length) { length = (b & 0x3F) << 8 | heap[offset + 1]; header = 2; }
        else if ((b & 0xE0) == 0xC0 && offset + 3 < heap.Length) { length = (b & 0x1F) << 24 | heap[offset + 1] << 16 | heap[offset + 2] << 8 | heap[offset + 3]; header = 4; }
        else return default;
        return offset + header + length > heap.Length ? default : heap.Slice(offset + header, length);
    }

    private static int RowCount(TablesHeap t, TableIndex table) => table switch
    {
        TableIndex.MethodDef => t.MethodTable.Rows,
        TableIndex.Field => t.FieldTable.Rows,
        TableIndex.MemberRef => t.MemberRefTable.Rows,
        TableIndex.StandAloneSig => t.StandAloneSigTable.Rows,
        TableIndex.TypeSpec => t.TypeSpecTable.Rows,
        TableIndex.MethodSpec => t.MethodSpecTable.Rows,
        TableIndex.Property => t.PropertyTable.Rows,
        _ => 0,
    };

    private static uint SignatureColumn(TablesHeap t, TableIndex table, uint rid) => table switch
    {
        TableIndex.MethodDef => t.MethodTable[rid].Signature,
        TableIndex.Field => t.FieldTable[rid].Signature,
        TableIndex.MemberRef => t.MemberRefTable[rid].Signature,
        TableIndex.StandAloneSig => t.StandAloneSigTable[rid].Signature,
        TableIndex.TypeSpec => t.TypeSpecTable[rid].Signature,
        TableIndex.MethodSpec => t.MethodSpecTable[rid].Instantiation,
        TableIndex.Property => t.PropertyTable[rid].Type,
        _ => throw new ArgumentOutOfRangeException(nameof(table)),
    };

    private static void SetSignatureColumn(TablesHeap t, TableIndex table, uint rid, uint blob)
    {
        switch (table)
        {
            case TableIndex.MethodDef: { var r = t.MethodTable[rid]; t.MethodTable[rid] = new RawMethodRow(r.RVA, r.ImplFlags, r.Flags, r.Name, blob, r.ParamList); break; }
            case TableIndex.Field: { var r = t.FieldTable[rid]; t.FieldTable[rid] = new RawFieldRow(r.Flags, r.Name, blob); break; }
            case TableIndex.MemberRef: { var r = t.MemberRefTable[rid]; t.MemberRefTable[rid] = new RawMemberRefRow(r.Class, r.Name, blob); break; }
            case TableIndex.StandAloneSig: t.StandAloneSigTable[rid] = new RawStandAloneSigRow(blob); break;
            case TableIndex.TypeSpec: t.TypeSpecTable[rid] = new RawTypeSpecRow(blob); break;
            case TableIndex.MethodSpec: { var r = t.MethodSpecTable[rid]; t.MethodSpecTable[rid] = new RawMethodSpecRow(r.Method, blob); break; }
            case TableIndex.Property: { var r = t.PropertyTable[rid]; t.PropertyTable[rid] = new RawPropertyRow(r.PropFlags, r.Name, blob); break; }
        }
    }

    /// <summary>Reads the written image back: every body and signature no edit touched must be the original one.</summary>
    private void Verify(byte[] image)
    {
        RawImage written;
        try
        {
            written = new RawImage(image);
        }
        catch (Exception ex) when (ex is BadImageFormatException or InvalidOperationException)
        {
            _issues.Add(new SaveIssue(SaveIssueReason.Reencoded, 0, "module", $"the written image cannot be read back: {ex.Message}"));
            return;
        }
        using (written)
        {
            int methods = Math.Min(_original.MethodCount, written.MethodCount);
            for (int rid = 1; rid <= methods; rid++)
            {
                var token = (uint)MetadataTokens.GetToken(MetadataTokens.MethodDefinitionHandle(rid));
                try
                {
                    var was = _original.Method(rid);
                    if (was.Rva == 0 || !was.IsIL || _editedBodies.Contains(rid) || _unreadable.Contains(rid)) continue;
                    var stored = _original.ReadBody(was.Rva, out _);
                    var now = written.Method(rid);
                    var back = now.Rva == 0 ? null : written.ReadBody(now.Rva, out _);
                    if (back != null && stored != null && stored.SameBytes(back)) continue;
                    _issues.Add(new SaveIssue(SaveIssueReason.Reencoded, token, Label(_module.ResolveToken(token), token),
                        stored == null ? "the original body cannot be read, and is written as dnlib encodes it"
                        : back == null ? $"the {stored.Length}-byte body was written without a body"
                        : $"the body reads back differently: {Difference([.. stored.Code, .. stored.Sections ?? []], [.. back.Code, .. back.Sections ?? []])}"));
                }
                catch (Exception ex) when (ex is BadImageFormatException or ArgumentException or InvalidOperationException or IndexOutOfRangeException)
                {
                    _issues.Add(new SaveIssue(SaveIssueReason.Reencoded, token, $"0x{token:X8}", $"the body could not be compared with the original: {ex.Message}"));
                }
            }

            foreach (var table in RawImage.SignatureTables)
            {
                int rows = Math.Min(_original.Metadata.GetTableRowCount(table), written.Metadata.GetTableRowCount(table));
                for (int rid = 1; rid <= rows; rid++)
                {
                    uint token = (uint)MetadataTokens.GetToken(MetadataTokens.EntityHandle(table, rid));
                    if (_editedSignatures.Contains(token)) continue;
                    try
                    {
                        var stored = _original.Blob(_original.Signature(table, rid));
                        var back = written.Blob(written.Signature(table, rid));
                        if (stored.AsSpan().SequenceEqual(back)) continue;
                        _issues.Add(new SaveIssue(SaveIssueReason.Reencoded, token, Label(_module.ResolveToken(token), token),
                            $"signature blob {Hex(stored)} was written as {Hex(back)}"));
                    }
                    catch (Exception ex) when (ex is BadImageFormatException or ArgumentException or InvalidOperationException or IndexOutOfRangeException)
                    {
                        _issues.Add(new SaveIssue(SaveIssueReason.Reencoded, token, $"0x{token:X8}", $"the signature could not be compared with the original: {ex.Message}"));
                    }
                }
            }

            // Bodies kept byte-for-byte refer to user strings and blobs by offset.
            foreach (var heap in new[] { HeapIndex.UserString, HeapIndex.Blob })
            {
                var before = _original.Heap(heap);
                var after = written.Heap(heap);
                if (after.Length < before.Length || !after[..before.Length].SequenceEqual(before))
                    _issues.Add(new SaveIssue(SaveIssueReason.Reencoded, 0, "module",
                        $"the {(heap == HeapIndex.UserString ? "#US" : "#Blob")} heap does not keep the original one as its prefix: literals and signatures may read differently"));
            }
        }

        foreach (var (message, source) in _logger.Errors)
        {
            if (source != null && _restored.Contains(source)) continue;
            _issues.Add(new SaveIssue(SaveIssueReason.WriterError, (source as IMDTokenProvider)?.MDToken.Raw ?? 0,
                source == null ? "module" : Label(source, (source as IMDTokenProvider)?.MDToken.Raw ?? 0), message));
        }
    }

    private static string Difference(byte[] a, byte[] b)
    {
        int i = 0;
        while (i < a.Length && i < b.Length && a[i] == b[i]) i++;
        return $"{a.Length} -> {b.Length} bytes, first difference at byte {i}";
    }

    private static string Hex(ReadOnlySpan<byte> bytes) =>
        bytes.Length == 0 ? "(empty)" : Convert.ToHexString(bytes.Length > 24 ? bytes[..24] : bytes) + (bytes.Length > 24 ? $"… ({bytes.Length} bytes)" : "");

    private static string Label(MethodDef method) => Label(method, method.MDToken.Raw);

    private static string Label(object? member, uint token)
    {
        string name;
        try
        {
            name = member switch
            {
                IMemberRef m => Format.MemberLabel(m),
                null => "",
                _ => member.ToString() ?? "",
            };
        }
        catch (Exception)
        {
            name = "";
        }
        return name.Length == 0 ? $"0x{token:X8}" : $"{name} [0x{token:X8}]";
    }

    /// <summary>Collects writer errors with the member being written; never throws, so the write continues.</summary>
    private sealed class CollectingLogger : ILogger
    {
        public List<(string Message, object? Source)> Errors { get; } = new();

        public void Log(object sender, LoggerEvent loggerEvent, string format, params object[] args)
        {
            if (loggerEvent != LoggerEvent.Error) return;
            string message;
            try { message = string.Format(System.Globalization.CultureInfo.InvariantCulture, format, args); }
            catch (FormatException) { message = format; }
            // The writer's error context appends the member and its token as the last two arguments.
            var source = args.Length >= 2 && args[^2] is IMDTokenProvider p && args[^1] is uint ? p : null;
            Errors.Add((message, source));
        }

        public bool IgnoresEvent(LoggerEvent loggerEvent) => loggerEvent != LoggerEvent.Error;
    }
}

/// <summary>Structural equality of two loads of a method body: instructions, operands by token or index, handlers, locals.</summary>
internal static class BodyComparer
{
    public static bool Same(CilBody? a, CilBody? b)
    {
        if (a == null || b == null) return a == b;
        if (a.InitLocals != b.InitLocals || a.MaxStack != b.MaxStack || a.LocalVarSigTok != b.LocalVarSigTok ||
            a.Instructions.Count != b.Instructions.Count || a.Variables.Count != b.Variables.Count ||
            a.ExceptionHandlers.Count != b.ExceptionHandlers.Count)
            return false;
        for (int i = 0; i < a.Variables.Count; i++)
            if (a.Variables[i].Type?.FullName != b.Variables[i].Type?.FullName) return false;

        var ia = Index(a);
        var ib = Index(b);
        int At(Dictionary<Instruction, int> index, Instruction? i) => i == null ? -1 : index.TryGetValue(i, out int k) ? k : -2;
        for (int i = 0; i < a.Instructions.Count; i++)
        {
            var x = a.Instructions[i];
            var y = b.Instructions[i];
            if (x.OpCode != y.OpCode) return false;
            bool same = (x.Operand, y.Operand) switch
            {
                (null, null) => true,
                (Instruction tx, Instruction ty) => At(ia, tx) == At(ib, ty),
                (IList<Instruction> tx, IList<Instruction> ty) => tx.Count == ty.Count && tx.Select(t => At(ia, t)).SequenceEqual(ty.Select(t => At(ib, t))),
                (Local lx, Local ly) => lx.Index == ly.Index,
                (Parameter px, Parameter py) => px.Index == py.Index,
                (string sx, string sy) => string.Equals(sx, sy, StringComparison.Ordinal),
                (IMDTokenProvider tx, IMDTokenProvider ty) => tx.MDToken.Rid != 0 && tx.MDToken.Raw == ty.MDToken.Raw,
                (MethodSig sx, MethodSig sy) => sx.OriginalToken != 0 && sx.OriginalToken == sy.OriginalToken,
                var (ox, oy) => ox != null && oy != null && ox.GetType() == oy.GetType() && ox.Equals(oy),
            };
            if (!same) return false;
        }
        for (int i = 0; i < a.ExceptionHandlers.Count; i++)
        {
            var x = a.ExceptionHandlers[i];
            var y = b.ExceptionHandlers[i];
            if (x.HandlerType != y.HandlerType || At(ia, x.TryStart) != At(ib, y.TryStart) || At(ia, x.TryEnd) != At(ib, y.TryEnd) ||
                At(ia, x.HandlerStart) != At(ib, y.HandlerStart) || At(ia, x.HandlerEnd) != At(ib, y.HandlerEnd) ||
                At(ia, x.FilterStart) != At(ib, y.FilterStart) || (x.CatchType?.MDToken.Raw ?? 0) != (y.CatchType?.MDToken.Raw ?? 0) ||
                x.CatchType is { MDToken.Rid: 0 })
                return false;
        }
        return true;
    }

    private static Dictionary<Instruction, int> Index(CilBody body)
    {
        var index = new Dictionary<Instruction, int>(body.Instructions.Count);
        for (int i = 0; i < body.Instructions.Count; i++) index[body.Instructions[i]] = i;
        return index;
    }
}

/// <summary>Whether two loads of a signature row encode the same signature (types by token).</summary>
internal static class SignatureComparer
{
    public static bool Same(object? a, object? b)
    {
        var (x, unmatchedX) = Encode(a);
        var (y, unmatchedY) = Encode(b);
        // A signature that references something without a token (added by an edit) never matches an original.
        return !unmatchedX && !unmatchedY && x.AsSpan().SequenceEqual(y);
    }

    internal static (byte[] Bytes, bool Unmatched) Encode(object? row)
    {
        var helper = new Tokens();
        try
        {
            byte[] bytes = row switch
            {
                MethodDef m => SignatureWriter.Write(helper, m.Signature),
                FieldDef f => SignatureWriter.Write(helper, f.Signature),
                MemberRef r => SignatureWriter.Write(helper, r.Signature),
                StandAloneSig s => SignatureWriter.Write(helper, s.Signature),
                TypeSpec t => SignatureWriter.Write(helper, t.TypeSig),
                MethodSpec s => SignatureWriter.Write(helper, s.Instantiation),
                PropertyDef p => SignatureWriter.Write(helper, p.Type),
                _ => [],
            };
            return (bytes, helper.Unmatched);
        }
        catch (Exception ex)
        {
            return (System.Text.Encoding.UTF8.GetBytes("error: " + ex.Message), helper.Unmatched);
        }
    }

    private sealed class Tokens : ISignatureWriterHelper
    {
        public bool Unmatched { get; private set; }

        public uint ToEncodedToken(ITypeDefOrRef typeDefOrRef)
        {
            if (typeDefOrRef == null || typeDefOrRef.MDToken.Rid == 0)
            {
                Unmatched = true;
                return 0;
            }
            return CodedToken.TypeDefOrRef.Encode(typeDefOrRef.MDToken);
        }

        public void Error(string message) { }
    }
}
