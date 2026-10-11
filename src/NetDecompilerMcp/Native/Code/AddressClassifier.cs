using Iced.Intel;
using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Native.Code;

/// <summary>What an address is, as far as the code index knows.</summary>
public enum AddressStatus
{
    /// <summary>An instruction start inside a known function.</summary>
    Decoded,
    /// <summary>Inside a known function's instruction, not at its start: decoding here desynchronizes.</summary>
    MidInstruction,
    /// <summary>A known data item (string, IAT slot, switch table, relocated pointer, PE directory, data section).</summary>
    Data,
    /// <summary>Executable bytes no known function owns: decoded linearly, may be code or data.</summary>
    NotInFunction,
    /// <summary>Not backed by the file: zero fill past a section's raw data (bss), or in no section.</summary>
    Unmapped,
    OutsideImage,
    /// <summary>The bytes do not decode.</summary>
    Invalid,
}

/// <summary>A data item covering an address; End is exclusive.</summary>
/// <param name="Kind">string, iat_slot, jump_table, index_table, pointer, pe_directory, headers or section.</param>
public sealed record DataItem(string Kind, uint Start, uint End, string Text);

/// <summary>
/// The classification of one address. <see cref="InstructionStart"/> is the instruction at the address (Decoded,
/// NotInFunction, Invalid) or the one covering it (MidInstruction).
/// </summary>
public sealed record AddressClass(uint Rva, AddressStatus Status, NativeFunction? Function, uint? Block, uint? InstructionStart, int InstructionLength,
    bool Overlapping, DataItem? Item, NativeSection? Section, string? Note)
{
    /// <summary>The wire spelling: decoded, mid_instruction, data, not_in_function, unmapped, outside_image, invalid.</summary>
    public string StatusName => Name(Status);

    public static string Name(AddressStatus status) => status switch
    {
        AddressStatus.Decoded => "decoded",
        AddressStatus.MidInstruction => "mid_instruction",
        AddressStatus.Data => "data",
        AddressStatus.NotInFunction => "not_in_function",
        AddressStatus.Unmapped => "unmapped",
        AddressStatus.OutsideImage => "outside_image",
        _ => "invalid",
    };
}

/// <summary>
/// Classifies addresses of an x86 / x64 / ARM64 image against its code index: instruction boundaries inside known functions
/// (blocks decoded again, cached per instance), data items, bss and unowned code. Not thread-safe; one per request.
/// </summary>
public sealed class AddressClassifier
{
    // Switch tables are found through their JumpTable references within this distance before the address.
    private const uint MaxTableSpan = 0x10000;

    private readonly NativeCodeIndex _index;
    private readonly INativeImage _image;
    private readonly int _pointerSize;
    private readonly uint[] _slots;
    private readonly NativeImport[] _slotImports;
    private readonly uint[] _relocations;
    private readonly uint _headersEnd;
    private readonly Dictionary<uint, FunctionGraph> _graphs = [];
    private readonly Dictionary<(uint, uint), List<(uint Rva, int Length)>> _blockStarts = [];

    public AddressClassifier(NativeCodeIndex index)
    {
        if (index.Support != CodeSupport.Full) throw new NotSupportedException(index.SupportNote ?? "instructions are not decoded for this architecture");
        _index = index;
        _image = index.Image;
        _pointerSize = _image.Is64Bit ? 8 : 4;
        var imports = _image.Imports.OrderBy(i => i.SlotRva).ToArray();
        _slots = imports.Select(i => i.SlotRva).ToArray();
        _slotImports = imports;
        _relocations = _image.RelocationRvas as uint[] ?? _image.RelocationRvas.ToArray();
        _headersEnd = _image.Sections.Count > 0 ? _image.Sections.Min(s => s.Rva) : 0;
    }

    public NativeCodeIndex Index => _index;

    /// <summary>The control-flow graph of <paramref name="f"/>, decoded once per classifier.</summary>
    public FunctionGraph Graph(NativeFunction f, CancellationToken ct = default)
    {
        if (!_graphs.TryGetValue(f.Start, out var g)) _graphs[f.Start] = g = _index.GetGraph(f, ct);
        return g;
    }

    public AddressClass Classify(uint rva, CancellationToken ct = default)
    {
        if (rva >= _image.SizeOfImage) return new(rva, AddressStatus.OutsideImage, null, null, null, 0, false, null, null, $"past the image end (SizeOfImage 0x{_image.SizeOfImage:X})");
        var section = _image.SectionAt(rva);
        if (section != null && _image.FileBackedLength(rva, 1) == 0)
            return new(rva, AddressStatus.Unmapped, null, null, null, 0, false, null, section, $"uninitialized data (bss) of {section.Name}: zero-filled at load");
        if (section == null && rva >= _headersEnd)
            return new(rva, AddressStatus.Unmapped, null, null, null, 0, false, null, null, "in no section");

        if (section is { IsExecutable: true } && _index.FunctionAt(rva) is { } f && InFunctionCode(f, rva, section, ct) is { } inCode) return inCode;
        if (DataItemAt(rva, section, ct) is { } item)
            return new(rva, AddressStatus.Data, null, null, null, 0, false, item, section, null);
        if (section is { IsExecutable: true })
        {
            int length = DecodeLength(rva);
            return length > 0
                ? new(rva, AddressStatus.NotInFunction, null, null, rva, length, false, null, section, "no known function contains it: unowned code or data")
                : new(rva, AddressStatus.Invalid, null, null, rva, 0, false, null, section, "the bytes do not decode");
        }
        return new(rva, AddressStatus.Data, null, null, null, 0, false, new DataItem("section", section!.Rva, section.Rva + section.MappedSize, section.Name), section, null);
    }

    /// <summary>Decoded or MidInstruction inside the blocks of <paramref name="f"/>; null when no block covers the address.</summary>
    private AddressClass? InFunctionCode(NativeFunction f, uint rva, NativeSection section, CancellationToken ct)
    {
        var graph = Graph(f, ct);
        (uint Block, uint Start, int Length)? exact = null, covering = null;
        bool mid = false;
        foreach (var b in graph.Blocks)
        {
            if (rva < b.Start || rva >= b.End) continue;
            foreach (var (start, length) in Starts(b))
            {
                if (start == rva) exact ??= (b.Start, start, length);
                else if (start < rva && rva < start + (uint)length) { covering ??= (b.Start, start, length); mid = true; }
            }
        }
        if (exact is { } e)
        {
            var status = e.Length > 0 ? AddressStatus.Decoded : AddressStatus.Invalid;
            return new(rva, status, f, e.Block, rva, e.Length, mid, null, section, mid ? "overlapping code: another decoding covers this address" : null);
        }
        if (covering is { } c)
            return new(rva, AddressStatus.MidInstruction, f, c.Block, c.Start, c.Length, false, null, section,
                $"decoding at the requested address desynchronizes; the instruction at 0x{_image.ImageBase + c.Start:X} covers it");
        return null;
    }

    /// <summary>Instruction starts and lengths of a block (length 0 for bytes that do not decode).</summary>
    private List<(uint Rva, int Length)> Starts(BasicBlock b)
    {
        if (_blockStarts.TryGetValue((b.Start, b.End), out var cached)) return cached;
        if (_image.Arch == NativeArch.Arm64)
        {
            // fixed 4-byte instructions
            var words = new List<(uint, int)>();
            for (uint a = b.Start; a < b.End; a += 4)
            {
                int length = DecodeLength(a);
                words.Add((a, length));
                if (length == 0) break;
            }
            return _blockStarts[(b.Start, b.End)] = words;
        }
        var bytes = new byte[Math.Min(b.End - b.Start, 1u << 20) + 15];
        int n = _image.Read(b.Start, bytes);
        var decoder = Decoder.Create(_image.Is64Bit ? 64 : 32, new ByteArrayCodeReader(bytes, 0, n), _image.ImageBase + b.Start, DecoderOptions.None);
        var list = new List<(uint, int)>(Math.Max(1, b.InstructionCount));
        ulong end = _image.ImageBase + b.End;
        while (decoder.IP < end && decoder.IP < _image.ImageBase + b.Start + (ulong)n)
        {
            uint at = (uint)(decoder.IP - _image.ImageBase);
            decoder.Decode(out var insn);
            if (insn.IsInvalid) { list.Add((at, 0)); break; }
            list.Add((at, insn.Length));
        }
        _blockStarts[(b.Start, b.End)] = list;
        return list;
    }

    private int DecodeLength(uint rva)
    {
        if (_image.Arch == NativeArch.Arm64) return _index.Decode(rva) is { Flow: not FlowKind.Invalid } ? 4 : 0;
        var bytes = new byte[15];
        int n = _image.Read(rva, bytes);
        if (n == 0) return 0;
        var decoder = Decoder.Create(_image.Is64Bit ? 64 : 32, new ByteArrayCodeReader(bytes, 0, n), _image.ImageBase + rva, DecoderOptions.None);
        decoder.Decode(out var insn);
        return insn.IsInvalid ? 0 : insn.Length;
    }

    /// <summary>The data item covering <paramref name="rva"/>: IAT slot, string, switch table, relocated pointer, PE directory or headers.</summary>
    public DataItem? DataItemAt(uint rva, NativeSection? section = null, CancellationToken ct = default)
    {
        section ??= _image.SectionAt(rva);
        if (section == null && rva < _headersEnd) return new DataItem("headers", 0, _headersEnd, "image headers");
        if (Floor(_slots, rva) is { } s && rva < _slots[s] + (uint)_pointerSize)
            return new DataItem("iat_slot", _slots[s], _slots[s] + (uint)_pointerSize, NativeCodeIndex.ImportName(_slotImports[s]));
        if (StringCovering(rva) is { } str)
        {
            uint bytes = (uint)(str.Encoding == StringEncoding.Utf16 ? (str.Length + 1) * 2 : str.Length + 1);
            return new DataItem("string", str.Rva, str.Rva + bytes, _index.CommentFor(str.Rva) ?? "");
        }
        if (TableCovering(rva, ct) is { } table) return table;
        if (Floor(_relocations, rva) is { } r && rva < _relocations[r] + (uint)_pointerSize && !InFunctionCode(_relocations[r]))
        {
            uint at = _relocations[r];
            string text = TryPointer(at, out uint target)
                ? $"pointer to {_index.NameAt(target) ?? $"0x{_image.ImageBase + target:X}"}" + (_index.StringAt(target) != null ? " " + _index.CommentFor(target) : "")
                : "relocated pointer";
            return new DataItem("pointer", at, at + (uint)_pointerSize, text);
        }
        if (_image is PeFile pe)
            foreach (var d in pe.DataDirectories)
                if (d.Rva != 0 && d.Size != 0 && d.Index != PeDirectory.Security && rva >= d.Rva && rva - d.Rva < d.Size)
                    return new DataItem("pe_directory", d.Rva, d.Rva + d.Size, DirectoryText(d));
        return null;
    }

    private bool InFunctionCode(uint rva) => _index.FunctionAt(rva) != null;

    private static string DirectoryText(PeDataDirectory d) => d.Index switch
    {
        PeDirectory.Exception => "exception directory (.pdata unwind entries)",
        PeDirectory.Iat => "import address table",
        _ => $"{d.Name.ToLowerInvariant().Replace('_', ' ')} directory",
    };

    private bool TryPointer(uint at, out uint target)
    {
        target = 0;
        Span<byte> b = stackalloc byte[8];
        b.Clear();
        if (_image.Read(at, b[.._pointerSize]) != _pointerSize) return false;
        ulong va = BitConverter.ToUInt64(b);
        if (va < _image.ImageBase || va - _image.ImageBase >= _image.SizeOfImage) return false;
        target = (uint)(va - _image.ImageBase);
        return true;
    }

    private StringLiteral? StringCovering(uint rva)
    {
        var strings = _index.Strings;
        int lo = 0, hi = strings.Count - 1, best = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (strings[mid].Rva <= rva) { best = mid; lo = mid + 1; } else hi = mid - 1;
        }
        // strings do not nest, but a short one can sit inside a longer one's span: check a few back
        for (int i = best; i >= 0 && i > best - 4; i--)
        {
            var s = strings[i];
            uint bytes = (uint)(s.Encoding == StringEncoding.Utf16 ? (s.Length + 1) * 2 : s.Length + 1);
            if (rva < s.Rva + bytes) return s;
        }
        return null;
    }

    private DataItem? TableCovering(uint rva, CancellationToken ct)
    {
        uint from = rva > MaxTableSpan ? rva - MaxTableSpan : 0;
        foreach (var x in _index.RefsToRange(from, rva + 1).Where(x => x.Kind == XrefKind.JumpTable).OrderByDescending(x => x.To))
        {
            if (_index.FunctionAt(x.From) is not { } f) continue;
            foreach (var sw in Graph(f, ct).Switches)
            {
                if (sw.JumpRva != x.From) continue;
                uint tableEnd = sw.TableRva + (uint)(sw.EntryCount * sw.EntrySize);
                if (rva >= sw.TableRva && rva < tableEnd)
                    return new DataItem("jump_table", sw.TableRva, tableEnd,
                        $"switch table of {f.Name} (jump at 0x{_image.ImageBase + sw.JumpRva:X}): {sw.EntryCount} entries of {sw.EntrySize} bytes");
                if (sw.IndexTableRva is { } it && rva >= it && rva < it + (uint)sw.IndexEntryCount)
                    return new DataItem("index_table", it, it + (uint)sw.IndexEntryCount,
                        $"switch index table of {f.Name} (jump at 0x{_image.ImageBase + sw.JumpRva:X}): {sw.IndexEntryCount} byte entries");
            }
        }
        return null;
    }

    /// <summary>Index of the last element &lt;= <paramref name="value"/> in a sorted array, or null.</summary>
    private static int? Floor(uint[] sorted, uint value)
    {
        int i = Array.BinarySearch(sorted, value);
        if (i < 0) i = ~i - 1;
        return i >= 0 ? i : null;
    }
}
