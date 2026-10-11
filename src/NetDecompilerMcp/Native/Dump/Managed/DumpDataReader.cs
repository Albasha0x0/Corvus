using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Microsoft.Diagnostics.Runtime;
using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Native.Dump.Managed;

/// <summary>
/// ClrMD's view of a minidump through our parser. Bytes the dump does not hold come from the module image only in its
/// headers and read-only sections, relocated to the module's base; writable data never falls back, because initial
/// values would mislead the runtime's data access layer.
/// </summary>
public sealed class DumpDataReader(MinidumpFile dump, Func<DumpModule, PeFile?> image) : IDataReader, IDisposable
{
    private readonly Dictionary<DumpModule, (PeFile? Image, uint[] Pointers)> _images = [];

    public string DisplayName => dump.Path;
    public bool IsThreadSafe => false;
    public OSPlatform TargetPlatform => OSPlatform.Windows;
    public Architecture Architecture => dump.Arch switch
    {
        NativeArch.X86 => Architecture.X86,
        NativeArch.Arm64 => Architecture.Arm64,
        NativeArch.Arm => Architecture.Arm,
        _ => Architecture.X64,
    };
    public int ProcessId => (int)(dump.MiscInfo?.ProcessId ?? 0);
    public int PointerSize => dump.Is64Bit ? 8 : 4;

    /// <summary>Reads served from module images rather than the dump (for tests and notes).</summary>
    public long ImageReads { get; private set; }

    public IEnumerable<ModuleInfo> EnumerateModules()
    {
        foreach (var m in dump.Modules)
        {
            var version = System.Version.TryParse(m.FileVersion, out var v) ? v : null;
            yield return ModuleInfo.TryCreate(this, m.Base, m.Path, (int)m.Size, (int)m.TimeDateStamp, version)
                         ?? new HeaderlessModule(m, version);
        }
    }

    public bool GetThreadContext(uint threadID, uint contextFlags, Span<byte> context)
    {
        var thread = dump.ThreadById(threadID);
        if (thread == null) return false;
        var bytes = dump.ContextBytes(thread.Context);
        if (bytes.Length == 0) return false;
        context.Clear();
        bytes.AsSpan(0, Math.Min(bytes.Length, context.Length)).CopyTo(context);
        return true;
    }

    public void FlushCachedData() { }

    public int Read(ulong address, Span<byte> buffer)
    {
        int n = dump.ReadMemory(address, buffer);
        while (n < buffer.Length)
        {
            ulong at = address + (ulong)n;
            // the image fills only the gap up to the next captured range
            int gap = (int)Math.Min((ulong)(buffer.Length - n), NextCaptured(at) - at);
            int k = ReadImage(at, buffer.Slice(n, gap));
            if (k == 0) break;
            ImageReads++;
            n += k;
            if (n < buffer.Length) n += dump.ReadMemory(address + (ulong)n, buffer[n..]);
        }
        return n;
    }

    private ulong NextCaptured(ulong address)
    {
        var ranges = dump.MemoryRanges;
        int lo = 0, hi = ranges.Count - 1, found = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (ranges[mid].Start > address) { found = mid; hi = mid - 1; }
            else lo = mid + 1;
        }
        return found >= 0 ? ranges[found].Start : ulong.MaxValue;
    }

    /// <summary>Bytes of a read-only part of a module image at <paramref name="address"/>, up to the end of that part.</summary>
    internal int ReadImage(ulong address, Span<byte> buffer)
    {
        var module = dump.ModuleAt(address);
        if (module == null) return 0;
        var (pe, pointers) = Image(module);
        if (pe == null) return 0;
        uint rva = (uint)(address - module.Base);
        uint end;
        var section = pe.Sections.FirstOrDefault(s => s.Contains(rva));
        if (section != null)
        {
            if ((section.Access & SectionAccess.Write) != 0) return 0;
            end = section.Rva + section.MappedSize;
        }
        else if (rva < pe.Optional.SizeOfHeaders) end = pe.Optional.SizeOfHeaders;
        else return 0;
        int want = (int)Math.Min((ulong)buffer.Length, end - rva);
        int n = pe.Read(rva, buffer[..want]);
        Relocate(module, pe, pointers, rva, buffer[..n]);
        return n;
    }

    private (PeFile? Image, uint[] Pointers) Image(DumpModule module)
    {
        lock (_images)
        {
            if (_images.TryGetValue(module, out var known)) return known;
            var pe = image(module);
            uint[] pointers = [];
            if (pe != null && pe.ImageBase != module.Base)
            {
                pointers = [.. pe.RelocationRvas];
                Array.Sort(pointers);
            }
            return _images[module] = (pe, pointers);
        }
    }

    /// <summary>Applies the base relocations inside [rva, rva + bytes.Length) for a module loaded away from its preferred base.</summary>
    private static void Relocate(DumpModule module, PeFile pe, uint[] pointers, uint rva, Span<byte> bytes)
    {
        if (pointers.Length == 0) return;
        ulong delta = module.Base - pe.ImageBase;
        int width = pe.Is64Bit ? 8 : 4;
        int i = Array.BinarySearch(pointers, rva);
        if (i < 0) i = ~i;
        for (; i < pointers.Length && pointers[i] < rva + (uint)bytes.Length; i++)
        {
            long at = (long)pointers[i] - rva;
            if (at < 0 || at + width > bytes.Length) continue; // a pointer split across reads keeps its file value
            if (width == 8) BinaryPrimitives.WriteUInt64LittleEndian(bytes[(int)at..], BinaryPrimitives.ReadUInt64LittleEndian(bytes[(int)at..]) + delta);
            else BinaryPrimitives.WriteUInt32LittleEndian(bytes[(int)at..], BinaryPrimitives.ReadUInt32LittleEndian(bytes[(int)at..]) + (uint)delta);
        }
    }

    public bool Read<T>(ulong address, out T value) where T : unmanaged
    {
        Span<byte> b = stackalloc byte[Unsafe.SizeOf<T>()];
        if (Read(address, b) == b.Length)
        {
            value = MemoryMarshal.Read<T>(b);
            return true;
        }
        value = default;
        return false;
    }

    public T Read<T>(ulong address) where T : unmanaged => Read(address, out T value) ? value : default;

    public bool ReadPointer(ulong address, out ulong value)
    {
        Span<byte> b = stackalloc byte[8];
        int size = PointerSize;
        if (Read(address, b[..size]) != size)
        {
            value = 0;
            return false;
        }
        value = size == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(b) : BinaryPrimitives.ReadUInt32LittleEndian(b);
        return true;
    }

    public ulong ReadPointer(ulong address) => ReadPointer(address, out var value) ? value : 0;

    public void Dispose() => dump.Dispose();

    /// <summary>A module whose headers are neither in the dump nor in a local image: the dump's own module record.</summary>
    private sealed class HeaderlessModule(DumpModule module, Version? version) : ModuleInfo(module.Base, module.Path)
    {
        public override ModuleKind Kind => ModuleKind.PortableExecutable;
        public override long ImageSize => module.Size;
        public override int IndexFileSize => (int)module.Size;
        public override int IndexTimeStamp => (int)module.TimeDateStamp;
        public override Version Version => version ?? new Version();
    }
}
