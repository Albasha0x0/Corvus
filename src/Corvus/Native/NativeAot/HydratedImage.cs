using System.Buffers.Binary;
using System.Security.Cryptography;
using Corvus.Native.ReadyToRun;

namespace Corvus.Native.NativeAot;

/// <summary>The image after NativeAOT rehydration (section 207) with its pointer slots; empty overlay when not dehydrated. Derived bytes have no file offset; <see cref="Sha256"/> identifies them.</summary>
public sealed class HydratedImage
{
    /// <summary>Largest destination expanded.</summary>
    public const int MaxHydratedBytes = 256 << 20;

    private const int Copy = 0, ZeroFill = 1, RelPtr32Reloc = 2, PtrReloc = 3, InlineRelPtr32Reloc = 4, InlinePtrReloc = 5;
    private const int MaxShortPayload = 28;

    private readonly byte[] overlay;
    private readonly uint[] pointerSlots;

    private HydratedImage(INativeImage image, uint destinationRva, byte[] overlay, uint[] pointerSlots, NativeAotStage stage)
    {
        Image = image;
        DestinationRva = destinationRva;
        this.overlay = overlay;
        this.pointerSlots = pointerSlots;
        Stage = stage;
        View = new ImageView(image, Read);
        Sha256 = overlay.Length == 0 ? null : Convert.ToHexStringLower(SHA256.HashData(overlay));
    }

    public INativeImage Image { get; }
    public uint DestinationRva { get; }
    public int HydratedLength => overlay.Length;
    /// <summary>SHA-256 of the rehydrated bytes, null when nothing was rehydrated.</summary>
    public string? Sha256 { get; }
    /// <summary>Bounds-checked reads through the overlay.</summary>
    public ImageView View { get; }
    public NativeAotStage Stage { get; }
    /// <summary>RVAs of pointer-sized slots holding absolute addresses, sorted.</summary>
    public IReadOnlyList<uint> PointerSlots => pointerSlots;
    public int PointerSize => Image.Is64Bit ? 8 : 4;

    public bool IsHydrated(uint rva) => rva >= DestinationRva && rva - DestinationRva < (uint)overlay.Length;

    public bool IsPointerSlot(uint rva) => Array.BinarySearch(pointerSlots, rva) >= 0;

    /// <summary>Length of the section's readable bytes: its file bytes, extended by the rehydrated range that overlaps it.</summary>
    public long ReadableLength(NativeSection section)
    {
        long length = Image.FileBytesLength(section);
        long end = Math.Min((long)DestinationRva + overlay.Length, (long)section.Rva + section.MappedSize);
        return overlay.Length == 0 ? length : Math.Max(length, end - section.Rva);
    }

    /// <summary>Mapped bytes with the rehydrated range replaced; same contract as <see cref="INativeImage.Read"/>.</summary>
    public int Read(uint rva, Span<byte> destination)
    {
        int n = Image.Read(rva, destination);
        if (overlay.Length == 0) return n;
        long start = Math.Max(rva, DestinationRva), end = Math.Min((long)rva + destination.Length, (long)DestinationRva + overlay.Length);
        if (start >= end) return n;
        overlay.AsSpan((int)(start - DestinationRva), (int)(end - start)).CopyTo(destination[(int)(start - rva)..]);
        // The destination is usually uninitialized data; the overlay makes it readable even past the raw bytes.
        return (int)Math.Max(n, end - rva);
    }

    /// <summary>A pointer-sized value at <paramref name="rva"/> as an RVA; null when it is zero or outside the image.</summary>
    public uint? PointerAt(uint rva)
    {
        Span<byte> b = stackalloc byte[8];
        var slot = b[..PointerSize];
        if (Read(rva, slot) != slot.Length) return null;
        ulong va = PointerSize == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(slot) : BinaryPrimitives.ReadUInt32LittleEndian(slot);
        // ELF images load at 0.
        return va != 0 && va >= Image.ImageBase && va - Image.ImageBase < Image.SizeOfImage ? (uint)(va - Image.ImageBase) : null;
    }

    /// <summary>The target of the 32-bit relative pointer at <paramref name="rva"/>; null when it leaves the image.</summary>
    public uint? RelativeAt(uint rva)
    {
        Span<byte> b = stackalloc byte[4];
        if (Read(rva, b) != 4) return null;
        long target = rva + (long)BinaryPrimitives.ReadInt32LittleEndian(b);
        return target >= 0 && target < Image.SizeOfImage ? (uint)target : null;
    }

    /// <summary>Rehydrates the module of <paramref name="header"/>; never throws on malformed data (the stage says what failed).</summary>
    public static HydratedImage Create(INativeImage image, NativeAotHeader header, CancellationToken ct = default)
    {
        var relocations = image.RelocationRvas.ToArray();
        var section = header.Section(SectionId.DehydratedData);
        if (section is not { Length: >= 4 })
            return new(image, 0, [], relocations, new("rehydration", NativeAotStage.Absent, "not dehydrated: MethodTables are in the file, pointers from base relocations"));
        var r = new Rehydrator(image, section, header.Format, ct);
        string? error = null;
        try { r.Run(); }
        catch (NativeAotFormatException ex) { error = ex.Message; }
        var slots = relocations.Concat(r.Pointers).Distinct().Order().ToArray();
        var hydrated = r.Output.AsSpan(0, r.Written).ToArray();
        string detail = $"{hydrated.Length} bytes at RVA 0x{r.Destination:X} from {r.CommandBytes} command bytes ({r.Format}), {r.Pointers.Count} pointers written";
        var stage = error == null
            ? new NativeAotStage("rehydration", NativeAotStage.Complete, detail)
            : new NativeAotStage("rehydration", NativeAotStage.Partial, $"{detail}; stopped: {error}");
        return new(image, r.Destination, hydrated, slots, stage);
    }

    /// <summary>Decoder of the DehydratedData command stream.</summary>
    private sealed class Rehydrator(INativeImage image, NativeAotSection section, NativeAotFormat format, CancellationToken ct)
    {
        public uint Destination;
        public byte[] Output = [];
        public int Written;
        public int CommandBytes;
        public RehydrationFormat Format;
        public readonly List<uint> Pointers = [];

        private byte[] stream = [];
        private uint streamRva;
        private uint fixupsRva;

        private int I32(uint rva)
        {
            Span<byte> b = stackalloc byte[4];
            if (image.Read(rva, b) != 4) throw new NativeAotFormatException($"dehydrated data reads past the image at RVA 0x{rva:X}");
            return BinaryPrimitives.ReadInt32LittleEndian(b);
        }

        private static uint Target(uint at, int delta) =>
            at + (long)delta is >= 0 and <= uint.MaxValue ? (uint)(at + (long)delta) : throw new NativeAotFormatException($"relative pointer at RVA 0x{at:X} leaves the address space");

        public void Run()
        {
            uint start = section.StartRva;
            Destination = Target(start, I32(start));
            Format = format.Rehydration;
            int length = I32(start + 4);
            if (!format.Exact && format.RtrMajor >= 16)
                Format = length >= 8 && length <= section.Length ? RehydrationFormat.LengthPrefixed : RehydrationFormat.EndBounded;
            uint end;
            if (Format == RehydrationFormat.LengthPrefixed)
            {
                if (length < 8 || length > section.Length) throw new NativeAotFormatException($"dehydrated data length {length} does not fit its {section.Length}-byte section");
                streamRva = start + 8;
                end = start + (uint)length;
            }
            else
            {
                streamRva = start + 4;
                end = section.EndRva;
            }
            fixupsRva = end;
            stream = new byte[end - streamRva];
            if (image.Read(streamRva, stream) != stream.Length) throw new NativeAotFormatException("the dehydrated command stream is not mapped");
            CommandBytes = stream.Length;

            var target = image.SectionAt(Destination) ?? throw new NativeAotFormatException($"rehydration destination RVA 0x{Destination:X} is outside every section");
            long capacity = Math.Min((long)target.Rva + target.MappedSize - Destination, MaxHydratedBytes);
            Output = new byte[capacity];
            Decode();
        }

        private void Need(long bytes)
        {
            if (Written + bytes > Output.Length) throw new NativeAotFormatException($"rehydrated data overflows its destination section after {Written} bytes");
        }

        private void WritePointer(uint targetRva)
        {
            int size = image.Is64Bit ? 8 : 4;
            Need(size);
            ulong va = image.ImageBase + targetRva;
            if (size == 8) BinaryPrimitives.WriteUInt64LittleEndian(Output.AsSpan(Written), va);
            else BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(Written), (uint)va);
            Pointers.Add(Destination + (uint)Written);
            Written += size;
        }

        private void WriteRelative(uint targetRva)
        {
            Need(4);
            uint at = Destination + (uint)Written;
            BinaryPrimitives.WriteInt32LittleEndian(Output.AsSpan(Written), (int)(targetRva - at));
            Written += 4;
        }

        private uint Fixup(int index)
        {
            uint at = fixupsRva + 4 * (uint)index;
            return Target(at, I32(at));
        }

        private void Decode()
        {
            int p = 0;
            while (p < stream.Length)
            {
                if ((p & 0xFFFF) == 0) ct.ThrowIfCancellationRequested();
                byte b = stream[p++];
                int command = b & 7, payload = b >> 3;
                int extra = payload - MaxShortPayload;
                if (extra > 0)
                {
                    if (p + extra > stream.Length) throw new NativeAotFormatException("truncated dehydrated command");
                    payload = 0;
                    for (int i = 0; i < extra; i++) payload |= stream[p++] << (8 * i);
                    payload += MaxShortPayload;
                }
                switch (command)
                {
                    case Copy:
                        if (p + payload > stream.Length) throw new NativeAotFormatException($"copy of {payload} bytes runs past the command stream");
                        Need(payload);
                        stream.AsSpan(p, payload).CopyTo(Output.AsSpan(Written));
                        Written += payload;
                        p += payload;
                        break;
                    case ZeroFill:
                        Need(payload);
                        Written += payload; // the buffer is zeroed
                        break;
                    case RelPtr32Reloc:
                        WriteRelative(Fixup(payload));
                        break;
                    case PtrReloc:
                        WritePointer(Fixup(payload));
                        break;
                    case InlineRelPtr32Reloc or InlinePtrReloc:
                        for (int i = 0; i < payload; i++)
                        {
                            if (p + 4 > stream.Length) throw new NativeAotFormatException("inline relocation runs past the command stream");
                            uint target = Target(streamRva + (uint)p, BinaryPrimitives.ReadInt32LittleEndian(stream.AsSpan(p)));
                            p += 4;
                            if (command == InlinePtrReloc) WritePointer(target);
                            else WriteRelative(target);
                        }
                        break;
                    default:
                        throw new NativeAotFormatException($"unknown dehydrated command {command} at RVA 0x{streamRva + p - 1:X}");
                }
            }
        }
    }
}
