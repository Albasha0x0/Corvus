using System.Buffers.Binary;
using System.Text;
using Corvus.Native;

namespace Corvus.Services;

/// <summary>
/// Finds the Il2CppCodeRegistration of a game binary from its data and relocations alone, without decoding code: the
/// module name "mscorlib.dll", the Il2CppCodeGenModule whose first field points at it, the codeGenModules array of
/// module pointers holding that module, and the pointer to the array's start, which is the registration's last field
/// (preceded by the module count). Used when the library's own search fails (Unity 6 armeabi-v7a builds).
/// </summary>
public static class Il2CppRegistrationSearch
{
    private const int MaxModules = 4096;

    /// <summary>A code registration candidate: the address of its codeGenModules field, the array it points at and the module count before it.</summary>
    public sealed record Candidate(ulong FieldVa, ulong ArrayVa, uint Modules);

    /// <summary>Candidates in address order; the caller places the struct start by the version's layout and checks it.</summary>
    public static List<Candidate> CodeRegistration(INativeImage image, CancellationToken ct = default)
    {
        int ptr = image.Is64Bit ? 8 : 4;
        var slots = image.RelocationRvas as uint[] ?? [.. image.RelocationRvas];
        var byTarget = new Dictionary<uint, List<uint>>();
        foreach (uint slot in slots)
        {
            if (Pointer(image, slot) is not { } target) continue;
            if (!byTarget.TryGetValue(target, out var list)) byTarget[target] = list = [];
            list.Add(slot);
        }
        bool IsModule(uint rva) => Pointer(image, rva) is { } name && IsModuleName(image, name);

        var result = new List<Candidate>();
        foreach (uint name in Strings(image, "mscorlib.dll", ct))
            foreach (uint module in byTarget.GetValueOrDefault(name) ?? [])
                foreach (uint entry in byTarget.GetValueOrDefault(module) ?? [])
                {
                    ct.ThrowIfCancellationRequested();
                    // Every module pointer before the entry may start the array (other module lists can precede it).
                    for (uint start = entry, i = 0; i < MaxModules; i++)
                    {
                        foreach (uint field in byTarget.GetValueOrDefault(start) ?? [])
                        {
                            if (field < ptr || ReadUInt(image, field - (uint)ptr, ptr) is not { } count || count is 0 or > MaxModules) continue;
                            // The array holds count modules and the found one among them.
                            if (entry >= start + count * (uint)ptr) continue;
                            result.Add(new Candidate(image.ImageBase + field, image.ImageBase + start, (uint)count));
                        }
                        if (start < ptr || Pointer(image, start - (uint)ptr) is not { } previous || !IsModule(previous)) break;
                        start -= (uint)ptr;
                    }
                }
        return [.. result.DistinctBy(c => c.FieldVa).OrderBy(c => c.FieldVa)];
    }

    /// <summary>
    /// The addresses of arrays of exactly <paramref name="modules"/> code-gen module pointers that hold mscorlib's module,
    /// for builds that fill their code registration at run time (only code references the array).
    /// </summary>
    public static List<ulong> ModuleArrays(INativeImage image, int modules, CancellationToken ct = default)
    {
        uint ptr = image.Is64Bit ? 8u : 4u;
        var result = new List<ulong>();
        if (modules is <= 0 or > MaxModules) return result;
        var mscorlib = Strings(image, "mscorlib.dll", ct).ToHashSet();
        bool IsModule(uint at, out uint target)
        {
            target = 0;
            if (Pointer(image, at) is not { } module || Pointer(image, module) is not { } name || !IsModuleName(image, name)) return false;
            target = name;
            return true;
        }
        foreach (uint slot in image.RelocationRvas)
        {
            if (!IsModule(slot, out uint name) || !mscorlib.Contains(name)) continue;
            ct.ThrowIfCancellationRequested();
            uint first = slot, last = slot;
            while (first >= ptr && slot - first < MaxModules * ptr && IsModule(first - ptr, out _)) first -= ptr;
            while (last - slot < MaxModules * ptr && IsModule(last + ptr, out _)) last += ptr;
            // Exactly the module count: one run, bounded by non-module words on both sides.
            if ((last - first) / ptr + 1 == modules) result.Add(image.ImageBase + first);
        }
        return [.. result.Distinct()];
    }

    /// <summary>
    /// The addresses of generic method pointer arrays of <paramref name="count"/> entries, for builds that fill their code
    /// registration at run time: a null first entry (Il2Cpp's generated table always starts with one) followed by
    /// count - 1 code pointers, outside the <paramref name="exclude"/>d ranges (the modules' own method pointer arrays).
    /// When several qualify, those whose run of code pointers ends with the array are kept (a longer run is another table).
    /// </summary>
    public static List<ulong> GenericMethodPointers(INativeImage image, int count, IReadOnlyCollection<(ulong Start, ulong End)> exclude, CancellationToken ct = default)
    {
        var found = new List<(ulong Va, bool Exact)>();
        if (count < 2) return [];
        int ptr = image.Is64Bit ? 8 : 4;
        ulong thumb = image.Arch == NativeArch.Arm && !image.Is64Bit ? 1UL : 0;
        var code = image.Sections.Where(s => s.IsExecutable).Select(s => (Start: image.ImageBase + s.Rva, End: image.ImageBase + s.Rva + s.MappedSize)).ToArray();
        bool IsCode(ulong va)
        {
            va &= ~thumb;
            foreach (var (start, end) in code)
                if (va >= start && va < end) return true;
            return false;
        }
        foreach (var section in image.Sections)
        {
            if (section.IsExecutable || section.RawSize == 0 || section.MappedSize < (ulong)count * (uint)ptr) continue;
            ct.ThrowIfCancellationRequested();
            var bytes = image.ReadFileBytes(section);
            int n = bytes.Length / ptr * ptr;
            long nullAt = -1, run = 0;
            void End()
            {
                if (nullAt < 0 || run < count - 1) return;
                ulong va = image.ImageBase + section.Rva + (ulong)nullAt, end = va + (ulong)count * (uint)ptr;
                if (!exclude.Any(x => va < x.End && x.Start < end)) found.Add((va, run == count - 1));
            }
            for (int at = 0; at < n; at += ptr)
            {
                ulong word = ptr == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(at)) : BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(at));
                if (word != 0 && IsCode(word)) { run++; continue; }
                End();
                (nullAt, run) = (word == 0 ? at : -1, 0);
            }
            End();
        }
        return [.. (found.Count > 1 && found.Any(f => f.Exact) ? found.Where(f => f.Exact) : found).Select(f => f.Va)];
    }

    private static IEnumerable<uint> Strings(INativeImage image, string text, CancellationToken ct)
    {
        var needle = Encoding.ASCII.GetBytes(text + "\0");
        foreach (var section in image.Sections)
        {
            if (section.IsExecutable || section.RawSize == 0) continue;
            ct.ThrowIfCancellationRequested();
            var bytes = image.ReadFileBytes(section);
            int n = bytes.Length;
            for (int at = 0; at < n;)
            {
                int hit = bytes.AsSpan(at, n - at).IndexOf(needle);
                if (hit < 0) break;
                at += hit;
                if (at == 0 || bytes[at - 1] == 0) yield return section.Rva + (uint)at;
                at++;
            }
        }
    }

    /// <summary>A module name: printable ASCII, "Assembly.dll" or a generated one such as "__Generated".</summary>
    private static bool IsModuleName(INativeImage image, uint rva)
    {
        Span<byte> b = stackalloc byte[256];
        int n = image.Read(rva, b);
        int end = b[..n].IndexOf((byte)0);
        return end > 0 && !b[..end].ContainsAnyExceptInRange((byte)0x20, (byte)0x7E);
    }

    private static ulong? ReadUInt(INativeImage image, uint rva, int size)
    {
        Span<byte> b = stackalloc byte[8];
        if (image.Read(rva, b[..size]) != size) return null;
        return size == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(b) : BinaryPrimitives.ReadUInt32LittleEndian(b);
    }

    private static uint? Pointer(INativeImage image, uint rva)
    {
        if (ReadUInt(image, rva, image.Is64Bit ? 8 : 4) is not { } va || va == 0 || va < image.ImageBase || va - image.ImageBase >= image.SizeOfImage) return null;
        return (uint)(va - image.ImageBase);
    }
}
