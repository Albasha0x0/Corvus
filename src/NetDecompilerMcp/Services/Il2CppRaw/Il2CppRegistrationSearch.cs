using System.Buffers.Binary;
using System.Text;
using NetDecompilerMcp.Native;

namespace NetDecompilerMcp.Services;

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
                    uint start = entry;
                    for (int i = 0; i < MaxModules && start >= ptr && Pointer(image, start - (uint)ptr) is { } previous && IsModule(previous); i++) start -= (uint)ptr;
                    foreach (uint field in byTarget.GetValueOrDefault(start) ?? [])
                    {
                        if (field < ptr || ReadUInt(image, field - (uint)ptr, ptr) is not { } count || count is 0 or > MaxModules) continue;
                        // The array holds count modules and the found one among them.
                        if (entry >= start + count * (uint)ptr) continue;
                        result.Add(new Candidate(image.ImageBase + field, image.ImageBase + start, (uint)count));
                    }
                }
        return [.. result.DistinctBy(c => c.FieldVa).OrderBy(c => c.FieldVa)];
    }

    private static IEnumerable<uint> Strings(INativeImage image, string text, CancellationToken ct)
    {
        var needle = Encoding.ASCII.GetBytes(text + "\0");
        foreach (var section in image.Sections)
        {
            if (section.IsExecutable || section.RawSize == 0) continue;
            ct.ThrowIfCancellationRequested();
            var bytes = new byte[Math.Min(section.MappedSize, (uint)Array.MaxLength)];
            int n = image.Read(section.Rva, bytes);
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
