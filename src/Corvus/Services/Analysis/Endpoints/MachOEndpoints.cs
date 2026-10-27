using System.Buffers.Binary;
using System.Text;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;

namespace Corvus.Services.Analysis.Endpoints;

/// <summary>
/// Absolute URLs in a Mach-O image's __cstring, each with the functions that load it.
/// A Swift large string's object address is the literal's minus 32.
/// </summary>
internal static class MachOEndpoints
{
    /// <summary>Most sites listed per string.</summary>
    private const int MaxSites = 8;

    public static void Scan(byte[] bytes, string file, List<CodeEndpoint> endpoints, CancellationToken ct)
    {
        if (NativeImageLoader.Detect(bytes) is not (NativeFileKind.MachO or NativeFileKind.MachOFat)) return;
        INativeImage image;
        try { image = NativeImageLoader.FromBytes(bytes, file); }
        catch (ToolError) { return; }
        var urls = new List<(uint Rva, string Text)>();
        foreach (var section in image.Sections.Where(s => s.Name.EndsWith(",__cstring", StringComparison.Ordinal) && s.VirtualSize <= 256u << 20))
        {
            var data = new byte[section.VirtualSize];
            int read = image.Read(section.Rva, data);
            for (int start = 0; start < read;)
            {
                int end = Array.IndexOf(data, (byte)0, start, read - start);
                if (end < 0) end = read;
                if (end - start is >= 10 and <= 2048 && (data[start] | 0x20) is (byte)'h' or (byte)'w')
                {
                    var text = Encoding.UTF8.GetString(data, start, end - start);
                    var folded = EndpointTemplates.FoldFormat(text);
                    if (EndpointTemplates.IsLinkUrl(folded)) urls.Add((section.Rva + (uint)start, folded));
                }
                start = end + 1;
            }
        }
        if (urls.Count == 0) return;
        ct.ThrowIfCancellationRequested();
        var cf = CfStrings(image);
        NativeCodeIndex? index = null;
        try { index = NativeCodeIndex.Build(image, ct: ct); }
        catch (ToolError) { }
        foreach (var (rva, text) in urls)
        {
            var sites = new List<CodeXref>();
            if (index != null)
            {
                sites.AddRange(index.RefsTo(rva, MaxSites));
                if (rva >= 32) sites.AddRange(index.RefsTo(rva - 32, MaxSites));
                if (cf.TryGetValue(rva, out var constant)) sites.AddRange(index.RefsTo(constant, MaxSites));
            }
            var functions = sites.Select(x => (Site: x.From, Function: index!.FunctionAt(x.From))).Where(x => x.Function != null)
                .DistinctBy(x => x.Function!.Start).Take(MaxSites).ToList();
            if (functions.Count == 0) endpoints.Add(new CodeEndpoint("*", text, "url", file, null, Va(image, rva)));
            foreach (var (site, function) in functions)
                endpoints.Add(new CodeEndpoint("*", text, "url", file, index!.NameAt(function!.Start) ?? $"sub_{image.ImageBase + function.Start:x}", Va(image, site)));
        }
    }

    private static string Va(INativeImage image, uint rva) => $"0x{image.ImageBase + rva:x}";

    /// <summary>__cfstring constants by the RVA of their characters.</summary>
    private static Dictionary<uint, uint> CfStrings(INativeImage image)
    {
        var map = new Dictionary<uint, uint>();
        int ptr = image.Is64Bit ? 8 : 4;
        foreach (var section in image.Sections.Where(s => s.Name.EndsWith(",__cfstring", StringComparison.Ordinal) && s.VirtualSize <= 64u << 20))
        {
            var data = new byte[section.VirtualSize];
            int read = image.Read(section.Rva, data);
            for (int at = 0; at + 4 * ptr <= read; at += 4 * ptr)
            {
                ulong va = ptr == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(at + 2 * ptr)) : BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(at + 2 * ptr));
                if (va >= image.ImageBase && va - image.ImageBase < image.SizeOfImage) map.TryAdd((uint)(va - image.ImageBase), section.Rva + (uint)at);
            }
        }
        return map;
    }
}
