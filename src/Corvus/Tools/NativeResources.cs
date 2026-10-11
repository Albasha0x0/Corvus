using System.ComponentModel;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;

namespace Corvus.Tools;

/// <summary>Native image facts by URI: sections, entry points and type layouts. Template values are URL-decoded ("app.dll%232" for app.dll#2).</summary>
[McpServerResourceType]
public sealed class NativeResources(AssemblyWorkspace workspace, IServiceProvider services)
{
    private const string Prefix = DecompilerResources.Scheme + "://native/{image}/";

    [McpServerResource(UriTemplate = Prefix + "segments", Name = "native_segments", Title = "Native segments", MimeType = "text/plain")]
    [Description("A native image's sections: name, start and exclusive end (VA), size and r/w/x.")]
    public string Segments([Description("Native image id.")] string image) => workspace.Read(() =>
    {
        var pe = workspace.GetNative(Decode(image)).Image;
        var sb = new StringBuilder();
        foreach (var s in pe.Sections)
            sb.AppendLine($"{s.Name}\t{NativeAddress.Va(pe, s.Rva)}-{NativeAddress.Va(pe, s.Rva + s.VirtualSize)}\t0x{s.VirtualSize:X}\t" +
                          $"{((s.Access & SectionAccess.Read) != 0 ? 'r' : '-')}{((s.Access & SectionAccess.Write) != 0 ? 'w' : '-')}{((s.Access & SectionAccess.Execute) != 0 ? 'x' : '-')}");
        return sb.Length == 0 ? "No sections." : sb.ToString();
    });

    [McpServerResource(UriTemplate = Prefix + "entrypoints", Name = "native_entrypoints", Title = "Native entry points", MimeType = "text/plain")]
    [Description("A native image's entry points with their addresses: the entry point, TLS callbacks and exports (PE ordinals; forwarders with their target).")]
    public string EntryPoints([Description("Native image id.")] string image) => workspace.Read(() =>
    {
        var pe = workspace.GetNative(Decode(image)).Image;
        var sb = new StringBuilder();
        if (pe.EntryPointRva != 0) sb.AppendLine($"{NativeAddress.Va(pe, pe.EntryPointRva)}\tentry");
        foreach (var t in pe.TlsCallbackRvas) sb.AppendLine($"{NativeAddress.Va(pe, t)}\ttls_callback");
        bool ordinals = pe.Format == ImageFormat.Pe;
        foreach (var e in pe.Exports)
        {
            var name = (e.Name ?? $"#{e.Ordinal}") + (ordinals ? $"\t#{e.Ordinal}" : "");
            sb.AppendLine(e.ForwardedTo != null ? $"-\texport\t{name}\t-> {e.ForwardedTo}" : $"{NativeAddress.Va(pe, e.Rva)}\texport\t{name}");
        }
        return sb.Length == 0 ? "No entry points." : sb.ToString();
    });

    [McpServerResource(UriTemplate = Prefix + "type/{name}", Name = "native_type", Title = "Native type", MimeType = "text/plain")]
    [Description("A native type's layout as get_native_type name=... shows it (PDB, RTTI, Il2Cpp, or an engine's types once analyzed).")]
    public Task<string> Type([Description("Native image id.")] string image, [Description("Type name.")] string name, CancellationToken cancellationToken) =>
        ActivatorUtilities.CreateInstance<NativeTypeInfoTools>(services).GetNativeType(Decode(image), name: Decode(name), cancellationToken: cancellationToken);

    private static string Decode(string value) => Uri.UnescapeDataString(value);
}
