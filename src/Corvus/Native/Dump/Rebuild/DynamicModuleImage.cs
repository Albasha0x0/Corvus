using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using Corvus.Native.Dump.Managed;
using Corvus.Native.Live;
using Microsoft.Diagnostics.Runtime;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>An assembly written from a dynamic module: its bytes, or the reason none was written, and the methods given a placeholder body.</summary>
/// <param name="Bytes">The PE file; null when <paramref name="Failure"/> says why none was written.</param>
/// <param name="Bodiless">The methods whose body is unknown, as <c>Type::Name</c>; each is written as <c>throw null</c>.</param>
/// <param name="Methods">The methods written with their own body.</param>
public sealed record DynamicModuleBuild(byte[]? Bytes, string? Failure, IReadOnlyList<string> Bodiless, int Methods);

/// <summary>Writes the metadata and IL bodies read from a dynamic module into a loadable assembly.</summary>
public static class DynamicModuleImage
{
    private const uint SectionAlignment = 0x1000, FileAlignment = 0x200, TextRva = 0x2000;
    private const int ClrHeaderSize = 72;

    // Stack slots a fat body declares: the runtime does not report the value.
    private const ushort MaxStack = 64;

    /// <summary>Writes <paramref name="read"/> as a PE file with a CLR header; a module without readable metadata yields a reason, never bytes.</summary>
    public static DynamicModuleBuild Build(DynamicModuleRead read)
    {
        if (read.Metadata == null) return Fail(read.MetadataUnknown ?? "metadata_unknown: the module has no metadata");
        var metadata = (byte[])read.Metadata.Clone();
        MetadataReader reader;
        try
        {
            reader = MetadataReaderProvider.FromMetadataImage(ImmutableArray.Create(metadata)).GetMetadataReader();
        }
        catch (Exception ex) when (ex is BadImageFormatException or ArgumentException or InvalidOperationException)
        {
            return Fail("metadata_unreadable: " + ex.Message);
        }
        int rows = reader.GetTableRowCount(TableIndex.MethodDef);
        int table = reader.GetTableMetadataOffset(TableIndex.MethodDef), rowSize = reader.GetTableRowSize(TableIndex.MethodDef);
        var bodies = read.Methods.Where(m => m.Code != null).GroupBy(m => m.Token).ToDictionary(g => g.Key, g => g.First());
        var text = new MemoryStream();
        text.Write(new byte[ClrHeaderSize]);
        var bodiless = new List<string>();
        int written = 0;
        for (int row = 1; row <= rows; row++)
        {
            var handle = MetadataTokens.MethodDefinitionHandle(row);
            var method = reader.GetMethodDefinition(handle);
            if (HasNoBody(method)) continue;
            byte[] body;
            if (bodies.TryGetValue((uint)MetadataTokens.GetToken(handle), out var found))
            {
                body = Body(found);
                written++;
            }
            else
            {
                // ldnull, throw: a tiny body of two bytes.
                body = [0x0A, 0x14, 0x7A];
                bodiless.Add(reader.GetString(reader.GetTypeDefinition(method.GetDeclaringType()).Name) + "::" + reader.GetString(method.Name));
            }
            while (text.Length % 4 != 0) text.WriteByte(0);
            BinaryPrimitives.WriteUInt32LittleEndian(metadata.AsSpan(table + (row - 1) * rowSize), TextRva + (uint)text.Length);
            text.Write(body);
        }
        while (text.Length % 4 != 0) text.WriteByte(0);
        uint metadataRva = TextRva + (uint)text.Length;
        text.Write(metadata);
        var section = text.ToArray();
        WriteClrHeader(section, metadataRva, (uint)metadata.Length);
        return new DynamicModuleBuild(Wrap(section), null, bodiless, written);
    }

    /// <summary>
    /// Rebuilds the dynamic module <paramref name="target"/> names from <paramref name="memory"/>; the check <c>dynamic module</c>
    /// is ok, partial with the count of methods without a body, or failed with the reason.
    /// </summary>
    public static RebuiltModule Rebuild(IProcessMemory memory, RebuildTarget target, CancellationToken ct)
    {
        DynamicModuleRead? read;
        try { read = ReadFrom(memory, target, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Failed(target, "runtime_unreadable: " + ex.Message);
        }
        if (read == null) return Failed(target, "runtime_unknown: no readable .NET runtime holds a dynamic module of this name");
        var built = Build(read);
        if (built.Bytes == null) return Failed(target, built.Failure ?? "metadata_unknown");
        var checks = new List<RebuildCheck>();
        int total = built.Methods + built.Bodiless.Count;
        checks.Add(built.Bodiless.Count == 0
            ? RebuildCheck.Ok("dynamic module", $"{total} method bodies written; exception handlers and the maximum stack are not read")
            : RebuildCheck.Partial("dynamic module", $"{built.Bodiless.Count} of {total} methods have no body and throw null: " + string.Join(", ", built.Bodiless.Take(8))));
        var verified = PeVerify.Check(built.Bytes, target, checks);
        int percent = total == 0 ? 100 : built.Methods * 100 / total;
        return new RebuiltModule(target, "pe", "unknown", built.Bytes, percent, checks, null, null, verified?.State, verified?.Reason);
    }

    private static RebuiltModule Failed(RebuildTarget target, string reason) =>
        new(target, "unknown", "unknown", null, 0, [RebuildCheck.Failed("dynamic module", reason)], Refused: reason);

    private static DynamicModuleBuild Fail(string reason) => new(null, reason, [], 0);

    // Abstract, external and runtime-implemented methods have no body in a
    // file.
    private static bool HasNoBody(MethodDefinition method) =>
        (method.Attributes & (MethodAttributes.Abstract | MethodAttributes.PinvokeImpl)) != 0
        || (method.ImplAttributes & (MethodImplAttributes.Runtime | MethodImplAttributes.InternalCall)) != 0;

    private static byte[] Body(DynamicMethodBody method)
    {
        var code = method.Code!;
        bool locals = method.LocalSignatureToken != 0;
        if (code.Length < 64 && !locals) return [(byte)((code.Length << 2) | 2), .. code];
        var header = new byte[12];
        // Fat format with a three-dword header; init-locals when locals exist
        // or the runtime set it.
        ushort flags = (ushort)(0x3003 | (locals || (method.Flags & 0x10) != 0 ? 0x10 : 0));
        BinaryPrimitives.WriteUInt16LittleEndian(header, flags);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(2), MaxStack);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(4), (uint)code.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(8), method.LocalSignatureToken);
        return [.. header, .. code];
    }

    private static void WriteClrHeader(byte[] section, uint metadataRva, uint metadataSize)
    {
        var header = section.AsSpan(0, ClrHeaderSize);
        BinaryPrimitives.WriteUInt32LittleEndian(header, ClrHeaderSize);
        BinaryPrimitives.WriteUInt16LittleEndian(header[4..], 2);
        BinaryPrimitives.WriteUInt16LittleEndian(header[6..], 5);
        BinaryPrimitives.WriteUInt32LittleEndian(header[8..], metadataRva);
        BinaryPrimitives.WriteUInt32LittleEndian(header[12..], metadataSize);
        // COMIMAGE_FLAGS_ILONLY.
        BinaryPrimitives.WriteUInt32LittleEndian(header[16..], 1);
    }

    // A 32-bit PE with one .text section holding the CLR header, bodies and
    // metadata.
    private static byte[] Wrap(byte[] section)
    {
        const int Nt = 0x80, Optional = Nt + 24, Sections = Optional + 0xE0, Headers = (int)FileAlignment;
        uint raw = Align((uint)section.Length, FileAlignment);
        var file = new byte[Headers + raw];
        void U16(int at, int value) => BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(at), (ushort)value);
        void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(at), value);
        U16(0, 0x5A4D);
        U32(0x3C, Nt);
        U32(Nt, 0x00004550);
        // Machine i386, one section, optional header 0xE0 bytes,
        // characteristics: executable, 32-bit, DLL.
        U16(Nt + 4, 0x14C);
        U16(Nt + 6, 1);
        U16(Nt + 20, 0xE0);
        U16(Nt + 22, 0x2102);
        U16(Optional, 0x10B);
        U32(Optional + 4, raw);
        U32(Optional + 28, 0x10000000);
        U32(Optional + 32, SectionAlignment);
        U32(Optional + 36, FileAlignment);
        U16(Optional + 40, 4);
        U16(Optional + 48, 4);
        U32(Optional + 56, TextRva + Align((uint)section.Length, SectionAlignment));
        U32(Optional + 60, FileAlignment);
        // Console subsystem; dynamic base and NX compatible.
        U16(Optional + 68, 3);
        U16(Optional + 70, 0x540);
        U32(Optional + 72, 0x100000);
        U32(Optional + 76, 0x1000);
        U32(Optional + 80, 0x100000);
        U32(Optional + 84, 0x1000);
        U32(Optional + 92, 16);
        // Data directory 14 is the CLR header.
        U32(Optional + 96 + 14 * 8, TextRva);
        U32(Optional + 96 + 14 * 8 + 4, ClrHeaderSize);
        System.Text.Encoding.ASCII.GetBytes(".text").CopyTo(file.AsSpan(Sections));
        U32(Sections + 8, (uint)section.Length);
        U32(Sections + 12, TextRva);
        U32(Sections + 16, raw);
        U32(Sections + 20, FileAlignment);
        // Contains code; executable and readable.
        U32(Sections + 36, 0x60000020);
        section.CopyTo(file.AsSpan(Headers));
        return file;
    }

    private static uint Align(uint value, uint alignment) => (value + alignment - 1) / alignment * alignment;

    private static DynamicModuleRead? ReadFrom(IProcessMemory memory, RebuildTarget target, CancellationToken ct)
    {
        // The DAC is signature-checked and never downloaded, as in the module
        // list.
        var request = new DacRequest();
        ClrDecoder? decoder = null;
        switch (memory)
        {
            case MinidumpFile dump when ClrDecoder.RuntimeModule(dump) != null:
                decoder = ClrDecoder.Open(MinidumpFile.Open(dump.Path), _ => null, [], request, ct).GetAwaiter().GetResult();
                break;
            case LiveProcess process when OperatingSystem.IsWindows() && ClrDecoder.RuntimeModule(process) != null:
                var reader = new LiveDataReader(LiveProcess.Attach(process.Pid, ct));
                try { decoder = ClrDecoder.OpenLive(reader, request, ct).GetAwaiter().GetResult(); }
                catch
                {
                    reader.Dispose();
                    throw;
                }
                break;
        }
        if (decoder == null) return null;
        using (decoder)
        {
            lock (decoder.Gate)
            {
                if (decoder.Runtime is not { } runtime) return null;
                var module = runtime.EnumerateModules().FirstOrDefault(m => m.IsDynamic && FileName(m).Equals(target.Name, StringComparison.OrdinalIgnoreCase));
                return module == null ? null : DynamicModuleReader.Read(module, runtime);
            }
        }
    }

    // The file name a dynamic module is listed under: its simple name with a
    // .dll extension.
    private static string FileName(ClrModule module)
    {
        string? name = string.IsNullOrEmpty(module.AssemblyName) ? module.Name : module.AssemblyName;
        if (string.IsNullOrEmpty(name)) return "assembly_" + module.Address.ToString("x") + ".dll";
        try { name = new AssemblyName(name).Name ?? name; }
        catch (Exception ex) when (ex is ArgumentException or FileLoadException) { name = Path.GetFileNameWithoutExtension(name); }
        return name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name : name + ".dll";
    }
}
