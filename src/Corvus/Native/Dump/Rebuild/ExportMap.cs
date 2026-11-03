using System.Buffers.Binary;
using System.Text;
using Corvus.Native.Pe;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>Names the export that starts at an address of a process, from the export directories of its loaded modules.</summary>
public sealed class ExportMap
{
    /// <summary>Most exports read from one module; a directory past it is skipped.</summary>
    public const int MaxExportsPerModule = 1 << 16;

    private const int MaxNameBytes = PeLimits.MaxNameLength;

    private readonly Dictionary<ulong, string> _byAddress = [];
    private readonly List<string> _forwarders = [];
    private readonly List<string> _ordinalForwarders = [];
    private readonly Dictionary<(ulong Base, string Name), string> _forwarderText = [];

    /// <summary>Reads the export directory of each module of <paramref name="memory"/>; a module that cannot be read is counted in <see cref="SkippedModules"/>.</summary>
    public ExportMap(IProcessMemory memory)
    {
        foreach (var module in memory.Modules)
            if (!Read(memory, module)) SkippedModules++;
    }

    /// <summary>Modules whose export directory was not captured, was malformed or held more than <see cref="MaxExportsPerModule"/> exports.</summary>
    public int SkippedModules { get; private set; }

    /// <summary>Forwarded exports as <c>module!name</c> and their forwarder text; they never match an address.</summary>
    public IReadOnlyList<string> Forwarders => _forwarders;

    /// <summary>Forwarded exports that have a name, as <c>module!#ordinal</c> and their forwarder text.</summary>
    public IReadOnlyList<string> OrdinalForwarders => _ordinalForwarders;

    /// <summary>The forwarder text of export <paramref name="name"/> (a name or <c>#ordinal</c>) of the module at <paramref name="moduleBase"/>; null when it is not forwarded.</summary>
    public string? ForwarderOf(ulong moduleBase, string name) => _forwarderText.GetValueOrDefault((moduleBase, name));

    /// <summary>The export starting at <paramref name="address"/> as <c>module!name</c> or <c>module!#ordinal</c>; null when none starts there.</summary>
    public string? NameAt(ulong address) => _byAddress.GetValueOrDefault(address);

    private bool Read(IProcessMemory memory, DumpModule module)
    {
        var head = new byte[0x1000];
        if (memory.ReadMemory(module.Base, head) < 0x200 || !DumpImages.TryHeader(head, out _, out _, out _)) return false;
        int nt = BinaryPrimitives.ReadInt32LittleEndian(head.AsSpan(0x3C));
        int opt = nt + 24;
        int dirs = opt + (BinaryPrimitives.ReadUInt16LittleEndian(head.AsSpan(opt)) == 0x20B ? 112 : 96);
        if (dirs + 8 > head.Length) return false;
        uint dirRva = BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(dirs));
        uint dirSize = BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(dirs + 4));
        if (dirRva == 0) return true;
        if (!Fits(module, dirRva, 40)) return false;

        var dir = new byte[40];
        if (memory.ReadMemory(module.Base + dirRva, dir) < dir.Length) return false;
        uint ordinalBase = BinaryPrimitives.ReadUInt32LittleEndian(dir.AsSpan(16));
        uint functionCount = BinaryPrimitives.ReadUInt32LittleEndian(dir.AsSpan(20));
        uint nameCount = BinaryPrimitives.ReadUInt32LittleEndian(dir.AsSpan(24));
        if (functionCount > MaxExportsPerModule || nameCount > MaxExportsPerModule) return false;
        uint functionsRva = BinaryPrimitives.ReadUInt32LittleEndian(dir.AsSpan(28));
        uint namesRva = BinaryPrimitives.ReadUInt32LittleEndian(dir.AsSpan(32));
        uint ordinalsRva = BinaryPrimitives.ReadUInt32LittleEndian(dir.AsSpan(36));

        var functions = Table(memory, module, functionsRva, functionCount, 4);
        var names = Table(memory, module, namesRva, nameCount, 4);
        var ordinals = Table(memory, module, ordinalsRva, nameCount, 2);
        if (functions is null || names is null || ordinals is null) return false;

        var named = new string?[functionCount];
        for (int i = 0; i < nameCount; i++)
        {
            int index = BinaryPrimitives.ReadUInt16LittleEndian(ordinals.AsSpan(2 * i));
            uint nameRva = BinaryPrimitives.ReadUInt32LittleEndian(names.AsSpan(4 * i));
            if (index < functionCount && ReadName(memory, module, nameRva) is { } name) named[index] = name;
        }

        string prefix = module.FileName + "!";
        for (int i = 0; i < functionCount; i++)
        {
            uint rva = BinaryPrimitives.ReadUInt32LittleEndian(functions.AsSpan(4 * i));
            if (rva == 0 || rva >= module.Size) continue;
            string label = prefix + (named[i] ?? $"#{ordinalBase + (uint)i}");
            if (rva >= dirRva && rva - dirRva < dirSize)
            {
                var text = ReadName(memory, module, rva);
                _forwarders.Add(text is null ? label : $"{label} {text}");
                if (text is not null)
                {
                    _forwarderText.TryAdd((module.Base, named[i] ?? $"#{ordinalBase + (uint)i}"), text);
                    if (named[i] is not null) _forwarderText.TryAdd((module.Base, $"#{ordinalBase + (uint)i}"), text);
                }
                if (text is not null && named[i] is not null) _ordinalForwarders.Add($"{prefix}#{ordinalBase + (uint)i} {text}");
                continue;
            }
            _byAddress.TryAdd(module.Base + rva, label);
        }
        return true;
    }

    private static bool Fits(DumpModule module, uint rva, ulong length) => rva < module.Size && length <= module.Size - rva;

    private static byte[]? Table(IProcessMemory memory, DumpModule module, uint rva, uint count, int width)
    {
        if (count == 0) return [];
        ulong length = (ulong)count * (ulong)width;
        if (!Fits(module, rva, length)) return null;
        var table = new byte[length];
        return memory.ReadMemory(module.Base + rva, table) == table.Length ? table : null;
    }

    private static string? ReadName(IProcessMemory memory, DumpModule module, uint rva)
    {
        if (rva >= module.Size) return null;
        var buffer = new byte[(int)Math.Min(MaxNameBytes, module.Size - rva)];
        int read = memory.ReadMemory(module.Base + rva, buffer);
        int end = buffer.AsSpan(0, read).IndexOf((byte)0);
        return end < 0 ? null : Encoding.ASCII.GetString(buffer, 0, end);
    }
}
