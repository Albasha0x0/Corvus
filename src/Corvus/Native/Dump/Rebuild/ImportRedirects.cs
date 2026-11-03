using System.Buffers.Binary;
using System.Text;
using Corvus.Native.Pe;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>An import address table slot checked against the export it names.</summary>
/// <param name="SlotRva">RVA of the slot in the image.</param>
/// <param name="Import"><c>module!name</c> or <c>module!#ordinal</c> as the import directory names it.</param>
/// <param name="State"><c>redirected</c> when the slot differs from the export address, <c>unknown</c> when it could not be checked.</param>
/// <param name="Expected">Address of the export; null when unknown.</param>
/// <param name="Actual">Value of the slot; null when its page was not captured.</param>
/// <param name="Reason">Why the slot is unknown; null for a redirect.</param>
/// <param name="Via">The API set map that resolved the contract name (<c>dump</c> or <c>system</c>); null for a plain module name.</param>
/// <param name="Target">Module and export the slot points into (<c>module!name</c> or <c>module+offset</c>); null outside every module.</param>
public sealed record ImportRedirect(
    uint SlotRva, string Import, string State, ulong? Expected, ulong? Actual, string? Reason, string? Via = null, string? Target = null);

/// <summary>Lists import address table slots that do not hold the address of the export they name.</summary>
public static class ImportRedirects
{
    private const int DescriptorSize = 20;
    private const int MaxSlots = 64 * 1024;
    private const int MaxForwardDepth = 8;
    private const int MaxNameBytes = 256;

    /// <summary>Reads the API set map at <paramref name="address"/>; null when the memory is not a version 6 map.</summary>
    public static ApiSetSchema? ReadApiSetMap(IProcessMemory memory, ulong address)
    {
        var head = new byte[8];
        if (memory.ReadMemory(address, head) < 8) return null;
        uint size = BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(4));
        if (BinaryPrimitives.ReadUInt32LittleEndian(head) != 6 || size < 28 || size > 16u << 20) return null;
        var map = new byte[size];
        int read = memory.ReadMemory(address, map);
        return ApiSetSchema.Parse(map.AsSpan(0, read));
    }

    /// <summary>
    /// Compares each slot of the captured, not yet restored <paramref name="mapped"/> image with the export its name table entry names.
    /// Returns only redirected slots and slots that could not be checked (module not loaded, name not exported,
    /// page or name table not captured); a slot holding its export address is not listed.
    /// A forwarded export is followed through <paramref name="exports"/>; the lookup by name reads the exports of <paramref name="memory"/>.
    /// A contract name (api-ms-*, ext-ms-*) resolves through <paramref name="dumpApiSets"/> when given, else through the system map;
    /// a row names that map in <see cref="ImportRedirect.Via"/>, and an unmapped contract stays unknown.
    /// A module name binds to the loaded module of the importer's machine, else of its bitness, else the first of that name.
    /// A slot equal to the same slot of <paramref name="disk"/> (an unbound import) is not listed.
    /// </summary>
    public static IReadOnlyList<ImportRedirect> Find(
        byte[] mapped, CapturedImage captured, ExportMap exports, IProcessMemory memory, ApiSetSchema? dumpApiSets = null, PeFile? disk = null)
    {
        List<ImportRedirect> rows = [];
        if (!PeImportRestore.TryDirectory(mapped, out bool is64, out uint dirRva, out uint dirSize) || dirRva == 0 || dirSize == 0) return rows;

        var index = new Index(memory, exports, dumpApiSets);
        ushort machine = BinaryPrimitives.ReadUInt16LittleEndian(mapped.AsSpan(BinaryPrimitives.ReadInt32LittleEndian(mapped.AsSpan(0x3C)) + 4));
        var onDisk = new byte[8];
        int width = is64 ? 8 : 4;
        long count = dirSize / DescriptorSize;
        int slots = 0;
        for (long i = 0; i < count; i++)
        {
            long at = dirRva + i * DescriptorSize;
            if (at + DescriptorSize > mapped.Length) break;
            var d = mapped.AsSpan((int)at, DescriptorSize);
            uint lookup = BinaryPrimitives.ReadUInt32LittleEndian(d), nameRva = BinaryPrimitives.ReadUInt32LittleEndian(d[12..]);
            uint first = BinaryPrimitives.ReadUInt32LittleEndian(d[16..]);
            if (lookup == 0 && first == 0 && nameRva == 0) break;
            if (first == 0 || first >= mapped.Length) continue;

            string module = ReadString(mapped, nameRva) ?? "?";
            if (lookup == 0 || lookup >= mapped.Length)
            {
                rows.Add(new ImportRedirect(first, module + "!?", "unknown", null, null, "import lookup table is absent"));
                continue;
            }
            for (long slot = 0; slots < MaxSlots; slot++, slots++)
            {
                long lookupAt = lookup + slot * width, slotAt = first + slot * width;
                if (lookupAt + width > mapped.Length || slotAt + width > mapped.Length) break;
                if (!captured.PageCaptured((uint)lookupAt))
                {
                    rows.Add(new ImportRedirect((uint)slotAt, module + "!?", "unknown", null, null, "import lookup table was not captured"));
                    break;
                }
                ulong entry = Read(mapped, (int)lookupAt, width);
                if (entry == 0) break;

                // An unbound slot still holds its file value, so nothing
                // was written to it.
                if (disk is not null && captured.PageCaptured((uint)slotAt) && captured.PageCaptured((uint)(slotAt + width - 1)) &&
                    disk.Read((uint)slotAt, onDisk.AsSpan(0, width)) == width && Read(onDisk, 0, width) == Read(mapped, (int)slotAt, width))
                    continue;

                string function = Function(mapped, entry, is64);
                string import = module + "!" + function;
                if (function == "?")
                {
                    rows.Add(new ImportRedirect((uint)slotAt, import, "unknown", null, null, "import name was not captured"));
                    continue;
                }
                if (!captured.PageCaptured((uint)slotAt) || !captured.PageCaptured((uint)(slotAt + width - 1)))
                {
                    rows.Add(new ImportRedirect((uint)slotAt, import, "unknown", null, null, "address table page was not captured"));
                    continue;
                }
                ulong actual = Read(mapped, (int)slotAt, width);
                if (!index.TryResolve(module, function, machine, is64, out ulong expected, out string? reason, out string? via))
                    rows.Add(new ImportRedirect((uint)slotAt, import, "unknown", null, actual, reason, via));
                else if (expected != actual)
                    rows.Add(new ImportRedirect((uint)slotAt, import, "redirected", expected, actual, null, via, Target(exports, memory, actual)));
            }
        }
        return rows;
    }

    private static string? Target(ExportMap exports, IProcessMemory memory, ulong address)
    {
        var name = exports.NameAt(address);
        if (name is not null) return name;
        var module = memory.ModuleAt(address);
        return module is null ? null : $"{module.FileName}+0x{address - module.Base:X}";
    }

    // "?" when the name entry lies outside the captured image.
    private static string Function(byte[] mapped, ulong entry, bool is64)
    {
        ulong flag = is64 ? 1UL << 63 : 1UL << 31;
        if ((entry & flag) != 0) return "#" + (entry & 0xFFFF);
        return entry + 2 < (ulong)mapped.Length ? ReadString(mapped, (long)entry + 2) ?? "?" : "?";
    }

    private static string? ReadString(byte[] image, long at)
    {
        if (at <= 0 || at >= image.Length) return null;
        int length = (int)Math.Min(MaxNameBytes, image.Length - at);
        int end = image.AsSpan((int)at, length).IndexOf((byte)0);
        return end < 0 ? null : Encoding.ASCII.GetString(image, (int)at, end);
    }

    private static ulong Read(byte[] image, int at, int width) =>
        width == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(image.AsSpan(at)) : BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(at));

    // Name to address lookup over the loaded modules; ExportMap only answers
    // address to name.
    private sealed class Index
    {
        private readonly IProcessMemory _memory;
        private readonly Dictionary<string, List<(DumpModule Module, ushort Machine, bool Is64)>> _modules = new(StringComparer.OrdinalIgnoreCase);
        private readonly ExportMap _map;
        private readonly Dictionary<ulong, Dictionary<string, ulong>?> _exports = [];

        private readonly ApiSetSchema? _dumpApiSets;
        private ApiSetSchema? _systemApiSets;
        private bool _systemLoaded;

        public Index(IProcessMemory memory, ExportMap map, ApiSetSchema? dumpApiSets)
        {
            _memory = memory;
            _dumpApiSets = dumpApiSets;
            _map = map;
            foreach (var m in memory.Modules)
            {
                var head = new byte[0x200];
                ushort machine = 0;
                bool is64 = memory.Is64Bit;
                if (memory.ReadMemory(m.Base, head) == head.Length && DumpImages.TryHeader(head, out _, out _, out _))
                {
                    int nt = BinaryPrimitives.ReadInt32LittleEndian(head.AsSpan(0x3C));
                    if (nt > 0 && nt + 26 <= head.Length)
                    {
                        machine = BinaryPrimitives.ReadUInt16LittleEndian(head.AsSpan(nt + 4));
                        is64 = BinaryPrimitives.ReadUInt16LittleEndian(head.AsSpan(nt + 24)) == 0x20B;
                    }
                }
                if (!_modules.TryGetValue(m.FileName, out var list)) _modules[m.FileName] = list = [];
                list.Add((m, machine, is64));
            }
        }

        // Same machine first, then same bitness, then the first of that name.
        private DumpModule? Pick(string name, ushort machine, bool is64)
        {
            if (!_modules.TryGetValue(name, out var list)) return null;
            foreach (var c in list) if (c.Machine == machine) return c.Module;
            foreach (var c in list) if (c.Is64 == is64) return c.Module;
            return list[0].Module;
        }

        // Hosts of an API set contract for an importer and the map that named
        // them; empty when unmapped.
        private IReadOnlyList<string> Hosts(string contract, string? importer, out string via)
        {
            if (_dumpApiSets is not null)
            {
                via = "dump";
                return _dumpApiSets.Hosts(contract, importer);
            }
            via = "system";
            if (!_systemLoaded)
            {
                _systemLoaded = true;
                try { _systemApiSets = ApiSetSchema.FromSystem(PeFile.Open); }
                catch (Exception e) when (e is Core.ToolError or IOException) { }
            }
            return _systemApiSets?.Hosts(contract, importer) ?? [];
        }

        public bool TryResolve(string module, string function, ushort machine, bool is64, out ulong address, out string? reason, out string? via)
        {
            address = 0;
            via = null;
            string? importer = null;
            for (int depth = 0; depth <= MaxForwardDepth; depth++)
            {
                if (ApiSetSchema.IsApiSetName(module))
                {
                    var hosts = Hosts(module, importer, out string used);
                    via ??= used;
                    if (hosts.Count == 0)
                    {
                        reason = $"contract {module} is not in the {used} api set map";
                        return false;
                    }
                    // A host equal to the forwarding module would loop back to
                    // the contract.
                    var host = hosts.FirstOrDefault(h => importer is null || !string.Equals(h, importer, StringComparison.OrdinalIgnoreCase));
                    if (host is null)
                    {
                        reason = $"the contract resolves back to {importer}";
                        return false;
                    }
                    module = host;
                }
                var loaded = Pick(module, machine, is64);
                if (loaded is null)
                {
                    reason = $"{module} is not a loaded module";
                    return false;
                }
                if (_map.ForwarderOf(loaded.Base, function) is { } target)
                {
                    int dot = target.LastIndexOf('.');
                    if (dot <= 0)
                    {
                        reason = $"forwarder '{target}' is malformed";
                        return false;
                    }
                    importer = loaded.FileName;
                    module = target[..dot];
                    if (!_modules.ContainsKey(module)) module += ".dll";
                    function = target[(dot + 1)..];
                    continue;
                }
                var table = Exports(loaded);
                if (table is null)
                {
                    reason = $"export directory of {loaded.FileName} was not captured";
                    return false;
                }
                if (!table.TryGetValue(function, out address))
                {
                    reason = $"{loaded.FileName} does not export {function}";
                    return false;
                }
                reason = null;
                return true;
            }
            reason = "forwarder chain is too long";
            return false;
        }

        private Dictionary<string, ulong>? Exports(DumpModule module)
        {
            if (!_exports.TryGetValue(module.Base, out var table))
                _exports[module.Base] = table = Read(module);
            return table;
        }

        // Forwarded exports are left out; they resolve through the forwarder
        // text.
        private Dictionary<string, ulong>? Read(DumpModule module)
        {
            var head = new byte[0x1000];
            if (_memory.ReadMemory(module.Base, head) < 0x200 || !DumpImages.TryHeader(head, out _, out _, out _)) return null;
            int nt = BinaryPrimitives.ReadInt32LittleEndian(head.AsSpan(0x3C));
            int opt = nt + 24;
            int dirs = opt + (BinaryPrimitives.ReadUInt16LittleEndian(head.AsSpan(opt)) == 0x20B ? 112 : 96);
            if (dirs + 8 > head.Length) return null;
            uint dirRva = BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(dirs));
            uint dirSize = BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(dirs + 4));
            if (dirRva == 0) return [];
            var dir = Block(module, dirRva, 40);
            if (dir is null) return null;
            uint ordinalBase = BinaryPrimitives.ReadUInt32LittleEndian(dir.AsSpan(16));
            uint functionCount = BinaryPrimitives.ReadUInt32LittleEndian(dir.AsSpan(20));
            uint nameCount = BinaryPrimitives.ReadUInt32LittleEndian(dir.AsSpan(24));
            if (functionCount > ExportMap.MaxExportsPerModule || nameCount > ExportMap.MaxExportsPerModule) return null;
            var functions = Block(module, BinaryPrimitives.ReadUInt32LittleEndian(dir.AsSpan(28)), functionCount * 4UL);
            var names = Block(module, BinaryPrimitives.ReadUInt32LittleEndian(dir.AsSpan(32)), nameCount * 4UL);
            var ordinals = Block(module, BinaryPrimitives.ReadUInt32LittleEndian(dir.AsSpan(36)), nameCount * 2UL);
            if (functions is null || names is null || ordinals is null) return null;

            Dictionary<string, ulong> table = [];
            for (uint i = 0; i < functionCount; i++)
            {
                uint rva = BinaryPrimitives.ReadUInt32LittleEndian(functions.AsSpan(4 * (int)i));
                if (rva == 0 || rva >= module.Size || (rva >= dirRva && rva - dirRva < dirSize)) continue;
                table.TryAdd("#" + (ordinalBase + i), module.Base + rva);
            }
            for (int i = 0; i < nameCount; i++)
            {
                int index = BinaryPrimitives.ReadUInt16LittleEndian(ordinals.AsSpan(2 * i));
                if (index >= functionCount || !table.TryGetValue("#" + (ordinalBase + (uint)index), out var address)) continue;
                var name = Name(module, BinaryPrimitives.ReadUInt32LittleEndian(names.AsSpan(4 * i)));
                if (name is not null) table.TryAdd(name, address);
            }
            return table;
        }

        private byte[]? Block(DumpModule module, uint rva, ulong length)
        {
            if (length == 0) return [];
            if (rva >= module.Size || length > module.Size - rva) return null;
            var block = new byte[length];
            return _memory.ReadMemory(module.Base + rva, block) == block.Length ? block : null;
        }

        private string? Name(DumpModule module, uint rva)
        {
            if (rva >= module.Size) return null;
            var buffer = new byte[(int)Math.Min(MaxNameBytes, module.Size - rva)];
            int read = _memory.ReadMemory(module.Base + rva, buffer);
            int end = buffer.AsSpan(0, read).IndexOf((byte)0);
            return end < 0 ? null : Encoding.ASCII.GetString(buffer, 0, end);
        }
    }
}
