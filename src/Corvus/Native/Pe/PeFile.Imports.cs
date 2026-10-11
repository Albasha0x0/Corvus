namespace Corvus.Native.Pe;

/// <summary>
/// One module of the import or delay-import directory. Table addresses are RVAs (converted from VAs for version 1
/// delay descriptors). <see cref="TimeDateStamp"/> is -1 (0xFFFFFFFF) for new-style bound imports.
/// </summary>
public sealed record PeImportModule(
    string Name,
    bool IsDelayLoad,
    uint DescriptorRva,
    uint NameTableRva,
    uint AddressTableRva,
    uint TimeDateStamp,
    IReadOnlyList<NativeImport> Functions,
    uint ForwarderChain = 0,
    uint DelayAttributes = 0,
    uint ModuleHandleRva = 0,
    uint BoundAddressTableRva = 0,
    uint UnloadAddressTableRva = 0)
{
    /// <summary>The IAT holds addresses bound at link or install time.</summary>
    public bool IsBound => TimeDateStamp != 0;
    /// <summary>Delay descriptor version 2 (RVAs); version 1 used VAs.</summary>
    public bool IsRvaBased => !IsDelayLoad || (DelayAttributes & 1) != 0;
}

/// <summary>An IMAGE_BOUND_IMPORT_DESCRIPTOR and its forwarder references.</summary>
public sealed record PeBoundImport(string Module, uint TimeDateStamp, IReadOnlyList<PeBoundForwarder> Forwarders);

public sealed record PeBoundForwarder(string Module, uint TimeDateStamp);

public sealed partial class PeFile
{
    private sealed record ImportTable(IReadOnlyList<PeImportModule> Modules, IReadOnlyList<NativeImport> Functions)
    {
        public static readonly ImportTable Empty = new([], []);
    }

    /// <summary>
    /// Import descriptors up to the first one with a zero Name or FirstThunk (the loader's terminator). Names come from
    /// the import name table (OriginalFirstThunk), or from the IAT when there is none.
    /// </summary>
    private ImportTable ParseImports(IssueLog log)
    {
        var dir = Directory(PeDirectory.Import);
        if (dir.Rva == 0) return ImportTable.Empty;
        var budget = new WorkBudget(log);
        var modules = new List<PeImportModule>();
        var all = new List<NativeImport>();
        for (long at = dir.Rva; ; at += 20)
        {
            if (modules.Count >= PeLimits.MaxImportModules)
            {
                log.Add($"more than {PeLimits.MaxImportModules} import descriptors; the rest are not read");
                break;
            }
            if (!budget.Step()) break;
            var d = ReadBlock(at, 20);
            if (d == null)
            {
                log.Add($"import descriptor at RVA 0x{at:X} is outside the mapped image; the table is unterminated", RvaToOffsetOrNull(at));
                break;
            }
            uint oft = Le32(d, 0), stamp = Le32(d, 4), chain = Le32(d, 8), nameRva = Le32(d, 12), ft = Le32(d, 16);
            if (nameRva == 0 || ft == 0) break;
            string name = ReadName(nameRva, budget, log, "import module name") ?? Unreadable(log, "import module name", nameRva);
            long thunks = ft;
            if (oft != 0)
            {
                if (IsMapped(oft, (uint)PointerSize)) thunks = oft;
                else log.Add($"{name}: import name table RVA 0x{oft:X} is outside the mapped image; names read from the IAT", RvaToOffsetOrNull(at));
            }
            else if (stamp != 0)
                log.Add($"{name}: bound imports without an import name table; the IAT holds addresses, not names", RvaToOffsetOrNull(at));
            var functions = ReadThunks(name, thunks, ft, rvaBased: true, isDelay: false, all, budget, log);
            modules.Add(new PeImportModule(name, false, (uint)at, oft, ft, stamp, functions, ForwarderChain: chain));
            if (budget.Exhausted) break;
        }
        return new ImportTable(modules, all);
    }

    /// <summary>Delay-load descriptors (ImgDelayDescr) up to the first with a zero name. Version 1 descriptors hold VAs.</summary>
    private ImportTable ParseDelayImports(IssueLog log)
    {
        var dir = Directory(PeDirectory.DelayImport);
        if (dir.Rva == 0) return ImportTable.Empty;
        var budget = new WorkBudget(log);
        var modules = new List<PeImportModule>();
        var all = new List<NativeImport>();
        for (long at = dir.Rva; ; at += 32)
        {
            if (modules.Count >= PeLimits.MaxImportModules)
            {
                log.Add($"more than {PeLimits.MaxImportModules} delay-load descriptors; the rest are not read");
                break;
            }
            if (!budget.Step()) break;
            var d = ReadBlock(at, 32);
            if (d == null)
            {
                log.Add($"delay-load descriptor at RVA 0x{at:X} is outside the mapped image; the table is unterminated", RvaToOffsetOrNull(at));
                break;
            }
            uint attributes = Le32(d, 0), nameField = Le32(d, 4);
            if (nameField == 0) break;
            bool rvaBased = (attributes & 1) != 0;
            if (!rvaBased && Is64Bit)
                log.Add("version 1 (VA-based) delay-load descriptor in a PE32+ image; its 32-bit VAs are read relative to the low half of the image base", RvaToOffsetOrNull(at));
            uint Fix(uint field) => rvaBased || field == 0 ? field : field - (uint)ImageBase;
            uint nameRva = Fix(nameField), hmod = Fix(Le32(d, 8)), iat = Fix(Le32(d, 12)), nameTable = Fix(Le32(d, 16));
            uint boundIat = Fix(Le32(d, 20)), unloadIat = Fix(Le32(d, 24)), stamp = Le32(d, 28);
            string name = ReadName(nameRva, budget, log, "delay-load module name") ?? Unreadable(log, "delay-load module name", nameRva);
            IReadOnlyList<NativeImport> functions = [];
            if (nameTable == 0 || iat == 0)
                log.Add($"{name}: delay-load descriptor without an import name table or IAT", RvaToOffsetOrNull(at));
            else
                functions = ReadThunks(name, nameTable, iat, rvaBased, isDelay: true, all, budget, log);
            modules.Add(new PeImportModule(name, true, (uint)at, nameTable, iat, stamp, functions,
                DelayAttributes: attributes, ModuleHandleRva: hmod, BoundAddressTableRva: boundIat, UnloadAddressTableRva: unloadIat));
            if (budget.Exhausted) break;
        }
        return new ImportTable(modules, all);
    }

    /// <summary>
    /// Thunks at <paramref name="thunks"/> up to a zero entry. An entry with the ordinal flag imports by ordinal;
    /// otherwise it points at IMAGE_IMPORT_BY_NAME (hint, name), as an RVA or, in version 1 delay tables, a VA.
    /// </summary>
    private List<NativeImport> ReadThunks(string module, long thunks, uint iat, bool rvaBased, bool isDelay, List<NativeImport> all,
        WorkBudget budget, IssueLog log)
    {
        var functions = new List<NativeImport>();
        int size = PointerSize;
        ulong ordinalFlag = Is64Bit ? 1UL << 63 : 1UL << 31;
        for (int i = 0; ; i++)
        {
            if (i >= PeLimits.MaxImportsPerModule)
            {
                log.Add($"{module}: more than {PeLimits.MaxImportsPerModule} imports; the rest are not read");
                break;
            }
            if (all.Count >= PeLimits.MaxImports)
            {
                if (all.Count == PeLimits.MaxImports) log.Add($"more than {PeLimits.MaxImports} imports; the rest are not read");
                break;
            }
            if (!budget.Step()) break;
            long entryRva = thunks + (long)i * size;
            if (!TryPointer(entryRva, out ulong entry))
            {
                log.Add($"{module}: thunk table runs out of the mapped image at RVA 0x{entryRva:X} without a terminator", RvaToOffsetOrNull(thunks));
                break;
            }
            if (entry == 0) break;
            uint slot = (uint)(iat + (long)i * size);
            NativeImport import;
            if ((entry & ordinalFlag) != 0)
                import = new NativeImport(module, null, (ushort)entry, 0, slot, isDelay);
            else
            {
                ulong target = rvaBased ? entry : entry - (Is64Bit ? ImageBase : (uint)ImageBase);
                if (target > 0x7FFFFFFF)
                {
                    log.Add($"{module}: thunk value 0x{entry:X} at RVA 0x{entryRva:X} is neither an ordinal nor a name RVA", RvaToOffsetOrNull(entryRva));
                    continue;
                }
                if (!TryU16((long)target, out ushort hint))
                {
                    log.Add($"{module}: import name at RVA 0x{target:X} is outside the mapped image", RvaToOffsetOrNull(entryRva));
                    continue;
                }
                var name = ReadName((long)target + 2, budget, log, "import name");
                if (name == null)
                {
                    if (budget.Exhausted) break;
                    log.Add($"{module}: import name at RVA 0x{target + 2:X} is outside the mapped image", RvaToOffsetOrNull(entryRva));
                    continue;
                }
                import = new NativeImport(module, name, null, hint, slot, isDelay);
            }
            functions.Add(import);
            all.Add(import);
        }
        return functions;
    }

    /// <summary>Bound import descriptors, each followed by its forwarder references; offsets are from the table start.</summary>
    private IReadOnlyList<PeBoundImport> ParseBoundImports(IssueLog log)
    {
        var dir = Directory(PeDirectory.BoundImport);
        if (dir.Rva == 0) return [];
        var budget = new WorkBudget(log);
        var result = new List<PeBoundImport>();
        long end = dir.Size != 0 ? (long)dir.Rva + dir.Size : long.MaxValue;
        long at = dir.Rva;
        while (at + 8 <= end)
        {
            if (result.Count >= PeLimits.MaxBoundImports)
            {
                log.Add($"more than {PeLimits.MaxBoundImports} bound import descriptors; the rest are not read");
                break;
            }
            if (!budget.Step()) break;
            var d = ReadBlock(at, 8);
            if (d == null)
            {
                log.Add($"bound import descriptor at RVA 0x{at:X} is outside the mapped image");
                break;
            }
            uint stamp = Le32(d, 0);
            ushort nameOffset = Le16(d, 4), refs = Le16(d, 6);
            if (stamp == 0 && nameOffset == 0 && refs == 0) break;
            string module = ReadName(dir.Rva + nameOffset, budget, log, "bound import name") ?? Unreadable(log, "bound import name", dir.Rva + nameOffset);
            var forwarders = new List<PeBoundForwarder>();
            for (int i = 1; i <= refs; i++)
            {
                if (!budget.Step()) break;
                var f = ReadBlock(at + i * 8L, 8);
                if (f == null) break;
                string fname = ReadName(dir.Rva + Le16(f, 4), budget, log, "bound forwarder name") ?? Unreadable(log, "bound forwarder name", dir.Rva + Le16(f, 4));
                forwarders.Add(new PeBoundForwarder(fname, Le32(f, 0)));
            }
            result.Add(new PeBoundImport(module, stamp, forwarders));
            at += 8L * (1 + refs);
        }
        return result;
    }

    private string Unreadable(IssueLog log, string what, long rva)
    {
        log.Add($"{what} at RVA 0x{rva:X} is outside the mapped image");
        return $"<unreadable 0x{rva:X}>";
    }

    private static uint Le32(byte[] b, int at) => System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(at));
    private static ushort Le16(byte[] b, int at) => System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(at));
    private static ulong Le64(byte[] b, int at) => System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(at));
}
