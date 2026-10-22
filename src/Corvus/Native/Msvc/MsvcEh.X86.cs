using System.Buffers.Binary;

namespace Corvus.Native.Msvc;

public static partial class MsvcEh
{
    private sealed partial class Run
    {
        /// <summary>Bytes after a function start in which a prologue installs its exception frame.</summary>
        private const uint PrologueWindow = 0x80;
        /// <summary>Bytes from an __ehhandler$ stub's start to its "mov eax, offset FuncInfo".</summary>
        private const uint StubWindow = 0x60;
        private const byte PushImm32 = 0x68, MovEaxImm32 = 0xB8;

        private readonly Dictionary<uint, Decoded?> _fh3x86 = [];

        /// <summary>
        /// x86: finds "push offset x" and "mov eax, offset x" in executable code (at relocations when the image has
        /// them, otherwise by scanning), then decodes the frames prologues install: an __ehhandler$ stub (code that
        /// loads a FuncInfo into eax and jumps to __CxxFrameHandler3), or an SEH3 / SEH4 scope table.
        /// </summary>
        public void X86(IMsvcEhCodeView view)
        {
            var codeRefs = new List<(uint Site, uint Target)>();
            var dataRefs = new List<(uint Site, uint Target)>();
            var funcInfoSites = new SortedDictionary<uint, uint>();
            // read-only data is often merged into the code section of x86 images: tables can be in executable sections
            foreach (var (site, op, target, next) in Sites())
            {
                if (!_r.IsMapped(target)) continue;
                if (op == MovEaxImm32 && next is 0xE9 or 0xEB && IsFuncInfoMagic(target)) funcInfoSites[site] = target;
                else
                {
                    if (_r.IsCode(target)) codeRefs.Add((site, target));
                    if (op == PushImm32) dataRefs.Add((site, target));
                }
            }
            ct.ThrowIfCancellationRequested();

            var stubSites = funcInfoSites.Keys.ToArray();
            var done = new HashSet<uint>();
            foreach (var (site, stub) in codeRefs)
            {
                int k = Array.BinarySearch(stubSites, stub);
                if (k < 0) k = ~k;
                if (k >= stubSites.Length || stubSites[k] - stub > StubWindow) continue;
                if (view.FunctionContaining(site) is not { } parent || site >= stub && site <= stubSites[k]) continue;
                if (site - parent >= PrologueWindow)
                {
                    Reject(site, "__ehhandler$ stub reference", $"0x{site - parent:X} bytes into function {parent:X}, not in its prologue (a function start discovery missed?)");
                    continue;
                }
                if (!done.Add(parent)) continue;
                uint info = funcInfoSites[stubSites[k]];
                if (!_fh3x86.TryGetValue(info, out var d))
                {
                    d = FuncInfo3Uncached(info, is64: false, out var reason);
                    _fh3x86[info] = d;
                    if (d == null) Reject(info, "FuncInfo", reason ?? "does not decode");
                }
                if (d == null) continue;
                var children = new List<MsvcEhChild>(d.Children) { new(stub, MsvcEhChildKind.HandlerStub) };
                AddFrame(new MsvcEhFrame(parent, MsvcEhScheme.Cxx3, stub, null, info, null, false, d.MaxState, d.TryBlocks, d.Unwind, [], [], children));
            }

            int n = 0;
            foreach (var (site, table) in dataRefs)
            {
                if ((++n & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
                if (view.FunctionContaining(site) is not { } parent || site - parent >= PrologueWindow || done.Contains(parent)) continue;
                if (ScopeTable32(table, parent, view) is { } frame && done.Add(parent)) AddFrame(frame);
            }
        }

        private bool IsFuncInfoMagic(uint rva) => _r.U32(rva, out uint magic) && (magic & ~0xFu) == 0x19930520 && (magic & 0xF) <= 2;

        /// <summary>push imm32 / mov eax, imm32 in executable sections whose operand is an address in the image, with the byte after the instruction.</summary>
        private IEnumerable<(uint Site, byte Op, uint Target, byte Next)> Sites()
        {
            long budget = options.MaxScanBytes;
            var relocations = image.RelocationRvas;
            foreach (var section in image.Sections)
            {
                if (!section.IsExecutable || section.MappedSize < 6 || section.Rva >= image.SizeOfImage) continue;
                // Instructions are file bytes: the zero fill past them, or past SizeOfImage, holds none.
                long backed = image.FileBackedLength(section.Rva, Math.Min(section.MappedSize, (long)image.SizeOfImage - section.Rva));
                if (backed < 6) continue;
                int size = (int)Math.Min(backed, Math.Max(0, budget));
                if (size < 6) yield break;
                budget -= size;
                var bytes = _r.Window(section.Rva, size);
                if (_r.HasRelocations)
                {
                    int lo = 0, hi = relocations.Count;
                    while (lo < hi) { int mid = (lo + hi) >>> 1; if (relocations[mid] < section.Rva + 1) lo = mid + 1; else hi = mid; }
                    for (int i = lo; i < relocations.Count; i++)
                    {
                        uint at = relocations[i] - section.Rva;
                        if (at + 5 > bytes.Length) break;
                        byte op = bytes[at - 1];
                        if (op is not (PushImm32 or MovEaxImm32)) continue;
                        if (_r.VaToRva(BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan((int)at)), out uint target))
                            yield return (section.Rva + at - 1, op, target, bytes[at + 4]);
                    }
                }
                else
                {
                    for (int p = 0; p + 6 <= bytes.Length; p++)
                    {
                        if ((p & 0xFFFFF) == 0) ct.ThrowIfCancellationRequested();
                        byte op = bytes[p];
                        if (op is not (PushImm32 or MovEaxImm32)) continue;
                        if (_r.VaToRva(BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(p + 1)), out uint target))
                            yield return (section.Rva + (uint)p, op, target, bytes[p + 5]);
                    }
                }
            }
        }

        /// <summary>
        /// An SEH4 scope table (GS cookie offset, GS XOR offset, EH cookie offset, EH XOR offset, then the records) or
        /// an SEH3 one (records only); each record is (enclosing level, filter, handler) with level -2 / -1 for the
        /// outermost scope. Records are read while they pass the checks (SEH3: at most the try levels the function
        /// stores at [ebp-4] when it stores constants); fewer records than the stored levels is a reject.
        /// </summary>
        private MsvcEhFrame? ScopeTable32(uint table, uint parent, IMsvcEhCodeView view)
        {
            var head = new byte[28];
            if (!_r.Bytes(table, head)) return null;
            int gs = BinaryPrimitives.ReadInt32LittleEndian(head), gsXor = BinaryPrimitives.ReadInt32LittleEndian(head.AsSpan(4));
            int eh = BinaryPrimitives.ReadInt32LittleEndian(head.AsSpan(8)), ehXor = BinaryPrimitives.ReadInt32LittleEndian(head.AsSpan(12));
            static bool Small(int v) => v > -0x100000 && v < 0x100000;
            MsvcEhScheme scheme;
            uint records;
            int top;
            if (Small(gs) && Small(gsXor) && Small(eh) && Small(ehXor) && BinaryPrimitives.ReadInt32LittleEndian(head.AsSpan(16)) == -2)
            {
                scheme = MsvcEhScheme.Seh4;
                records = table + 16;
                top = -2;
            }
            else if (BinaryPrimitives.ReadInt32LittleEndian(head) == -1)
            {
                scheme = MsvcEhScheme.Seh3;
                records = table;
                top = -1;
            }
            else return null;
            // the first record must point at code before the table counts as one
            if (!_r.Pointer32(records + 8, out uint firstHandler) || !_r.IsCode(firstHandler)) return null;

            // SEH4: records end where a pointer field is not a relocated code address (the next table's header never
            // is); SEH3 tables have no header, so the next table's records look valid: stop at the stored levels
            int levels = TryLevels(view.RangesOf(parent));
            int max = scheme == MsvcEhScheme.Seh3 && levels > 0 ? levels : options.MaxScopes;
            var scopes = new List<MsvcEhScope>();
            var children = new List<MsvcEhChild>();
            for (int i = 0; i < max; i++)
            {
                uint at = records + (uint)i * 12;
                string? why = null;
                if (!_r.I32(at, out int level)) why = "runs out of the image";
                else if (level != top && (level < 0 || level >= i)) why = $"encloses level {level}";
                uint filter = 0, handler = 0;
                if (why == null && (!_r.Pointer32(at + 4, out filter) || filter != 0 && !_r.IsCode(filter))) why = "filter is not in executable code";
                if (why == null && (!_r.Pointer32(at + 8, out handler) || !_r.IsCode(handler))) why = "handler is not in executable code";
                if (why != null)
                {
                    if (i < levels) { Reject(table, $"{scheme} scope table of {parent:X}", $"record {i} of {levels} {why}"); return null; }
                    break;
                }
                scopes.Add(new MsvcEhScope(i, null, null, level, filter != 0 ? filter : null, null, handler, filter == 0));
                if (filter != 0) children.Add(new MsvcEhChild(filter, MsvcEhChildKind.Filter));
                children.Add(new MsvcEhChild(handler, filter != 0 ? MsvcEhChildKind.ExceptBlock : MsvcEhChildKind.Finally));
            }
            if (scopes.Count == 0) return null;
            int? cookie = scheme == MsvcEhScheme.Seh4 && gs != -2 ? gs : null;
            return new MsvcEhFrame(parent, scheme, 0, null, table, cookie, false, 0, [], [], [], scopes, children);
        }

        /// <summary>
        /// Number of try levels a function enters: the highest constant stored at [ebp-4] ("mov dword ptr [ebp-4], n",
        /// "and dword ptr [ebp-4], 0") plus one; 0 when it stores none.
        /// </summary>
        private int TryLevels(IReadOnlyList<(uint Start, uint End)> ranges)
        {
            int max = -1;
            foreach (var (start, end) in ranges)
            {
                if (end <= start || end - start > 1 << 20) continue;
                var bytes = _r.Window(start, (int)(end - start) + 3);
                for (int p = 0; p + 4 <= bytes.Length && p < end - start; p++)
                {
                    if (bytes[p + 1] != 0x65 && bytes[p + 1] != 0x45 || bytes[p + 2] != 0xFC) continue;
                    if (bytes[p] == 0xC7 && bytes[p + 1] == 0x45 && p + 7 <= bytes.Length)
                    {
                        int level = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(p + 3));
                        if (level >= 0 && level < options.MaxScopes) max = Math.Max(max, level);
                    }
                    else if (bytes[p] == 0x83 && bytes[p + 1] == 0x65 && bytes[p + 3] == 0) max = Math.Max(max, 0);
                }
            }
            return max + 1;
        }
    }
}
