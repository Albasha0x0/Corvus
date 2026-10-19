namespace Corvus.Native.Msvc;

public static partial class MsvcEh
{
    private sealed partial class Run
    {
        private const uint XdataX = 1u << 20, XdataE = 1u << 21;

        /// <summary>
        /// ARM64 .pdata: an entry with .xdata (flag 0) whose X bit is set has a language-specific handler after the
        /// header, its extension word, the epilog scopes (none when E is set) and the unwind code words; its data
        /// follows the handler RVA. Packed unwind data has no handler.
        /// </summary>
        public void Arm64()
        {
            var uses = new List<HandlerUse>();
            int i = 0;
            foreach (var rf in image.RuntimeFunctions)
            {
                if ((++i & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
                uint xdata = rf.UnwindInfoRva;
                if (xdata == 0 || !_r.U32(xdata, out uint header) || (header & XdataX) == 0) continue;
                if (((header >> 18) & 3) != 0) { Reject(rf.BeginRva, "unwind data", $"version {(header >> 18) & 3}"); continue; }
                uint at = xdata + 4;
                uint epilogs = (header >> 22) & 0x1F, words = header >> 27;
                if (epilogs == 0 && words == 0)
                {
                    if (!_r.U32(at, out uint extension)) { Reject(rf.BeginRva, "unwind data", "extension word outside the image"); continue; }
                    epilogs = extension & 0xFFFF;
                    words = (extension >> 16) & 0xFF;
                    at += 4;
                }
                if ((header & XdataE) == 0) at += 4 * epilogs;
                at += 4 * words;
                if (!_r.U32(at, out uint handler)) { Reject(rf.BeginRva, "unwind data", "handler field outside the image"); continue; }
                if (!_r.IsCode(handler)) { Reject(rf.BeginRva, "unwind data", $"language-specific handler {handler:X} is not in executable code"); continue; }
                uses.Add(new HandlerUse(rf, handler, at + 4));
            }
            DecodeUses(uses);
        }

        /// <summary>The import slot an ARM64 import thunk (adrp xN, page; ldr xN, [xN, #off]; br xN) jumps through.</summary>
        private uint? Arm64ImportSlot(uint thunk)
        {
            if (!_r.U32(thunk, out uint adrp) || !_r.U32(thunk + 4, out uint ldr) || !_r.U32(thunk + 8, out uint br)) return null;
            if ((adrp & 0x9F000000) != 0x90000000 || (ldr & 0xFFC00000) != 0xF9400000) return null;
            uint reg = adrp & 31;
            if (((ldr >> 5) & 31) != reg || (ldr & 31) != reg || br != (0xD61F0000 | reg << 5)) return null;
            long page = (long)(((adrp >> 5) & 0x7FFFF) << 2 | (adrp >> 29) & 3) << 43 >> 31;
            return (uint)((thunk & ~0xFFFu) + page + ((ldr >> 10) & 0xFFF) * 8);
        }
    }
}
