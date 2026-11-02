namespace Corvus.Native.Dump.Rebuild;

/// <summary>Reads a module's pages from process memory into a mapped-layout buffer.</summary>
public static class CapturedImageReader
{
    /// <summary>The captured image of <paramref name="target"/>, missing pages zero; null when its headers are not captured.</summary>
    public static CapturedImage? Read(IProcessMemory memory, RebuildTarget target, CancellationToken ct)
    {
        var head = new byte[0x1000];
        if (memory.ReadMemory(target.Base, head) < 0x200 || !DumpImages.TryHeader(head, out _, out uint sizeOfImage, out _)) return null;
        uint size = (uint)Math.Min(target.Size != 0 ? target.Size : sizeOfImage, ModuleRebuild.MaxImageBytes);
        size = (size + 0xFFF) & ~0xFFFu;
        var image = new byte[size];
        var captured = new bool[size / 0x1000];
        for (uint page = 0; page < size; page += 0x1000)
        {
            ct.ThrowIfCancellationRequested();
            captured[page / 0x1000] = memory.ReadMemory(target.Base + page, image.AsSpan((int)page, 0x1000)) == 0x1000;
        }
        return new CapturedImage(target, image, captured, "mapped");
    }
}
