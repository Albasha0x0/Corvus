using Corvus.Native.Pe;

namespace Corvus.Native;

/// <summary>A part of an image parsed on first use; a parser exception becomes an "internal error" issue and the fallback.</summary>
internal sealed class ImageArea<T>(string name, Func<IssueLog, T> parse, T fallback)
{
    private readonly Lock gate = new();
    private volatile bool done;
    private T value = default!;
    private IReadOnlyList<ParseIssue> issues = [];

    public T Value
    {
        get
        {
            if (!done) Run();
            return value;
        }
    }

    public IReadOnlyList<ParseIssue> Issues
    {
        get
        {
            if (!done) Run();
            return issues;
        }
    }

    private void Run()
    {
        lock (gate)
        {
            if (done) return;
            var log = new IssueLog(name);
            try { value = parse(log); }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                value = fallback;
                log.Add($"internal error: {ex.GetType().Name}: {ex.Message}");
            }
            issues = log.ToList();
            done = true;
        }
    }
}

/// <summary>Values the loader writes into the image, applied over the file bytes on read.</summary>
internal sealed class FixupOverlay
{
    private readonly uint[] rvas;
    private readonly ulong[] values;
    private readonly byte[] widths;
    private readonly bool bigEndian;

    public static readonly FixupOverlay Empty = new([], false);

    /// <summary><paramref name="fixups"/> may be unsorted and repeat a location; the last value given for it wins.</summary>
    public FixupOverlay(List<(uint Rva, ulong Value, byte Width)> fixups, bool bigEndian)
    {
        var order = new int[fixups.Count];
        for (int i = 0; i < order.Length; i++) order[i] = i;
        Array.Sort(order, (a, b) => fixups[a].Rva != fixups[b].Rva ? fixups[a].Rva.CompareTo(fixups[b].Rva) : a.CompareTo(b));
        var r = new List<uint>(order.Length);
        var v = new List<ulong>(order.Length);
        var w = new List<byte>(order.Length);
        foreach (int i in order)
        {
            var f = fixups[i];
            if (r.Count > 0 && r[^1] == f.Rva) { v[^1] = f.Value; w[^1] = f.Width; continue; }
            r.Add(f.Rva);
            v.Add(f.Value);
            w.Add(f.Width);
        }
        rvas = [.. r];
        values = [.. v];
        widths = [.. w];
        this.bigEndian = bigEndian;
    }

    public int Count => rvas.Length;

    /// <summary>Overwrites the parts of <paramref name="destination"/> (read at <paramref name="rva"/>) that fixups cover.</summary>
    public void Apply(uint rva, Span<byte> destination)
    {
        if (rvas.Length == 0 || destination.IsEmpty) return;
        long end = (long)rva + destination.Length;
        int i = Array.BinarySearch(rvas, (uint)Math.Max(0, (long)rva - 7));
        if (i < 0) i = ~i;
        Span<byte> word = stackalloc byte[8];
        for (; i < rvas.Length && rvas[i] < end; i++)
        {
            int width = widths[i];
            if ((long)rvas[i] + width <= rva) continue;
            ByteView.Put(word, values[i], width, bigEndian);
            long offset = (long)rvas[i] - rva;
            for (int b = 0; b < width; b++)
            {
                long at = offset + b;
                if (at >= 0 && at < destination.Length) destination[(int)at] = word[b];
            }
        }
    }
}
