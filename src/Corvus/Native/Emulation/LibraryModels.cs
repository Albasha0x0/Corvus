namespace Corvus.Native.Emulation;

/// <summary>
/// Built-in models of memcpy, memset and strlen, run in place of a call to a
/// routine of that name, including one defined in the image.
/// </summary>
internal static class LibraryModels
{
    /// <summary>Most bytes one modelled call copies, fills or measures.</summary>
    public const int MaxBytes = 1 << 20;

    /// <summary>
    /// The model for a callee name, or null when none is built in. Accepts
    /// "lib!" and "__imp_" prefixes, "_" and "j_" prefixes, and "@plt".
    /// </summary>
    public static string? Find(string? name)
    {
        if (name == null) return null;
        var label = name[(name.IndexOf('!') + 1)..];
        if (label.EndsWith("@plt", StringComparison.Ordinal)) label = label[..^4];
        if (label.StartsWith("__imp_", StringComparison.Ordinal)) label = label[6..];
        if (label.StartsWith("j_", StringComparison.Ordinal)) label = label[2..];
        if (label.StartsWith('_')) label = label[1..];
        return label.ToLowerInvariant() switch
        {
            "memcpy" => "memcpy",
            "memset" => "memset",
            "strlen" => "strlen",
            _ => null,
        };
    }

    /// <summary>
    /// Runs the model at a call and returns the value for the return register.
    /// An unmapped read throws <see cref="EmulatorFaultException"/> naming the
    /// first unreadable address. A size above <see cref="MaxBytes"/> throws
    /// <see cref="EmulatorUnsupportedException"/>.
    /// </summary>
    public static ulong Run(string model, IEmulatorCpu cpu, EmulatorMemory memory)
    {
        var slots = cpu.Arguments(model == "strlen" ? 1 : 3);
        ulong Arg(int i) => slots[i].Register is { } reg && cpu.TryGet(reg, out var v) ? v
            : memory.ReadUInt(cpu.Sp + (ulong)slots[i].StackOffset, cpu.PointerSize);
        ulong Count(ulong n)
        {
            n &= cpu.PointerSize == 4 ? 0xFFFFFFFF : ulong.MaxValue;
            return n <= MaxBytes ? n : throw new EmulatorUnsupportedException($"{model} of {n:N0} bytes exceeds the {MaxBytes:N0} the emulator models");
        }
        switch (model)
        {
            case "memcpy":
                {
                    ulong dst = Arg(0), src = Arg(1), n = Count(Arg(2));
                    var bytes = new byte[(int)n];
                    memory.Read(src, bytes);
                    memory.Write(dst, bytes);
                    return dst;
                }
            case "memset":
                {
                    ulong dst = Arg(0), n = Count(Arg(2));
                    var bytes = new byte[(int)n];
                    Array.Fill(bytes, (byte)Arg(1));
                    memory.Write(dst, bytes);
                    return dst;
                }
            default:
                {
                    ulong s = Arg(0), length = 0;
                    var chunk = new byte[256];
                    while (true)
                    {
                        // Stay inside one page; fall back to a byte when a region ends mid-page.
                        int want = (int)Math.Min((ulong)chunk.Length, 4096 - ((s + length) & 0xFFF));
                        int got = want;
                        try { memory.Read(s + length, chunk.AsSpan(0, want)); }
                        catch (EmulatorFaultException) when (want > 1) { got = 1; memory.Read(s + length, chunk.AsSpan(0, 1)); }
                        int zero = Array.IndexOf(chunk, (byte)0, 0, got);
                        if (zero >= 0) return length + (ulong)zero;
                        length += (ulong)got;
                        if (length > MaxBytes) throw new EmulatorUnsupportedException($"strlen found no terminator within {MaxBytes:N0} bytes");
                    }
                }
        }
    }
}
