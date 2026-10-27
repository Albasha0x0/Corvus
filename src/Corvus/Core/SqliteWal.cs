using System.Buffers.Binary;

namespace Corvus.Core;

/// <summary>A -wal frame; CommitPages is 0 for a non-commit frame; State is applied, superseded, uncommitted or stale.</summary>
/// <remarks>Stale frames lie past a salt or checksum break, left by an earlier WAL generation.</remarks>
public sealed record SqliteWalFrame(int Index, long Page, long CommitPages, string State);

/// <summary>A SQLite write-ahead log read as SQLite reads it; frames past the last commit are kept, marked.</summary>
public sealed class SqliteWalLog
{
    public const int MaxFrames = 1_000_000;

    public int PageSize { get; private init; }
    public uint CheckpointSequence { get; private init; }
    public uint Salt1 { get; private init; }
    public uint Salt2 { get; private init; }
    /// <summary>False when the header checksum fails: SQLite ignores the whole log.</summary>
    public bool HeaderValid { get; private set; }
    public List<SqliteWalFrame> Frames { get; } = [];
    /// <summary>Frames in the committed prefix of the valid chain.</summary>
    public int Committed { get; private set; }
    public int Commits { get; private set; }
    /// <summary>The database's page count as of the last commit.</summary>
    public long DatabasePages { get; private set; }
    /// <summary>Each page's latest committed copy: page number to the offset of its data in the log.</summary>
    public Dictionary<long, long> Latest { get; } = [];
    public List<string> Issues { get; } = [];

    private const uint MagicLittle = 0x377f0682, MagicBig = 0x377f0683;

    /// <summary>The offset of frame <paramref name="index"/>'s page data.</summary>
    public long DataOffset(int index) => 32 + index * (24L + PageSize) + 24;

    /// <summary>The log, or null without the WAL magic.</summary>
    public static SqliteWalLog? Read(SqliteSource wal, CancellationToken ct = default)
    {
        var h = new byte[32];
        if (wal.Read(0, h) < 32) return null;
        uint magic = BinaryPrimitives.ReadUInt32BigEndian(h);
        if (magic is not (MagicLittle or MagicBig)) return null;
        bool big = magic == MagicBig;
        int pageSize = (int)BinaryPrimitives.ReadUInt32BigEndian(h.AsSpan(8));
        var log = new SqliteWalLog
        {
            PageSize = pageSize, CheckpointSequence = BinaryPrimitives.ReadUInt32BigEndian(h.AsSpan(12)),
            Salt1 = BinaryPrimitives.ReadUInt32BigEndian(h.AsSpan(16)), Salt2 = BinaryPrimitives.ReadUInt32BigEndian(h.AsSpan(20)),
        };
        if (pageSize < 512 || pageSize > 65536 || (pageSize & (pageSize - 1)) != 0)
        {
            log.Issues.Add($"page size {pageSize} is not a power of two from 512 to 65536");
            return log;
        }
        if (BinaryPrimitives.ReadUInt32BigEndian(h.AsSpan(4)) != 3007000) log.Issues.Add("unknown WAL format version");
        var (s0, s1) = Checksum(h.AsSpan(0, 24), 0, 0, big);
        log.HeaderValid = s0 == BinaryPrimitives.ReadUInt32BigEndian(h.AsSpan(24)) && s1 == BinaryPrimitives.ReadUInt32BigEndian(h.AsSpan(28));
        if (!log.HeaderValid) log.Issues.Add("header checksum fails: SQLite ignores this log");

        long frameSize = 24L + pageSize, count = (wal.Length - 32) / frameSize;
        if (count > MaxFrames) { log.Issues.Add($"frames: the first {MaxFrames:N0} of {count:N0} read"); count = MaxFrames; }
        if ((wal.Length - 32) % frameSize != 0) log.Issues.Add("the log ends inside a frame (a write in progress or a truncated copy)");
        var frame = new byte[frameSize];
        bool chain = log.HeaderValid;
        var pages = new long[count];
        var commits = new long[count];
        var valid = new bool[count];
        int lastCommit = -1;
        for (int i = 0; i < count; i++)
        {
            ct.ThrowIfCancellationRequested();
            if (wal.Read(32 + i * frameSize, frame) < frameSize) break;
            pages[i] = BinaryPrimitives.ReadUInt32BigEndian(frame);
            commits[i] = BinaryPrimitives.ReadUInt32BigEndian(frame.AsSpan(4));
            if (chain)
            {
                bool salts = BinaryPrimitives.ReadUInt32BigEndian(frame.AsSpan(8)) == log.Salt1 && BinaryPrimitives.ReadUInt32BigEndian(frame.AsSpan(12)) == log.Salt2;
                (s0, s1) = Checksum(frame.AsSpan(0, 8), s0, s1, big);
                (s0, s1) = Checksum(frame.AsSpan(24), s0, s1, big);
                chain = salts && pages[i] != 0 && s0 == BinaryPrimitives.ReadUInt32BigEndian(frame.AsSpan(16)) && s1 == BinaryPrimitives.ReadUInt32BigEndian(frame.AsSpan(20));
            }
            valid[i] = chain;
            if (chain && commits[i] != 0)
            {
                lastCommit = i;
                log.Commits++;
                log.DatabasePages = commits[i];
            }
        }
        log.Committed = lastCommit + 1;
        for (int i = 0; i < log.Committed; i++) log.Latest[pages[i]] = log.DataOffset(i);
        for (int i = 0; i < count; i++)
        {
            string state = i < log.Committed ? (log.Latest[pages[i]] == log.DataOffset(i) ? "applied" : "superseded") : valid[i] ? "uncommitted" : "stale";
            log.Frames.Add(new SqliteWalFrame(i, pages[i], commits[i], state));
        }
        return log;
    }

    /// <summary>The WAL checksum: 32-bit words in the log's byte order, summed in pairs.</summary>
    private static (uint, uint) Checksum(ReadOnlySpan<byte> data, uint s0, uint s1, bool big)
    {
        for (int i = 0; i + 8 <= data.Length; i += 8)
        {
            uint x0 = big ? BinaryPrimitives.ReadUInt32BigEndian(data[i..]) : BinaryPrimitives.ReadUInt32LittleEndian(data[i..]);
            uint x1 = big ? BinaryPrimitives.ReadUInt32BigEndian(data[(i + 4)..]) : BinaryPrimitives.ReadUInt32LittleEndian(data[(i + 4)..]);
            unchecked
            {
                s0 += x0 + s1;
                s1 += x1 + s0;
            }
        }
        return (s0, s1);
    }
}
