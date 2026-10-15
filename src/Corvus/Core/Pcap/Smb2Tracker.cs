using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Pcap;

/// <summary>SMB2 messages of one TCP segment: commands, the share (tree) and file names they act on, NTLMSSP account names.</summary>
internal sealed record Smb2Facts(List<long> Commands, List<string> Trees, List<string> Files, List<string> Users, List<string> Domains, List<string> Hosts);

/// <summary>
/// SMB2 over TCP 445 (NetBIOS session framing, compounded messages): tree paths from TREE_CONNECT, file names from CREATE,
/// both carried to later messages by tree id, file id and message id as Wireshark does; NTLMSSP AUTHENTICATE names in
/// SESSION_SETUP. Messages are read from the segment that starts them.
/// </summary>
internal sealed class Smb2Tracker
{
    private const int MaxConnections = 10_000, MaxNames = 100_000;

    private sealed class Connection
    {
        public readonly Dictionary<ulong, string> TreePending = [], FilePending = [], ByMessage = [];
        public readonly Dictionary<uint, string> Trees = [];
        public readonly Dictionary<UInt128, string> Files = [];
    }

    private readonly Dictionary<(bool, UInt128, ushort, UInt128, ushort), Connection> _connections = [];

    public void Observe(PacketView v)
    {
        if (!v.Tcp || (v.P.SrcPort != 445 && v.P.DstPort != 445)) return;
        var p = v.Payload;
        if (p.Length < 4 + 64) return;
        bool toServer = v.P.DstPort == 445;
        var key = toServer ? (v.P.V6, v.P.Src, v.P.SrcPort, v.P.Dst, v.P.DstPort) : (v.P.V6, v.P.Dst, v.P.DstPort, v.P.Src, v.P.SrcPort);
        Smb2Facts? facts = null;
        for (int at = 0; at + 4 <= p.Length;)
        {
            if (p[at] != 0) break;
            int length = p[at + 1] << 16 | p[at + 2] << 8 | p[at + 3];
            var message = p.Slice(at + 4, Math.Min(length, p.Length - at - 4));
            at += 4 + length;
            for (int m = 0; m + 64 <= message.Length;)
            {
                var smb = message[m..];
                if (smb[0] != 0xFE || !smb[1..4].SequenceEqual("SMB"u8)) break;
                if (!_connections.TryGetValue(key, out var c))
                {
                    if (_connections.Count >= MaxConnections) return;
                    _connections[key] = c = new Connection();
                }
                facts ??= new Smb2Facts([], [], [], [], [], []);
                uint next = BinaryPrimitives.ReadUInt32LittleEndian(smb[20..]);
                Message(c, next > 0 && next <= smb.Length ? smb[..(int)next] : smb, facts);
                if (next < 64 || next > smb.Length) break;
                m += (int)next;
            }
        }
        v.Smb2 = facts;
    }

    private static void Message(Connection c, ReadOnlySpan<byte> smb, Smb2Facts facts)
    {
        int command = BinaryPrimitives.ReadUInt16LittleEndian(smb[12..]);
        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(smb[16..]);
        bool response = (flags & 1) != 0, async = (flags & 2) != 0;
        ulong messageId = BinaryPrimitives.ReadUInt64LittleEndian(smb[24..]);
        uint treeId = async ? 0 : BinaryPrimitives.ReadUInt32LittleEndian(smb[36..]);
        facts.Commands.Add(command);
        var body = smb[64..];
        if (!response && command == 3 && body.Length >= 8 && Name(smb, BinaryPrimitives.ReadUInt16LittleEndian(body[4..]), BinaryPrimitives.ReadUInt16LittleEndian(body[6..])) is { } path)
        {
            if (c.TreePending.Count < MaxNames) c.TreePending[messageId] = path;
            facts.Trees.Add(path);
        }
        else if (response && command == 3 && c.TreePending.Remove(messageId, out var connected))
        {
            if (c.Trees.Count < MaxNames) c.Trees[treeId] = connected;
            facts.Trees.Add(connected);
        }
        else if (treeId != 0 && c.Trees.TryGetValue(treeId, out var tree)) facts.Trees.Add(tree);

        if (!response && command == 5 && body.Length >= 48 && Name(smb, BinaryPrimitives.ReadUInt16LittleEndian(body[44..]), BinaryPrimitives.ReadUInt16LittleEndian(body[46..])) is { } file)
        {
            if (c.FilePending.Count < MaxNames) c.FilePending[messageId] = file;
            facts.Files.Add(file);
        }
        else if (response && command == 5 && c.FilePending.Remove(messageId, out var created))
        {
            if (body.Length >= 80 && c.Files.Count < MaxNames) c.Files[BinaryPrimitives.ReadUInt128LittleEndian(body[64..])] = created;
            facts.Files.Add(created);
        }
        else if (!response && FileIdOffset(command) is { } offset && body.Length >= offset + 16
                 && c.Files.TryGetValue(BinaryPrimitives.ReadUInt128LittleEndian(body[offset..]), out var named))
        {
            if (c.ByMessage.Count < MaxNames) c.ByMessage[messageId] = named;
            facts.Files.Add(named);
        }
        else if (response && c.ByMessage.Remove(messageId, out var answered)) facts.Files.Add(answered);

        if (!response && command == 1 && body.Length >= 16)
        {
            int offset = BinaryPrimitives.ReadUInt16LittleEndian(body[12..]), length = BinaryPrimitives.ReadUInt16LittleEndian(body[14..]);
            if (offset + length <= smb.Length) Ntlm(smb.Slice(offset, length), facts);
        }
    }

    /// <summary>Where a request's FileId sits in its body (CLOSE, FLUSH, READ, WRITE, LOCK, IOCTL, QUERY_DIRECTORY, CHANGE_NOTIFY, QUERY_INFO, SET_INFO).</summary>
    private static int? FileIdOffset(int command) => command switch
    {
        6 or 7 or 10 or 11 or 14 or 15 => 8,
        8 or 9 or 17 => 16,
        16 => 24,
        _ => null,
    };

    /// <summary>A UTF-16LE name at an offset from the SMB2 header.</summary>
    private static string? Name(ReadOnlySpan<byte> smb, int offset, int length) =>
        length > 0 && length % 2 == 0 && offset >= 64 && offset + length <= smb.Length ? Printable(Encoding.Unicode.GetString(smb.Slice(offset, length))) : null;

    /// <summary>The domain, user and host of an NTLMSSP AUTHENTICATE message inside a security blob (SPNEGO-wrapped or raw).</summary>
    private static void Ntlm(ReadOnlySpan<byte> blob, Smb2Facts facts)
    {
        int at = blob.IndexOf("NTLMSSP\0"u8);
        if (at < 0) return;
        var m = blob[at..];
        if (m.Length < 64 || BinaryPrimitives.ReadUInt32LittleEndian(m[8..]) != 3) return;
        bool unicode = (BinaryPrimitives.ReadUInt32LittleEndian(m[60..]) & 1) != 0;
        if (Field(m, 28, unicode) is { } domain) facts.Domains.Add(domain);
        if (Field(m, 36, unicode) is { } user) facts.Users.Add(user);
        if (Field(m, 44, unicode) is { } host) facts.Hosts.Add(host);
    }

    /// <summary>An NTLMSSP string field: length, max length and offset at <paramref name="f"/>.</summary>
    private static string? Field(ReadOnlySpan<byte> m, int f, bool unicode)
    {
        int length = BinaryPrimitives.ReadUInt16LittleEndian(m[f..]);
        int offset = (int)Math.Min(BinaryPrimitives.ReadUInt32LittleEndian(m[(f + 4)..]), int.MaxValue);
        if (length == 0 || offset > m.Length - length) return null;
        var raw = m.Slice(offset, length);
        return Printable(unicode ? Encoding.Unicode.GetString(raw) : Encoding.Latin1.GetString(raw));
    }

    private static string Printable(string s) => string.Create(s.Length, s, (chars, text) =>
    {
        for (int i = 0; i < text.Length; i++) chars[i] = char.IsControl(text[i]) ? '?' : text[i];
    });
}
