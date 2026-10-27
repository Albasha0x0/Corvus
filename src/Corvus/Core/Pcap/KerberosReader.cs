namespace Corvus.Core.Pcap;

/// <summary>A Kerberos message's type and the principal and realm names it carries.</summary>
internal sealed record KerberosFacts(long MsgType, List<string> CNames, List<string> SNames, List<string> Realms, List<string> CRealms);

/// <summary>Kerberos 5 messages (RFC 4120) on port 88: names and realms; encrypted parts are not opened.</summary>
internal static class KerberosReader
{
    private const int MaxDepth = 12;

    public static KerberosFacts? Read(ReadOnlySpan<byte> m)
    {
        int at = 0;
        if (!Tlv(m, ref at, out int cls, out _, out int tag, out var body) || cls != 1 || tag is not (10 or 11 or 12 or 13 or 30)) return null;
        var facts = new KerberosFacts(tag, [], [], [], []);
        int inner = 0;
        if (!Tlv(body, ref inner, out _, out _, out int seq, out var fields) || seq != 16) return null;
        if (tag is 10 or 12) Request(fields, facts, 0);
        else if (tag == 30) Error(fields, facts);
        else Reply(fields, facts);
        return facts;
    }

    private static void Request(ReadOnlySpan<byte> fields, KerberosFacts facts, int depth)
    {
        foreach (var (n, v) in Fields(fields))
        {
            // padata: the AP-REQ of a PA-TGS-REQ carries the ticket.
            if (n == 3)
                foreach (var pa in Elements(v))
                {
                    long type = -1;
                    ReadOnlySpan<byte> value = default;
                    foreach (var (pn, pv) in Fields(Sequence(pa)))
                    {
                        if (pn == 1) type = Integer(pv);
                        else if (pn == 2) value = Primitive(pv);
                    }
                    if (type == 1 && depth < MaxDepth) ApRequest(value, facts, depth + 1);
                }
            else if (n == 4) Body(Sequence(v), facts, depth);
        }
    }

    private static void Body(ReadOnlySpan<byte> fields, KerberosFacts facts, int depth)
    {
        foreach (var (n, v) in Fields(fields))
            switch (n)
            {
                case 1: Principal(v, facts.CNames); break;
                case 2: Text(v, facts.Realms); break;
                case 3: Principal(v, facts.SNames); break;
                case 11: foreach (var t in Elements(v)) if (depth < MaxDepth) Ticket(t, facts); break;
            }
    }

    private static void ApRequest(ReadOnlySpan<byte> ap, KerberosFacts facts, int depth)
    {
        int at = 0;
        if (!Tlv(ap, ref at, out int cls, out _, out int tag, out var body) || cls != 1 || tag != 14) return;
        foreach (var (n, v) in Fields(Sequence(body)))
            if (n == 3) Ticket(v, facts);
    }

    private static void Reply(ReadOnlySpan<byte> fields, KerberosFacts facts)
    {
        foreach (var (n, v) in Fields(fields))
            switch (n)
            {
                case 3: Text(v, facts.CRealms); break;
                case 4: Principal(v, facts.CNames); break;
                case 5: Ticket(v, facts); break;
            }
    }

    private static void Error(ReadOnlySpan<byte> fields, KerberosFacts facts)
    {
        foreach (var (n, v) in Fields(fields))
            switch (n)
            {
                case 7: Text(v, facts.CRealms); break;
                case 8: Principal(v, facts.CNames); break;
                case 9: Text(v, facts.Realms); break;
                case 10: Principal(v, facts.SNames); break;
            }
    }

    /// <summary>Ticket ::= [APPLICATION 1] SEQUENCE { tkt-vno [0], realm [1], sname [2], enc-part [3] }.</summary>
    private static void Ticket(ReadOnlySpan<byte> t, KerberosFacts facts)
    {
        int at = 0;
        if (!Tlv(t, ref at, out int cls, out _, out int tag, out var body) || cls != 1 || tag != 1) return;
        foreach (var (n, v) in Fields(Sequence(body)))
            if (n == 1) Text(v, facts.Realms);
            else if (n == 2) Principal(v, facts.SNames);
    }

    /// <summary>PrincipalName ::= SEQUENCE { name-type [0], name-string [1] SEQUENCE OF KerberosString }.</summary>
    private static void Principal(ReadOnlySpan<byte> v, List<string> into)
    {
        foreach (var (n, f) in Fields(Sequence(v)))
            if (n == 1)
                foreach (var s in Elements(f)) into.Add(String(s));
    }

    private static void Text(ReadOnlySpan<byte> v, List<string> into)
    {
        int at = 0;
        if (Tlv(v, ref at, out _, out _, out _, out var content)) into.Add(Printable(content));
    }

    private static string String(ReadOnlySpan<byte> tlv)
    {
        int at = 0;
        return Tlv(tlv, ref at, out _, out _, out _, out var content) ? Printable(content) : "";
    }

    /// <summary>KerberosString is ASCII in practice; other bytes print as '?'.</summary>
    private static string Printable(ReadOnlySpan<byte> b) => CaptureAnalysis.Printable(b);

    private static long Integer(ReadOnlySpan<byte> v)
    {
        int at = 0;
        if (!Tlv(v, ref at, out _, out _, out int tag, out var c) || tag != 2 || c.Length is 0 or > 8) return -1;
        long n = (sbyte)c[0];
        for (int i = 1; i < c.Length; i++) n = n << 8 | c[i];
        return n;
    }

    private static ReadOnlySpan<byte> Primitive(ReadOnlySpan<byte> v)
    {
        int at = 0;
        return Tlv(v, ref at, out _, out _, out _, out var c) ? v.Slice(at - c.Length, c.Length) : default;
    }

    /// <summary>The content of a SEQUENCE at the start of <paramref name="v"/>; empty when it is not one.</summary>
    private static ReadOnlySpan<byte> Sequence(ReadOnlySpan<byte> v)
    {
        int at = 0;
        return Tlv(v, ref at, out int cls, out _, out int tag, out var c) && cls == 0 && tag == 16 ? v.Slice(at - c.Length, c.Length) : default;
    }

    /// <summary>The explicit context-tagged fields of a SEQUENCE's content: (tag number, the inner TLV).</summary>
    private static List<(int Tag, byte[] Value)> Fields(ReadOnlySpan<byte> content)
    {
        var list = new List<(int, byte[])>();
        for (int at = 0; at < content.Length && list.Count < 64;)
        {
            if (!Tlv(content, ref at, out int cls, out _, out int tag, out var inner) || cls != 2) break;
            list.Add((tag, inner.ToArray()));
        }
        return list;
    }

    /// <summary>The elements (whole TLVs) of a SEQUENCE OF at the start of <paramref name="v"/>.</summary>
    private static List<byte[]> Elements(ReadOnlySpan<byte> v)
    {
        var list = new List<byte[]>();
        var content = Sequence(v);
        for (int at = 0; at < content.Length && list.Count < 64;)
        {
            int start = at;
            if (!Tlv(content, ref at, out _, out _, out _, out _)) break;
            list.Add(content[start..at].ToArray());
        }
        return list;
    }

    /// <summary>One definite-length BER element: class (0 universal, 1 application, 2 context), tag number and content.</summary>
    private static bool Tlv(ReadOnlySpan<byte> b, ref int at, out int cls, out bool constructed, out int tag, out ReadOnlySpan<byte> content)
    {
        cls = tag = 0;
        constructed = false;
        content = default;
        if (at + 2 > b.Length) return false;
        byte first = b[at++];
        cls = first >> 6;
        constructed = (first & 0x20) != 0;
        tag = first & 0x1F;
        if (tag == 0x1F)
        {
            tag = 0;
            for (int i = 0; ; i++)
            {
                if (at >= b.Length || i > 3) return false;
                byte t = b[at++];
                tag = tag << 7 | (t & 0x7F);
                if ((t & 0x80) == 0) break;
            }
        }
        if (at >= b.Length) return false;
        int length = b[at++];
        if (length >= 0x80)
        {
            int bytes = length & 0x7F;
            if (bytes is 0 or > 3 || at + bytes > b.Length) return false;
            length = 0;
            for (int i = 0; i < bytes; i++) length = length << 8 | b[at++];
        }
        if (length > b.Length - at) return false;
        content = b.Slice(at, length);
        at += length;
        return true;
    }
}
