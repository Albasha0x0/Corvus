using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using Corvus.Native.Pe;

namespace Corvus.Native.MachO;

/// <summary>
/// A code requirement from the signature's requirement set: its type (designated, host, guest, library, plugin) and its
/// expression in the text form codesign -d -r- prints. Partial when the expression holds an opcode not read here.
/// </summary>
public sealed record CodeRequirement(uint Type, string Text, bool Partial)
{
    public string TypeName => Type switch { 1 => "host", 2 => "guest", 3 => "designated", 4 => "library", 5 => "plugin", _ => $"type {Type}" };

    public override string ToString() => $"{TypeName} => {Text}";
}

/// <summary>Decodes compiled code requirements (Security framework's requirement.h) into their source text.</summary>
public static class CodeRequirements
{
    private const uint SetMagic = 0xFADE0C01, RequirementMagic = 0xFADE0C00;
    private const int MaxDepth = 256, MaxRequirements = 32;

    /// <summary>
    /// The requirements of a requirement set blob (magic included); empty for a set with none. Bad offsets and lengths are
    /// logged and the requirements read before them are kept.
    /// </summary>
    internal static IReadOnlyList<CodeRequirement> Parse(ReadOnlySpan<byte> set, IssueLog log)
    {
        var list = new List<CodeRequirement>();
        if (set.Length < 12 || BinaryPrimitives.ReadUInt32BigEndian(set) != SetMagic) return list;
        uint count = BinaryPrimitives.ReadUInt32BigEndian(set[8..]);
        for (uint i = 0; i < Math.Min(count, MaxRequirements); i++)
        {
            long entry = 12 + 8L * i;
            if (entry + 8 > set.Length) { log.Add($"requirement set entry {i} lies outside the blob"); break; }
            uint type = BinaryPrimitives.ReadUInt32BigEndian(set[(int)entry..]), offset = BinaryPrimitives.ReadUInt32BigEndian(set[(int)(entry + 4)..]);
            if (offset > set.Length - 12L || BinaryPrimitives.ReadUInt32BigEndian(set[(int)offset..]) != RequirementMagic
                || BinaryPrimitives.ReadUInt32BigEndian(set[(int)(offset + 4)..]) is var length && (length < 12 || length > set.Length - offset))
            {
                log.Add($"requirement {i} at +0x{offset:X} is not a requirement blob");
                continue;
            }
            var blob = set.Slice((int)offset, (int)length);
            uint kind = BinaryPrimitives.ReadUInt32BigEndian(blob[8..]);
            if (kind != 1)
            {
                list.Add(new(type, $"/* requirement kind {kind} not read */", true));
                continue;
            }
            var d = new Dumper(blob[12..].ToArray());
            list.Add(new(type, d.Run(), d.Partial));
        }
        return list;
    }

    // Precedence: or binds loosest, then and, then a primary (not, a leaf).
    private enum Level { Or, And, Primary }

    private sealed class Truncated : Exception;

    private sealed class TooDeep : Exception;

    private sealed class Dumper(byte[] code)
    {
        private readonly StringBuilder _sb = new();
        private int _at;

        public bool Partial { get; private set; }

        public string Run()
        {
            try { Expr(Level.Or, 0); }
            catch (TooDeep)
            {
                _sb.Append($" /* nested deeper than {MaxDepth} */");
                Partial = true;
            }
            catch (Truncated)
            {
                _sb.Append(" /* truncated */");
                Partial = true;
            }
            catch (UnknownOpcode e)
            {
                _sb.Append($"/* unknown opcode {e.Code} */");
                Partial = true;
            }
            return _sb.ToString();
        }

        private sealed class UnknownOpcode(uint code) : Exception
        {
            public uint Code => code;
        }

        private uint U32()
        {
            if (_at + 4 > code.Length) throw new Truncated();
            _at += 4;
            return BinaryPrimitives.ReadUInt32BigEndian(code.AsSpan(_at - 4));
        }

        private long I64()
        {
            if (_at + 8 > code.Length) throw new Truncated();
            _at += 8;
            return BinaryPrimitives.ReadInt64BigEndian(code.AsSpan(_at - 8));
        }

        // Data: a length, the bytes, padding to 4.
        private ReadOnlySpan<byte> Data()
        {
            uint n = U32();
            if (n > code.Length - _at) throw new Truncated();
            var s = code.AsSpan(_at, (int)n);
            _at += (int)((n + 3) & ~3u);
            if (_at > code.Length) _at = code.Length;
            return s;
        }

        private void Expr(Level level, int depth)
        {
            if (depth > MaxDepth) throw new TooDeep();
            uint op = U32();
            switch (op & 0x00FFFFFF)
            {
                case 0: _sb.Append("never"); break;
                case 1: _sb.Append("always"); break;
                case 2: _sb.Append("identifier "); Text(Data()); break;
                case 3: _sb.Append("anchor apple"); break;
                case 4: _sb.Append("certificate "); Slot(); _sb.Append(" = "); Hash(Data()); break;
                case 5: _sb.Append("info["); Text(Data(), dotOk: true); _sb.Append("] = "); Text(Data()); break;
                case 6: Binary(level, Level.And, " and ", depth); break;
                case 7: Binary(level, Level.Or, " or ", depth); break;
                case 8: _sb.Append("cdhash "); Hash(Data()); break;
                case 9: _sb.Append("! "); Expr(Level.Primary, depth + 1); break;
                case 10: _sb.Append("info["); Text(Data(), dotOk: true); _sb.Append(']'); Match(); break;
                case 11: _sb.Append("certificate "); Slot(); _sb.Append('['); Text(Data(), dotOk: true); _sb.Append(']'); Match(); break;
                case 12: _sb.Append("certificate "); Slot(); _sb.Append(" trusted"); break;
                case 13: _sb.Append("anchor trusted"); break;
                case 14: Field("field."); break;
                case 15: _sb.Append("anchor apple generic"); break;
                case 16: _sb.Append("entitlement["); Text(Data(), dotOk: true); _sb.Append(']'); Match(); break;
                case 17: Field("policy."); break;
                case 18: _sb.Append("anchor apple "); Text(Data()); break;
                case 19: _sb.Append('('); Text(Data()); _sb.Append(')'); break;
                case 20: _sb.Append("platform = ").Append(U32().ToString(CultureInfo.InvariantCulture)); break;
                case 21: _sb.Append("notarized"); break;
                case 22: Field("timestamp."); break;
                case 23: _sb.Append("legacy"); break;
                default: throw new UnknownOpcode(op);
            }
        }

        private void Binary(Level level, Level own, string word, int depth)
        {
            bool parens = level > own;
            if (parens) _sb.Append('(');
            Expr(own, depth + 1);
            _sb.Append(word);
            Expr(own, depth + 1);
            if (parens) _sb.Append(')');
        }

        // A certificate field named by its OID: certificate leaf[field.1.2.840.113635.100.6.1.13].
        private void Field(string prefix)
        {
            _sb.Append("certificate ");
            Slot();
            _sb.Append('[').Append(prefix);
            var oid = Data();
            if (Oid(oid) is { } dotted) _sb.Append(dotted);
            else _sb.Append("0x").Append(Convert.ToHexStringLower(oid));
            _sb.Append(']');
            Match();
        }

        private void Slot()
        {
            int slot = (int)U32();
            _sb.Append(slot switch { 0 => "leaf", -1 => "root", _ => slot.ToString(CultureInfo.InvariantCulture) });
        }

        private void Hash(ReadOnlySpan<byte> hash) => _sb.Append("H\"").Append(Convert.ToHexStringLower(hash)).Append('"');

        private void Match()
        {
            uint op = U32();
            switch (op)
            {
                case 0: _sb.Append(" /* exists */"); break;
                case 1: _sb.Append(" = "); Text(Data()); break;
                case 2: _sb.Append(" ~ "); Text(Data()); break;
                case 3: _sb.Append(" = "); Text(Data()); _sb.Append('*'); break;
                case 4: _sb.Append(" = *"); Text(Data()); break;
                case 5: _sb.Append(" < "); Text(Data()); break;
                case 6: _sb.Append(" > "); Text(Data()); break;
                case 7: _sb.Append(" <= "); Text(Data()); break;
                case 8: _sb.Append(" >= "); Text(Data()); break;
                case >= 9 and <= 13:
                    _sb.Append(op switch { 9 => " = ", 10 => " < ", 11 => " > ", 12 => " <= ", _ => " >= " });
                    Timestamp(I64());
                    break;
                case 14: _sb.Append(" absent "); break;
                default: throw new UnknownOpcode(op);
            }
        }

        // Seconds since 2001-01-01 UTC, as CFAbsoluteTime counts them.
        private void Timestamp(long seconds)
        {
            var epoch = new DateTime(2001, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            _sb.Append("timestamp \"");
            if (seconds > -60_000_000_000 && seconds < 250_000_000_000) _sb.Append(epoch.AddSeconds(seconds).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)).Append(" +0000");
            else _sb.Append(seconds.ToString(CultureInfo.InvariantCulture));
            _sb.Append('"');
        }

        // Bare when alphanumeric (dots too in field names) and not led by a digit, quoted when printable, else hex.
        private void Text(ReadOnlySpan<byte> s, bool dotOk = false)
        {
            bool simple = s.Length > 0 && !char.IsAsciiDigit((char)s[0]), printable = true;
            foreach (var b in s)
                if (char.IsAsciiLetterOrDigit((char)b) || b == '.' && dotOk) continue;
                else if (b is >= 0x20 and < 0x7F or (byte)'\t' or (byte)'\n' or (byte)'\r') simple = false;
                else { printable = false; break; }
            if (!printable) { _sb.Append("0x").Append(Convert.ToHexStringLower(s)); return; }
            if (simple) { _sb.Append(Encoding.ASCII.GetString(s)); return; }
            _sb.Append('"');
            foreach (var b in s)
            {
                if (b is (byte)'"' or (byte)'\\') _sb.Append('\\');
                _sb.Append((char)b);
            }
            _sb.Append('"');
        }

        /// <summary>Dotted form of a DER OID's content bytes; null when they do not decode.</summary>
        private static string? Oid(ReadOnlySpan<byte> der)
        {
            if (der.Length == 0) return null;
            var parts = new List<ulong>();
            ulong value = 0;
            int bytes = 0;
            foreach (var b in der)
            {
                if (++bytes > 9) return null;
                value = value << 7 | (uint)(b & 0x7F);
                if ((b & 0x80) != 0) continue;
                parts.Add(value);
                (value, bytes) = (0, 0);
            }
            if (bytes != 0) return null;
            ulong first = parts[0];
            var head = first < 40 ? $"0.{first}" : first < 80 ? $"1.{first - 40}" : $"2.{first - 80}";
            return string.Join('.', [head, .. parts.Skip(1).Select(p => p.ToString(CultureInfo.InvariantCulture))]);
        }
    }
}
