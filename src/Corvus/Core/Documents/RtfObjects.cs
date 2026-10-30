using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Documents;

/// <summary>Reads the OLE objects and template targets of a Rich Text Format document; nothing is run.</summary>
internal static class RtfObjects
{
    private enum Mode { None, Hex, Text }

    private sealed class Open
    {
        public int Depth;
        public bool Update;
        public string Class = "";
        public StringBuilder Hex = new();
        public bool BadHex;
    }

    /// <summary>True when <paramref name="b"/> starts with the RTF signature.</summary>
    public static bool Looks(ReadOnlySpan<byte> b) => b.Length >= 6 && b.StartsWith("{\\rtf"u8);

    /// <summary>Adds the objects, classes, remote templates and notes of an RTF document to <paramref name="doc"/>; malformed parts are noted.</summary>
    public static void Read(byte[] data, OfficeDocument doc, CancellationToken ct)
    {
        var stack = new List<Open>();
        var text = new StringBuilder();
        var mode = Mode.None;
        string target = "";
        int depth = 0, modeDepth = 0, n = 0;
        for (int i = 0; i < data.Length; i++)
        {
            if ((i & 0xFFFF) == 0) ct.ThrowIfCancellationRequested();
            char c = (char)data[i];
            if (c == '{') { depth++; continue; }
            if (c == '}')
            {
                depth--;
                if (mode != Mode.None && depth < modeDepth) EndMode();
                if (stack.Count > 0 && depth < stack[^1].Depth) { Finish(stack[^1]); stack.RemoveAt(stack.Count - 1); }
                continue;
            }
            if (c == '\\')
            {
                int start = ++i;
                if (i >= data.Length) break;
                if (!char.IsAsciiLetter((char)data[i]))
                {
                    if (data[i] == '\'') i += 2;
                    else if (mode == Mode.Text && data[i] is (byte)'\\' or (byte)'{' or (byte)'}') text.Append((char)data[i]);
                    continue;
                }
                while (i < data.Length && char.IsAsciiLetter((char)data[i])) i++;
                var word = Encoding.ASCII.GetString(data, start, i - start);
                int param = 0;
                bool hasParam = false, negative = false;
                if (i < data.Length && data[i] == '-') { negative = true; i++; }
                while (i < data.Length && char.IsAsciiDigit((char)data[i]) && param < 100_000_000) { param = param * 10 + data[i] - '0'; hasParam = true; i++; }
                if (negative) param = -param;
                // One space after a control word belongs to it.
                if (i < data.Length && data[i] == ' ') i++;
                i--;
                switch (word)
                {
                    case "object": stack.Add(new Open { Depth = depth }); break;
                    case "objupdate": if (stack.Count > 0) stack[^1].Update = true; break;
                    case "objclass" when stack.Count > 0: BeginText("class"); break;
                    case "template": BeginText("template"); break;
                    case "objdata" when stack.Count > 0: mode = Mode.Hex; modeDepth = depth; break;
                    case "bin" when hasParam && param > 0:
                        if (mode == Mode.Hex && stack.Count > 0) stack[^1].BadHex = true;
                        i = (int)Math.Min((long)data.Length, (long)i + 1 + param) - 1;
                        break;
                }
                continue;
            }
            if (mode == Mode.Hex)
            {
                if (stack.Count == 0) continue;
                if (Uri.IsHexDigit(c)) stack[^1].Hex.Append(c);
                else if (c is not ('\r' or '\n' or ' ' or '\t')) stack[^1].BadHex = true;
            }
            else if (mode == Mode.Text && c is not ('\r' or '\n')) text.Append(c);
        }
        while (stack.Count > 0) { Finish(stack[^1]); stack.RemoveAt(stack.Count - 1); }
        return;

        void BeginText(string what) { mode = Mode.Text; modeDepth = depth; target = what; text.Clear(); }

        void EndMode()
        {
            var value = text.ToString().Trim();
            if (mode == Mode.Text && target == "class" && stack.Count > 0) stack[^1].Class = value;
            else if (mode == Mode.Text && target == "template" && IsRemote(value)) doc.Links.Add(new ExternalLink("rtf", "template", value));
            mode = Mode.None;
        }

        void Finish(Open o)
        {
            n++;
            var path = $"object {n}";
            if (o.Update) doc.Notes.Add($"{path}: \\objupdate refreshes the object when the document opens");
            if (o.BadHex) doc.Notes.Add($"{path}: objdata holds bytes that are not hexadecimal text; its content is partial");
            if (o.Hex.Length % 2 != 0) { doc.Notes.Add($"{path}: objdata has an odd number of hexadecimal digits; the last digit is dropped"); o.Hex.Length--; }
            var declared = OleClasses.FromProgId(o.Class);
            if (o.Hex.Length == 0)
            {
                AddClass(path, declared?.Name ?? o.Class, declared?.Active == true);
                return;
            }
            var bytes = Convert.FromHexString(o.Hex.ToString());
            if (!Header(bytes, out var progId, out var topic, out var native, out var linked))
            {
                doc.Notes.Add($"{path}: objdata is not an OLE 1.0 object header; its content is unknown");
                AddClass(path, declared?.Name ?? o.Class, declared?.Active == true);
                return;
            }
            var cls = OleClasses.FromProgId(progId) ?? declared;
            if (linked)
            {
                if (topic.Length > 0) doc.Links.Add(new ExternalLink("rtf " + path, "objautlink", topic));
            }
            else if (native is { Length: > 0 })
            {
                if (CompoundFile.Looks(native))
                {
                    try
                    {
                        var cf = CompoundFile.Read(native, path);
                        cls ??= OleClasses.FromClsid(cf.RootClsid);
                        doc.ReadCompound(cf, path + "/", ct);
                    }
                    catch (ToolError ex) when (ex.Code is ErrorCode.MalformedInput or ErrorCode.LimitExceeded) { doc.Notes.Add($"{path}: {ex.Message}"); }
                }
                else if (cls?.ProgId == "Package")
                {
                    if (OfficeDocument.Ole10Native([.. BitConverter.GetBytes(native.Length), .. native]) is { } package) doc.Objects.Add(package with { Path = path });
                    else doc.Notes.Add($"{path}: not a readable OLE Package");
                }
                else doc.Objects.Add(new EmbeddedObject(path, $"object_{n}.bin", null, native));
            }
            AddClass(path, cls?.Name ?? (progId.Length > 0 ? progId : o.Class), cls?.Active == true);
        }

        void AddClass(string path, string name, bool active)
        {
            if (name.Length > 0) doc.Classes.Add(new OleObjectClass(path, name, active));
        }
    }

    private static bool IsRemote(string target) => target.Contains("://", StringComparison.Ordinal) || target.StartsWith(@"\\", StringComparison.Ordinal) || target.StartsWith("//", StringComparison.Ordinal);

    /// <summary>Reads an OLE 1.0 embedded or linked object header (MS-OLEDS); false when it is damaged.</summary>
    private static bool Header(byte[] b, out string progId, out string topic, out byte[]? native, out bool linked)
    {
        progId = topic = "";
        native = null;
        linked = false;
        int at = 0;
        if (b.Length < 12) return false;
        at += 4;
        uint format = BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(at));
        at += 4;
        if (format is not (1 or 2)) return false;
        linked = format == 1;
        string ignored;
        if (!Lp(out progId) || !Lp(out topic) || !Lp(out ignored)) return false;
        if (linked) return true;
        if (at + 4 > b.Length) return false;
        uint size = BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(at));
        at += 4;
        if (size > b.Length - at) return false;
        native = b.AsSpan(at, (int)size).ToArray();
        return true;

        bool Lp(out string s)
        {
            s = "";
            if (at + 4 > b.Length) return false;
            uint len = BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(at));
            at += 4;
            if (len > b.Length - at) return false;
            s = len == 0 ? "" : Encoding.Latin1.GetString(b, at, (int)len).TrimEnd('\0');
            at += (int)len;
            return true;
        }
    }
}
