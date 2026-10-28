using System.Globalization;
using System.Text;

namespace Corvus.Core.Python;

/// <summary>Python 2.7 and 3.0 to 3.14 bytecode as that version's dis.dis prints it; nothing is run.</summary>
/// <remarks>Nested code objects follow their parent; an index past a table prints as such instead of failing.</remarks>
public static class PyDisassembler
{
    private const int OpNameWidth = 20, OpArgWidth = 5;

    private readonly record struct Instruction(int Offset, int Op, long? Arg);

    private sealed record ExceptionEntry(int Start, int End, int Target, int Depth, bool LastI);

    public static bool Supports((int Major, int Minor) version) => PyOpcodes.For(version) != null;

    /// <summary>The disassembly of <paramref name="code"/> and the code objects in its constants, up to about <paramref name="maxChars"/> characters.</summary>
    public static string Disassemble(PyCode code, (int Major, int Minor) version, int maxChars, CancellationToken ct, out bool complete)
    {
        var table = PyOpcodes.For(version) ?? throw new ToolError(ErrorCode.Unsupported, $"Python {PyVersion.Label(version)} bytecode is not disassembled (2.7 and 3.0 to 3.14 are).");
        var sb = new StringBuilder();
        complete = Recursive(sb, code, table, maxChars, ct);
        return sb.ToString();
    }

    /// <summary>The names IMPORT_NAME loads in <paramref name="code"/> and its nested code objects, in order of first use.</summary>
    public static List<string> Imports(PyCode code, (int Major, int Minor) version)
    {
        var found = new List<string>();
        if (PyOpcodes.For(version) is not { } table) return found;
        int import = table.Op("IMPORT_NAME");
        // Shared code objects repeat per path: 100,000 visits at most.
        int visits = 0;
        void Walk(PyCode c, int depth)
        {
            if (++visits > 100_000) return;
            foreach (var i in Unpack(c.Code, table))
                if (i.Op == import && i.Arg is { } a && a >= 0 && a < c.Names.Length && PyMarshal.Str(c.Names[a]) is { Length: > 0 } name && !found.Contains(name))
                    found.Add(name);
            if (depth < 64)
                foreach (var nested in c.Consts.OfType<PyCode>()) Walk(nested, depth + 1);
        }
        Walk(code, 0);
        return found;
    }

    /// <summary>Module-level names bound to string constants, first binding kept; empty when the opcodes are unknown.</summary>
    public static Dictionary<string, string> ModuleStrings(PyCode code, (int Major, int Minor) version)
    {
        var found = new Dictionary<string, string>(StringComparer.Ordinal);
        if (PyOpcodes.For(version) is not { } table) return found;
        int load = table.Op("LOAD_CONST"), store = table.Op("STORE_NAME");
        var ops = Unpack(code.Code, table);
        for (int i = 0; i + 1 < ops.Count; i++)
            if (ops[i].Op == load && ops[i + 1].Op == store && ops[i].Arg is { } c && c >= 0 && c < code.Consts.Length && code.Consts[c] is string or PyBytes
                && ops[i + 1].Arg is { } n && n >= 0 && n < code.Names.Length && PyMarshal.Str(code.Names[n]) is { Length: > 0 } name)
                found.TryAdd(name, PyMarshal.Str(code.Consts[c]));
        return found;
    }

    private static bool Recursive(StringBuilder sb, PyCode code, PyOpcodes table, int maxChars, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (!PyVersion.AtLeast(table.Version, 3, 4)) Python2(sb, code, table);
        else if (PyVersion.AtLeast(table.Version, 3, 13)) Python313(sb, code, table);
        else Python3(sb, code, table);
        foreach (var nested in code.Consts.OfType<PyCode>())
        {
            if (sb.Length > maxChars) return false;
            sb.Append("\nDisassembly of ").Append(PyRepr.Of(nested, table.Version)).Append(":\n");
            if (!Recursive(sb, nested, table, maxChars, ct)) return false;
        }
        return sb.Length <= maxChars;
    }

    // Reading the instructions.

    private static List<Instruction> Unpack(byte[] code, PyOpcodes t)
    {
        var list = new List<Instruction>();
        int extendedOp = t.Op("EXTENDED_ARG");
        if (!PyVersion.AtLeast(t.Version, 3, 6))
        {
            // One byte, then a two-byte argument from HAVE_ARGUMENT up; EXTENDED_ARG supplies the high 16 bits.
            long extended = 0;
            for (int i = 0; i < code.Length;)
            {
                int offset = i, op = code[i++];
                long? arg = null;
                if (op >= t.HaveArgument)
                {
                    if (i + 1 >= code.Length) { list.Add(new(offset, op, null)); break; }
                    arg = code[i] | code[i + 1] << 8;
                    arg += extended;
                    extended = 0;
                    i += 2;
                    if (op == extendedOp) extended = arg.Value * 65536;
                }
                list.Add(new(offset, op, arg));
            }
            return list;
        }
        // Wordcode: an opcode and an argument byte; 3.11+ follows some opcodes with inline cache entries.
        long ext = 0;
        int caches = 0;
        bool v311 = PyVersion.AtLeast(t.Version, 3, 11);
        for (int i = 0; i + 1 < code.Length; i += 2)
        {
            if (caches > 0) { caches--; continue; }
            int op = code[i];
            if (v311) caches = t.Caches(op);
            if (t.HasArgument(op))
            {
                long arg = code[i + 1] | ext;
                ext = op == extendedOp ? unchecked(arg << 8) : 0;
                // The C int the interpreter keeps.
                if (v311 && ext >= 1L << 31) ext -= 1L << 32;
                list.Add(new(i, op, arg));
            }
            else
            {
                if (PyVersion.AtLeast(t.Version, 3, 10)) ext = 0;
                list.Add(new(i, op, null));
            }
        }
        return list;
    }

    /// <summary>A jump's target offset, as that version's dis computes it; null for other opcodes.</summary>
    private static long? Target(PyOpcodes t, Instruction i, bool rawArgument = false)
    {
        if (i.Arg is not { } arg) return null;
        var v = t.Version;
        if (!PyVersion.AtLeast(v, 3, 6))
        {
            // The label scan reads the bare two-byte argument; the listing adds EXTENDED_ARG.
            if (rawArgument) arg &= 0xFFFF;
            return t.Is(i.Op, PyOpcodes.Kinds.JumpRelative) ? i.Offset + 3 + arg : t.Is(i.Op, PyOpcodes.Kinds.JumpAbsolute) ? arg : null;
        }
        if (!PyVersion.AtLeast(v, 3, 10))
            return t.Is(i.Op, PyOpcodes.Kinds.JumpRelative) ? i.Offset + 2 + arg : t.Is(i.Op, PyOpcodes.Kinds.JumpAbsolute) ? arg : null;
        if (t.Is(i.Op, PyOpcodes.Kinds.JumpRelative))
        {
            long signed = t.Is(i.Op, PyOpcodes.Kinds.Backward) ? -arg : arg;
            return i.Offset + 2 + signed * 2 + (PyVersion.AtLeast(v, 3, 12) ? 2 * t.Caches(i.Op) : 0);
        }
        return t.Is(i.Op, PyOpcodes.Kinds.JumpAbsolute) ? arg * 2 : null;
    }

    private static List<long> Labels(PyOpcodes t, List<Instruction> code)
    {
        var labels = new List<long>();
        foreach (var i in code)
            if (Target(t, i, rawArgument: true) is { } target && !labels.Contains(target)) labels.Add(target);
        return labels;
    }

    // Line numbers.

    /// <summary>findlinestarts: (offset, line) where a source line starts; a null line (3.13) marks code without one.</summary>
    private static List<(int Offset, int? Line)> LineStarts(PyCode c, PyOpcodes t)
    {
        var v = t.Version;
        var starts = new List<(int, int?)>();
        if (!PyVersion.AtLeast(v, 3, 10))
        {
            // co_lnotab: (bytecode increment, line increment) pairs; line increments are signed from 3.6.
            int? last = null;
            int line = c.FirstLineNo, addr = 0;
            var tab = c.LineTable;
            for (int k = 0; k + 1 < tab.Length; k += 2)
            {
                int byteIncrement = tab[k], lineIncrement = tab[k + 1];
                if (byteIncrement != 0)
                {
                    if (line != last) { starts.Add((addr, line)); last = line; }
                    addr += byteIncrement;
                    if (PyVersion.AtLeast(v, 3, 8) && addr >= c.Code.Length) return starts;
                }
                if (PyVersion.AtLeast(v, 3, 6) && lineIncrement >= 0x80) lineIncrement -= 0x100;
                line += lineIncrement;
            }
            if (line != last) starts.Add((addr, line));
            return starts;
        }
        bool v313 = PyVersion.AtLeast(v, 3, 13);
        bool first = true;
        int? lastLine = null;
        foreach (var (start, line) in Lines(c, v))
        {
            if (v313)
            {
                // co_lines merges ranges of one line; 3.13 keeps every range, those without a line too.
                if (first || line != lastLine) starts.Add((start, line));
                first = false;
                lastLine = line;
            }
            else if (line != null && line != lastLine)
            {
                starts.Add((start, line));
                lastLine = line;
            }
        }
        return starts;
    }

    /// <summary>co_lines(): the start offset and line of each address range, from the 3.10 line table or the 3.11+ location table.</summary>
    private static IEnumerable<(int Start, int? Line)> Lines(PyCode c, (int Major, int Minor) v)
    {
        var tab = c.LineTable;
        int end = 0, computed = c.FirstLineNo;
        if (!PyVersion.AtLeast(v, 3, 11))
        {
            for (int k = 0; k + 1 < tab.Length;)
            {
                int start = end;
                int? line = null;
                // Empty ranges are skipped; their line increments still count.
                do
                {
                    start = end;
                    end += tab[k];
                    int delta = (sbyte)tab[k + 1];
                    k += 2;
                    if (delta == -128) line = null;
                    else { computed += delta; line = computed; }
                } while (start == end && k + 1 < tab.Length);
                if (start != end) yield return (start, line);
            }
            yield break;
        }
        for (int k = 0; k < tab.Length;)
        {
            int b = tab[k], kind = (b >> 3) & 15;
            computed += kind switch
            {
                13 or 14 => SignedVarint(tab, k + 1),
                11 => 1,
                12 => 2,
                _ => 0,
            };
            int start = end;
            end += ((b & 7) + 1) * 2;
            do k++; while (k < tab.Length && (tab[k] & 0x80) == 0);
            yield return (start, b >> 3 == 0x1F ? null : computed);
        }
    }

    private static int SignedVarint(byte[] tab, int k)
    {
        uint value = 0;
        int shift = 0;
        while (k < tab.Length)
        {
            int read = tab[k++];
            value |= (uint)(read & 63) << shift;
            shift += 6;
            if ((read & 64) == 0 || shift > 30) break;
        }
        return (value & 1) != 0 ? -(int)(value >> 1) : (int)(value >> 1);
    }

    private static List<ExceptionEntry> ExceptionTable(byte[] tab)
    {
        var entries = new List<ExceptionEntry>();
        int k = 0;
        bool Next(out int value)
        {
            value = 0;
            if (k >= tab.Length) return false;
            int b = tab[k++];
            value = b & 63;
            while ((b & 64) != 0)
            {
                if (k >= tab.Length) return false;
                b = tab[k++];
                value = value << 6 | b & 63;
            }
            return true;
        }
        while (Next(out int start) && Next(out int length) && Next(out int target) && Next(out int depthLasti))
            entries.Add(new(start * 2, start * 2 + length * 2, target * 2, depthLasti >> 1, (depthLasti & 1) != 0));
        return entries;
    }

    // Argument details.

    private static string Item(object[] items, long index, Func<object, string> show) =>
        index >= 0 && index < items.Length ? show(items[index]) : $"<index {index} out of range>";

    private static string Name(object[] items, long index) => Item(items, index, PyMarshal.Str);

    private static readonly string[] Conversions = ["", "str", "repr", "ascii"];
    private static readonly string[] FunctionFlags = ["defaults", "kwdefaults", "annotations", "closure", "annotate"];
    private static readonly string[] CommonConstants = ["AssertionError", "NotImplementedError", "tuple", "<built-in function all>", "<built-in function any>"];
    private static readonly string[] SpecialMethods = ["__enter__", "__exit__", "__aenter__", "__aexit__"];

    /// <summary>The function attributes set by <paramref name="arg"/>; "annotate" is new in 3.14.</summary>
    private static string Flags(long arg, (int, int) v) =>
        string.Join(", ", FunctionFlags.Take(PyVersion.AtLeast(v, 3, 14) ? 5 : 4).Where((_, k) => (arg & 1 << k) != 0));

    /// <summary>The argument detail dis prints in parentheses (3.0 to 3.12).</summary>
    private static string ArgRepr(PyOpcodes t, PyCode c, Instruction i)
    {
        if (i.Arg is not { } arg) return "";
        var v = t.Version;
        int op = i.Op;
        string name = t.Name(op);
        bool v311 = PyVersion.AtLeast(v, 3, 11), v312 = PyVersion.AtLeast(v, 3, 12);
        if (t.Is(op, PyOpcodes.Kinds.Const))
            return v311 && !v312 && name != "LOAD_CONST" ? "" : Item(c.Consts, arg, o => PyRepr.Of(o, v));
        if (t.Is(op, PyOpcodes.Kinds.Name))
        {
            if (v311 && name == "LOAD_GLOBAL") return ((arg & 1) != 0 ? "NULL + " : "") + Name(c.Names, arg >> 1);
            if (v312 && name == "LOAD_ATTR") return ((arg & 1) != 0 ? "NULL|self + " : "") + Name(c.Names, arg >> 1);
            if (v312 && name == "LOAD_SUPER_ATTR") return ((arg & 1) != 0 ? "NULL|self + " : "") + Name(c.Names, arg >> 2);
            return Name(c.Names, arg);
        }
        if (PyVersion.AtLeast(v, 3, 10) && t.Is(op, PyOpcodes.Kinds.JumpAbsolute)) return "to " + Target(t, i);
        if (t.Is(op, PyOpcodes.Kinds.JumpRelative)) return "to " + Target(t, i);
        if (t.Is(op, PyOpcodes.Kinds.Local) || v311 && t.Is(op, PyOpcodes.Kinds.Free))
            return Name(v311 ? c.LocalsPlusNames : c.VarNames, arg);
        if (t.Is(op, PyOpcodes.Kinds.Compare)) return Item([.. t.CompareOps], v312 ? arg >> 4 : arg, o => (string)o);
        if (t.Is(op, PyOpcodes.Kinds.Free)) return Name([.. c.CellVars, .. c.FreeVars], arg);
        if (name == "FORMAT_VALUE" && PyVersion.AtLeast(v, 3, 6))
        {
            var conversion = Conversions[arg & 3];
            return (arg & 4) != 0 ? conversion + (conversion.Length > 0 ? ", " : "") + "with format" : conversion;
        }
        if (name == "MAKE_FUNCTION" && PyVersion.AtLeast(v, 3, 8)) return Flags(arg, v);
        if (CountsArguments(t, op)) return Arguments(arg);
        if (name == "BINARY_OP" && v311) return Item([.. t.BinaryOps], arg, o => (string)o);
        if (name == "CALL_INTRINSIC_1") return Item([.. t.Intrinsic1], arg, o => (string)o);
        if (name == "CALL_INTRINSIC_2") return Item([.. t.Intrinsic2], arg, o => (string)o);
        return "";
    }

    // The listings.

    private static string Int(long n) => n.ToString(CultureInfo.InvariantCulture);

    /// <summary>Python 2.7 to 3.3: print statements joined by single spaces, the padded opcode name kept; 3.x ends the line with a space too.</summary>
    private static void Python2(StringBuilder sb, PyCode c, PyOpcodes t)
    {
        var code = Unpack(c.Code, t);
        var labels = Labels(t, code);
        var starts = new Dictionary<int, int?>();
        foreach (var (offset, line) in LineStarts(c, t)) starts[offset] = line;
        var free = c.CellVars.Concat(c.FreeVars).ToArray();
        foreach (var i in code)
        {
            var fields = new List<string>();
            if (starts.TryGetValue(i.Offset, out var line))
            {
                if (i.Offset > 0) sb.Append('\n');
                fields.Add(string.Format(CultureInfo.InvariantCulture, "{0,3}", line));
            }
            else fields.Add("   ");
            fields.Add("   ");
            fields.Add(labels.Contains(i.Offset) ? ">>" : "  ");
            fields.Add(Int(i.Offset).PadLeft(4));
            fields.Add(t.Name(i.Op).PadRight(OpNameWidth));
            if (i.Arg is { } arg)
            {
                fields.Add(Int(arg).PadLeft(OpArgWidth));
                if (t.Is(i.Op, PyOpcodes.Kinds.Const)) fields.Add("(" + Item(c.Consts, arg, o => PyRepr.Of(o, t.Version)) + ")");
                else if (t.Is(i.Op, PyOpcodes.Kinds.Name)) fields.Add("(" + Name(c.Names, arg) + ")");
                else if (t.Is(i.Op, PyOpcodes.Kinds.JumpRelative)) fields.Add("(to " + Int(i.Offset + 3 + arg) + ")");
                else if (t.Is(i.Op, PyOpcodes.Kinds.Local)) fields.Add("(" + Name(c.VarNames, arg) + ")");
                else if (t.Is(i.Op, PyOpcodes.Kinds.Compare)) fields.Add("(" + Item([.. t.CompareOps], arg, o => (string)o) + ")");
                else if (t.Is(i.Op, PyOpcodes.Kinds.Free)) fields.Add("(" + Name(free, arg) + ")");
                else if (CountsArguments(t, i.Op)) fields.Add("(" + Arguments(arg) + ")");
            }
            sb.Append(string.Join(' ', fields)).Append(t.Version.Major == 3 ? " \n" : "\n");
        }
    }

    /// <summary>3.3 to 3.5 describe a call's two argument bytes (hasnargs).</summary>
    private static bool CountsArguments(PyOpcodes t, int op) =>
        PyVersion.AtLeast(t.Version, 3, 3) && !PyVersion.AtLeast(t.Version, 3, 6) && t.Name(op).StartsWith("CALL_FUNCTION", StringComparison.Ordinal);

    private static string Arguments(long arg) => $"{arg & 0xFF} positional, {arg >> 8 & 0xFF} keyword pair";

    /// <summary>Python 3.4 to 3.12: line, marker, jump target, offset, opcode, argument and detail; 3.11+ adds the exception table.</summary>
    private static void Python3(StringBuilder sb, PyCode c, PyOpcodes t)
    {
        var v = t.Version;
        var code = Unpack(c.Code, t);
        var labels = new HashSet<long>(Labels(t, code));
        var exceptions = PyVersion.AtLeast(v, 3, 11) ? ExceptionTable(c.ExceptionTable) : [];
        foreach (var e in exceptions) labels.Add(e.Target);
        var starts = new Dictionary<int, int>();
        foreach (var (offset, line) in LineStarts(c, t)) starts[offset] = line!.Value;
        bool showLines = PyVersion.AtLeast(v, 3, 10) ? starts.Count > 0 : true;
        int linesWidth = 0;
        // Before 3.7 the line and offset columns have a fixed width.
        bool v37 = PyVersion.AtLeast(v, 3, 7);
        if (showLines && starts.Count > 0 && v37)
        {
            int max = starts.Values.Max();
            linesWidth = max >= 1000 ? Int(max).Length : 3;
        }
        else if (showLines) linesWidth = 3;
        int maxOffset = c.Code.Length - 2;
        int offsetWidth = maxOffset >= 10000 && v37 ? Int(maxOffset).Length : 4;
        foreach (var i in code)
        {
            bool startsLine = starts.TryGetValue(i.Offset, out int line);
            if (showLines && startsLine && i.Offset > 0) sb.Append('\n');
            var fields = new List<string>();
            if (linesWidth > 0) fields.Add(startsLine ? Int(line).PadLeft(linesWidth) : new string(' ', linesWidth));
            fields.Add("   ");
            fields.Add(labels.Contains(i.Offset) ? ">>" : "  ");
            fields.Add(Int(i.Offset).PadLeft(offsetWidth));
            fields.Add(t.Name(i.Op).PadRight(OpNameWidth));
            if (i.Arg is { } arg)
            {
                fields.Add(Int(arg).PadLeft(OpArgWidth));
                if (ArgRepr(t, c, i) is { Length: > 0 } detail) fields.Add("(" + detail + ")");
            }
            sb.Append(string.Join(' ', fields).TrimEnd()).Append('\n');
        }
        if (exceptions.Count > 0)
        {
            sb.Append("ExceptionTable:\n");
            foreach (var e in exceptions)
                sb.Append("  ").Append(e.Start).Append(" to ").Append(e.End - 2).Append(" -> ").Append(e.Target).Append(" [").Append(e.Depth).Append(']')
                    .Append(e.LastI ? " lasti" : "").Append('\n');
        }
    }

    /// <summary>Python 3.13 and 3.14: jump targets and exception ranges as labels L1, L2, ..., no offsets, lines without a source line as "--".</summary>
    private static void Python313(StringBuilder sb, PyCode c, PyOpcodes t)
    {
        var code = Unpack(c.Code, t);
        var exceptions = ExceptionTable(c.ExceptionTable);
        var targets = new SortedSet<long>(Labels(t, code));
        foreach (var e in exceptions) { targets.Add(e.Start); targets.Add(e.End); targets.Add(e.Target); }
        var labels = new Dictionary<long, int>();
        foreach (var offset in targets) labels[offset] = labels.Count + 1;
        int labelWidth = 4 + Int(labels.Count).Length;
        var starts = new Dictionary<int, int?>();
        foreach (var (offset, l) in LineStarts(c, t)) starts[offset] = l;
        int max = starts.Values.Where(l => l is not (null or 0)).Select(l => l!.Value).DefaultIfEmpty(-1).Max();
        int linesWidth = max == -1 ? 0 : Math.Max(3, Int(max).Length);
        if (linesWidth > 0 && linesWidth < 4 && starts.ContainsValue(null)) linesWidth = 4;
        int? lineNumber = null;
        foreach (var i in code)
        {
            bool startsLine = starts.TryGetValue(i.Offset, out var local);
            if (startsLine) lineNumber = local;
            if (linesWidth > 0 && startsLine && i.Offset > 0) sb.Append('\n');
            var fields = new List<string>();
            if (linesWidth > 0)
                fields.Add(!startsLine ? new string(' ', linesWidth) : lineNumber is { } n ? Int(n).PadLeft(linesWidth) : "  --".PadLeft(linesWidth));
            fields.Add(labels.TryGetValue(i.Offset, out int label) ? ("L" + Int(label) + ":").PadLeft(labelWidth) : new string(' ', labelWidth));
            fields.Add("   ");
            var name = t.Name(i.Op);
            fields.Add(name.PadRight(OpNameWidth));
            if (i.Arg is { } arg)
            {
                fields.Add(Int(arg).PadLeft(Math.Max(0, OpArgWidth - Math.Max(0, name.Length - OpNameWidth))));
                if (ArgRepr313(t, c, i, labels) is { Length: > 0 } detail) fields.Add("(" + detail + ")");
            }
            sb.Append(string.Join(' ', fields).TrimEnd()).Append('\n');
        }
        if (exceptions.Count > 0)
        {
            sb.Append("ExceptionTable:\n");
            foreach (var e in exceptions)
                sb.Append("  L").Append(labels[e.Start]).Append(" to L").Append(labels[e.End]).Append(" -> L").Append(labels[e.Target])
                    .Append(" [").Append(e.Depth).Append(']').Append(e.LastI ? " lasti" : "").Append('\n');
        }
    }

    private static string ArgRepr313(PyOpcodes t, PyCode c, Instruction i, Dictionary<long, int> labels)
    {
        long arg = i.Arg!.Value;
        int op = i.Op;
        var name = t.Name(op);
        if (t.Is(op, PyOpcodes.Kinds.Const)) return Item(c.Consts, arg, o => PyRepr.Of(o, t.Version));
        if (t.Is(op, PyOpcodes.Kinds.Name))
            return name switch
            {
                "LOAD_GLOBAL" => Name(c.Names, arg >> 1) + ((arg & 1) != 0 ? " + NULL" : ""),
                "LOAD_ATTR" => Name(c.Names, arg >> 1) + ((arg & 1) != 0 ? " + NULL|self" : ""),
                "LOAD_SUPER_ATTR" => Name(c.Names, arg >> 2) + ((arg & 1) != 0 ? " + NULL|self" : ""),
                _ => Name(c.Names, arg),
            };
        if (t.Is(op, PyOpcodes.Kinds.JumpRelative | PyOpcodes.Kinds.JumpAbsolute))
        {
            var preposition = name == "END_ASYNC_FOR" ? "from " : "to ";
            return Target(t, i) is { } target && labels.TryGetValue(target, out int label) ? preposition + "L" + Int(label) : preposition + Target(t, i);
        }
        if (name is "LOAD_FAST_LOAD_FAST" or "LOAD_FAST_BORROW_LOAD_FAST_BORROW" or "STORE_FAST_LOAD_FAST" or "STORE_FAST_STORE_FAST")
            return Name(c.LocalsPlusNames, arg >> 4) + ", " + Name(c.LocalsPlusNames, arg & 15);
        if (t.Is(op, PyOpcodes.Kinds.Local | PyOpcodes.Kinds.Free)) return Name(c.LocalsPlusNames, arg);
        if (t.Is(op, PyOpcodes.Kinds.Compare))
        {
            var compare = Item([.. t.CompareOps], arg >> 5, o => (string)o);
            return (arg & 16) != 0 ? $"bool({compare})" : compare;
        }
        return name switch
        {
            "CONVERT_VALUE" => Item([.. Conversions], arg, o => (string)o),
            "SET_FUNCTION_ATTRIBUTE" => Flags(arg, t.Version),
            "BINARY_OP" => Item([.. t.BinaryOps], arg, o => (string)o),
            "CALL_INTRINSIC_1" => Item([.. t.Intrinsic1], arg, o => (string)o),
            "CALL_INTRINSIC_2" => Item([.. t.Intrinsic2], arg, o => (string)o),
            "LOAD_COMMON_CONSTANT" => Item([.. CommonConstants], arg, o => (string)o),
            "LOAD_SPECIAL" => Item([.. SpecialMethods], arg, o => (string)o),
            "IS_OP" when PyVersion.AtLeast(t.Version, 3, 14) => arg != 0 ? "is not" : "is",
            "CONTAINS_OP" when PyVersion.AtLeast(t.Version, 3, 14) => arg != 0 ? "not in" : "in",
            _ => "",
        };
    }
}
