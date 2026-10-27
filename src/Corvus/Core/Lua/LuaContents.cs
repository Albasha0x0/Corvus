using System.Text;

namespace Corvus.Core.Lua;

/// <summary>A Lua or LuaJIT chunk as a container: one entry per function, listing.txt and strings.txt.</summary>
public static class LuaContents
{
    public static ContainerContents Open(byte[] data, string name)
    {
        bool jit = LuaJitBytecode.Looks(data);
        LuaChunk chunk;
        IReadOnlyList<LuaFunction> functions;
        try
        {
            if (jit) (chunk, functions) = LuaJitBytecode.Read(data);
            else
            {
                chunk = LuaBytecode.Read(data);
                var all = new List<LuaFunction>();
                Walk(chunk.Main, all);
                functions = all;
            }
        }
        catch (InvalidDataException ex) { throw new ToolError(ErrorCode.MalformedInput, $"{name}: not a readable {(jit ? "LuaJIT" : "Lua")} chunk: {ex.Message}"); }

        var listing = new StringBuilder();
        var strings = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var entries = new List<ContainerEntry>();
        int index = 0;
        foreach (var f in functions)
        {
            index++;
            string header = Header(chunk, f);
            string counts = Counts(f, jit);
            entries.Add(new ContainerEntry($"functions/{index:D4} {(f == chunk.Main ? "main" : "function")} {Display(f.Source)}:{f.Line}-{f.LastLine}", 4L * f.Code.Length, counts));
            listing.Append(header).Append('\n').Append(counts).Append('\n');
            for (int pc = 0; pc < f.Code.Length; pc++)
            {
                string text = jit ? LuaJitBytecode.Instruction(chunk.Version, f.Code[pc]) : LuaBytecode.Instruction(chunk.Version, f.Code[pc]);
                listing.Append('\t').Append(pc + 1).Append('\t');
                if (f.Lines != null && pc < f.Lines.Length) listing.Append('[').Append(f.Lines[pc]).Append("]\t");
                listing.Append(text).Append('\n');
            }
            if (f.Constants.Count > 0)
            {
                listing.Append("constants (").Append(f.Constants.Count).Append(")\n");
                for (int k = 0; k < f.Constants.Count; k++)
                {
                    var c = f.Constants[k];
                    listing.Append('\t').Append(k).Append('\t').Append(c.Type).Append('\t').Append(c.Text).Append('\n');
                    if (c.Bytes != null && seen.Add(c.Text)) strings.Add(Encoding.UTF8.GetString(c.Bytes));
                }
            }
            listing.Append('\n');
        }
        int instructions = functions.Sum(f => f.Code.Length), constants = functions.Sum(f => f.Constants.Count);
        var notes = new List<string>
        {
            $"{(jit ? chunk.Version : "Lua " + chunk.Version)} bytecode ({chunk.Layout}): {functions.Count:N0} function(s), {instructions:N0} instruction(s), " +
            $"{constants:N0} constant(s), {strings.Count:N0} distinct string(s)" + (chunk.Stripped ? "; debug information stripped (no source names, lines or locals)." : $"; source {Display(chunk.Main.Source)}."),
        };
        var items = new List<ExtractedItem>
        {
            new("listing.txt", Encoding.UTF8.GetBytes(listing.ToString()), $"{(jit ? chunk.Version : "Lua " + chunk.Version)} listing"),
            new("strings.txt", Encoding.UTF8.GetBytes(string.Join('\n', strings)), "string constants"),
        };
        return new ContainerContents(jit ? LuaJitBytecode.Kind : LuaBytecode.Kind, items, notes) { Entries = entries };
    }

    private static void Walk(LuaFunction f, List<LuaFunction> all)
    {
        all.Add(f);
        foreach (var c in f.Children) Walk(c, all);
    }

    /// <summary>A function's first listing line, as luac -l prints it without the address.</summary>
    public static string Header(LuaChunk chunk, LuaFunction f) =>
        $"{(f == chunk.Main ? "main" : "function")} <{Display(f.Source)}:{f.Line},{f.LastLine}> ({f.Code.Length} instruction{(f.Code.Length == 1 ? "" : "s")})";

    /// <summary>A function's second listing line, as luac -l prints it; LuaJIT dumps give no local count.</summary>
    public static string Counts(LuaFunction f, bool jit) =>
        $"{f.Params}{(f.Vararg ? "+" : "")} param{S(f.Params)}, {f.Slots} slot{S(f.Slots)}, {f.Upvalues} upvalue{S(f.Upvalues)}, " +
        (jit ? "" : $"{f.Locals} local{S(f.Locals)}, ") + $"{f.Constants.Count} constant{S(f.Constants.Count)}, {f.Children.Count} function{S(f.Children.Count)}";

    private static string S(int n) => n == 1 ? "" : "s";

    /// <summary>A source name as luac shows it: '@' and '=' prefixes dropped, other text as "(string)".</summary>
    public static string Display(string source) =>
        source.Length > 0 && source[0] is '@' or '=' ? source[1..] : source.StartsWith('') ? "(bstring)" : "(string)";
}
