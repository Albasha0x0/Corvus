namespace NetDecompilerMcp.Native.Msvc;

/// <summary>How much of a demangled name is printed.</summary>
public enum MsvcNameStyle
{
    /// <summary>Access, storage class, types, calling convention and parameters: "public: virtual int __cdecl A::f(char const *)".</summary>
    Full,
    /// <summary>The qualified name only: "A::f".</summary>
    NameOnly,
}

public enum MsvcSymbolKind
{
    /// <summary>Not a decorated name (or one that could not be decoded).</summary>
    None,
    Function,
    /// <summary>Adjustor, vtordisp and vcall thunks.</summary>
    Thunk,
    Variable,
    /// <summary>`vftable', `vbtable', `local vftable', `RTTI Complete Object Locator'.</summary>
    SpecialTable,
    RttiTypeDescriptor,
    RttiBaseClassDescriptor,
    RttiBaseClassArray,
    RttiClassHierarchyDescriptor,
    StringLiteral,
    LocalStaticGuard,
    /// <summary>"??@hash@": a name too long for the scheme, replaced by its MD5; not reversible.</summary>
    Md5Hash,
    /// <summary>A type as stored in an RTTI type descriptor (".?AVname@@").</summary>
    TypeName,
    /// <summary>A C function with an x86 calling convention decoration (_f@8, @f@8, f@@8, _f).</summary>
    CFunction,
}

public sealed record MsvcDemangleOptions
{
    public static readonly MsvcDemangleOptions Default = new();

    public MsvcNameStyle Style { get; init; } = MsvcNameStyle.Full;

    /// <summary>Print ??_C@ string literals as their (possibly truncated) text instead of "`string'".</summary>
    public bool DecodeStringLiterals { get; init; } = true;

    /// <summary>Print the __ptr64 qualifier on pointers and member functions of 64-bit names, as DbgHelp does.</summary>
    public bool Ptr64 { get; init; }

    /// <summary>The name comes from an x86 image: a plain leading underscore is the __cdecl decoration.</summary>
    public bool X86 { get; init; }
}

/// <summary>
/// Outcome of <see cref="MsvcDemangler.Demangle"/>: <see cref="Text"/> is null when the name could not be decoded and
/// <see cref="Error"/> says why (with <see cref="ErrorOffset"/> into <see cref="Input"/> when known).
/// </summary>
public sealed record MsvcDemangleResult(string Input, string? Text, MsvcSymbolKind Kind, string? Error = null, int ErrorOffset = -1)
{
    public bool Success => Text != null;

    /// <summary>C decorations: the calling convention the decoration implies.</summary>
    public string? CallingConvention { get; init; }

    /// <summary>C decorations: the byte count after '@' (stack argument size).</summary>
    public int? ArgumentBytes { get; init; }

    /// <summary>The name was an import thunk pointer ("__imp_" prefix).</summary>
    public bool IsImport { get; init; }
}

/// <summary>
/// Microsoft C++ name undecorator. Never throws: undecodable input yields a result with <see cref="MsvcDemangleResult.Error"/>.
/// Input length, nesting depth and output length are capped.
/// </summary>
public static class MsvcDemangler
{
    public const int MaxInputLength = 32 * 1024;
    public const int MaxDepth = 200;
    public const int MaxOutputLength = 64 * 1024;

    /// <summary>The demangled text, or null when <paramref name="name"/> is not a decodable decorated name.</summary>
    public static string? Undecorate(string? name, MsvcNameStyle style = MsvcNameStyle.Full) =>
        Demangle(name, style == MsvcNameStyle.Full ? MsvcDemangleOptions.Default : new MsvcDemangleOptions { Style = style }).Text;

    public static MsvcDemangleResult Demangle(string? name, MsvcDemangleOptions? options = null)
    {
        options ??= MsvcDemangleOptions.Default;
        if (string.IsNullOrEmpty(name))
            return new MsvcDemangleResult(name ?? "", null, MsvcSymbolKind.None, "empty name");
        if (name.Length > MaxInputLength)
            return new MsvcDemangleResult(name, null, MsvcSymbolKind.None, $"name longer than {MaxInputLength} characters");
        bool import = false;
        string body = name;
        if (body.StartsWith("__imp_", StringComparison.Ordinal))
        {
            import = true;
            body = body[6..];
        }
        if (body.Length == 0)
            return new MsvcDemangleResult(name, null, MsvcSymbolKind.None, "empty name after __imp_");
        if (body[0] is '?' or '.')
            return DemangleCpp(name, body, import, options);
        return DemangleC(name, body, import, options);
    }

    /// <summary>
    /// The type in an RTTI type descriptor name (".?AVA@@" / ".?AUB@n@@"): the full form ("class A") and the bare
    /// qualified name ("A"); null when the name does not decode.
    /// </summary>
    public static (string Type, string Name)? DemangleTypeDescriptorName(string? name)
    {
        if (string.IsNullOrEmpty(name) || name[0] != '.' || name.Length > MaxInputLength) return null;
        try
        {
            var parser = new MsvcParser(name);
            if (parser.ParseSymbol() is not VariableSymbol { Type: { } type } || !parser.AtEnd) return null;
            var full = type.Render();
            var bare = type is TagType tag ? tag.Name.Render() : full;
            return (full, bare);
        }
        catch (MangledNameException) { return null; }
        catch (Exception ex) when (ex is ArgumentException or IndexOutOfRangeException or InvalidCastException or NullReferenceException or InvalidOperationException)
        {
            return null;
        }
    }

    private static MsvcDemangleResult DemangleCpp(string input, string body, bool import, MsvcDemangleOptions options)
    {
        var parser = new MsvcParser(body);
        int offset = input.Length - body.Length;
        try
        {
            var symbol = parser.ParseSymbol();
            if (!parser.AtEnd)
                return new MsvcDemangleResult(input, null, MsvcSymbolKind.None, "trailing characters after the symbol", parser.Position + offset);
            var p = new Printer(MaxOutputLength, options.DecodeStringLiterals, options.Ptr64, options.Style == MsvcNameStyle.NameOnly);
            if (import && options.Style == MsvcNameStyle.Full)
                p.Append("__declspec(dllimport) ");
            if (options.Style == MsvcNameStyle.NameOnly)
                symbol.OutputName(p);
            else
                symbol.Output(p);
            return new MsvcDemangleResult(input, p.ToString(), symbol.Kind) { IsImport = import };
        }
        catch (MangledNameException ex)
        {
            return new MsvcDemangleResult(input, null, MsvcSymbolKind.None, ex.Message, ex.Offset < 0 ? -1 : ex.Offset + offset);
        }
        catch (Exception ex) when (ex is ArgumentException or IndexOutOfRangeException or InvalidCastException or NullReferenceException or InvalidOperationException)
        {
            // Defensive: a parser bug must not escape; tests sweep for this message.
            return new MsvcDemangleResult(input, null, MsvcSymbolKind.None, "internal error: " + ex.GetType().Name + ": " + ex.Message, parser.Position + offset);
        }
    }

    /// <summary>
    /// x86 C decorations: "_f@8" __stdcall, "@f@8" __fastcall, "f@@8" __vectorcall, and with <see cref="MsvcDemangleOptions.X86"/>
    /// "_f" __cdecl. Anything else is reported as not decorated.
    /// </summary>
    private static MsvcDemangleResult DemangleC(string input, string body, bool import, MsvcDemangleOptions options)
    {
        string? conv = null;
        string? core = null;
        int? bytes = null;
        int at = body.LastIndexOf('@');
        if (at > 0 && at < body.Length - 1 && IsDigits(body.AsSpan(at + 1)) && body.Length - at - 1 <= 5)
        {
            bytes = int.Parse(body.AsSpan(at + 1), System.Globalization.CultureInfo.InvariantCulture);
            if (body[0] == '@' && at > 1) { conv = "__fastcall"; core = body[1..at]; }
            else if (body[0] == '_' && at > 1) { conv = "__stdcall"; core = body[1..at]; }
            else if (at > 1 && body[at - 1] == '@') { conv = "__vectorcall"; core = body[..(at - 1)]; }
        }
        else if (options.X86 && body.Length > 1 && body[0] == '_' && body.IndexOf('@') < 0)
        {
            conv = "__cdecl";
            core = body[1..];
        }
        if (conv == null || string.IsNullOrEmpty(core) || !IsCName(core))
            return new MsvcDemangleResult(input, null, MsvcSymbolKind.None, "not an MSVC decorated name");
        var text = options.Style == MsvcNameStyle.Full ? $"{(import ? "__declspec(dllimport) " : "")}{conv} {core}" : core;
        return new MsvcDemangleResult(input, text, MsvcSymbolKind.CFunction) { CallingConvention = conv, ArgumentBytes = bytes, IsImport = import };
    }

    private static bool IsDigits(ReadOnlySpan<char> s)
    {
        foreach (var c in s) if (!char.IsAsciiDigit(c)) return false;
        return s.Length > 0;
    }

    private static bool IsCName(string s)
    {
        foreach (var c in s)
            if (!(char.IsAsciiLetterOrDigit(c) || c is '_' or '$' or '.')) return false;
        return true;
    }
}
