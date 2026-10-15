using System.Globalization;
using Corvus.Core;
using Corvus.Core.WebAssembly;
using Corvus.Native;

namespace Corvus.Services;

/// <summary>The code views of a WebAssembly image: a function's WAT (as wasm2wat writes it) and its lifted pseudocode.</summary>
public static class WasmCodeViews
{
    /// <summary>The function containing <paramref name="rva"/> (its body), or the function import whose entry starts there.</summary>
    public static uint Function(WasmImage w, uint rva)
    {
        if (w.FunctionAt(rva) is { } f) return f;
        var m = w.Module;
        for (uint i = 0; i < m.ImportedFunctions; i++)
            if (m.ImportAt(WasmExternal.Func, i) is { } imp && imp.Offset == rva) return i;
        throw new ToolError(ErrorCode.NotFound, $"0x{rva:X} is in no function body of {Path.GetFileName(w.Path)}.",
            "list_functions gives each function's address (its body's file offset); a name or func_<index> works too");
    }

    /// <summary>One line naming the function: name, index, type, address and size, and where the name came from.</summary>
    public static string Header(WasmImage w, uint index, string comment)
    {
        var m = w.Module;
        var type = m.FunctionType(index);
        string signature = type == null ? "?" : $"({string.Join(", ", type.Params.Select(WasmBinary.TypeName))}) -> ({string.Join(", ", type.Results.Select(WasmBinary.TypeName))})";
        string where = m.BodyOf(index) is { } b ? $"at 0x{b.Start:X}, {b.End - b.Start:N0} bytes" : $"imported from {m.ImportAt(WasmExternal.Func, index)?.Module}";
        return $"{comment} {w.FunctionNames[(int)index]}: function {index.ToString(CultureInfo.InvariantCulture)}, type {m.FunctionTypeIndex(index)} {signature}, {where}" +
               $" (name from {w.NameSources[(int)index]})\n";
    }

    /// <summary>The function's text exactly as in wasm2wat's module output, with a header comment.</summary>
    public static string Text(WasmImage w, uint index)
    {
        if (WatWriter.Function(w.Module, index) is not { } text)
            throw new ToolError(ErrorCode.Unsupported, $"{Path.GetFileName(w.Path)} holds {w.Module.Unsupported}, which the text writer does not model.");
        return Header(w, index, ";;") + text;
    }

    /// <summary>The function's lifted pseudocode with a header comment; an import gives its declaration.</summary>
    public static string Lifted(WasmImage w, uint index)
    {
        var m = w.Module;
        if (index < m.ImportedFunctions)
            return Header(w, index, "//") + "// imported: the host implements it (the JS import object)\n";
        var text = WasmDecompiler.Function(m, index, i => i < w.FunctionNames.Count ? w.FunctionNames[(int)i] : $"func_{i}", w.Memory)
                   ?? throw new ToolError(ErrorCode.NotFound, $"function {index} has no body.");
        return Header(w, index, "//") + text;
    }
}
