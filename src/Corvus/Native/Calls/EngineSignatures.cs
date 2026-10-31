using Corvus.Native.Providers;

namespace Corvus.Native.Calls;

/// <summary>Call signatures taken from an engine's function record.</summary>
public static class EngineSignatures
{
    /// <summary>
    /// Returns the signature of a function the engine typed (names, types,
    /// decoding), or null when the record has no prototype, a default or
    /// guessed one, or a convention the argument locations do not model.
    /// </summary>
    public static ApiSignature? From(EngineFunctionRecord record, NativeArch arch)
    {
        if (string.IsNullOrWhiteSpace(record.Prototype)) return null;
        if (record.SignatureSource?.ToLowerInvariant() is "default" or "guessed") return null;
        var convention = record.CallingConvention ?? "";
        if (convention.Contains("usercall", StringComparison.OrdinalIgnoreCase)
            || convention.Contains("vectorcall", StringComparison.OrdinalIgnoreCase)) return null;
        if (arch == NativeArch.X86
            && (convention.Contains("fastcall", StringComparison.OrdinalIgnoreCase)
                || convention.Contains("thiscall", StringComparison.OrdinalIgnoreCase))) return null;
        var ps = new List<ApiParam>();
        for (int i = 0; i < record.Parameters.Count; i++)
        {
            var p = record.Parameters[i];
            ps.Add(new ApiParam(string.IsNullOrWhiteSpace(p.Name) ? $"arg{i + 1}" : p.Name, TypeOf(p.Type)));
        }
        return new ApiSignature(record.Name, ps, record.VarArgs,
            convention.Contains("cdecl", StringComparison.OrdinalIgnoreCase));
    }

    private static ApiParamType TypeOf(string type)
    {
        var t = type.Replace("const ", "", StringComparison.OrdinalIgnoreCase).Trim();
        var lower = t.ToLowerInvariant();
        var compact = lower.Replace(" ", "");
        if (lower is "lpcwstr" or "lpwstr" or "pcwstr" or "pwstr" || compact is "wchar_t*" or "wchar*") return ApiParamType.WideString;
        if (lower is "lpcstr" or "lpstr" or "pcstr" or "pstr" || compact == "char*") return ApiParamType.AnsiString;
        if (lower.Contains('*') || lower is "lpvoid" or "pvoid" or "lpcvoid") return ApiParamType.Pointer;
        return lower switch
        {
            "handle" or "hwnd" or "hmodule" or "hinstance" => ApiParamType.Handle,
            "bool" or "_bool" or "boolean" => ApiParamType.Bool,
            "float" => ApiParamType.Float,
            "double" => ApiParamType.Double,
            "size_t" or "ssize_t" or "ulong_ptr" or "uintptr_t" => ApiParamType.Size,
            "long long" or "unsigned long long" or "__int64" or "unsigned __int64" or "int64_t" or "uint64_t" or "longlong" or "ulonglong" or "uint64" or "int64"
                => ApiParamType.Int64,
            "unsigned int" or "uint" or "dword" or "ulong" or "unsigned long" or "uint32_t" or "word" or "ushort" or "unsigned short" or "byte" or "uchar" or "unsigned char"
                => ApiParamType.UInt,
            _ => ApiParamType.Int,
        };
    }
}
