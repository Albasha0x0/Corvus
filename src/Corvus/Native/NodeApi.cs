using System.Buffers.Binary;
using System.Text;
using Corvus.Native.Annotations;
using Corvus.Native.Calls;
using Corvus.Native.Code;

namespace Corvus.Native;

/// <summary>
/// Node-API (N-API) registrations of a .node add-on, recovered statically: the JavaScript name each native callback is
/// exposed under. Reads the constant arguments of napi_create_function, napi_define_properties and napi_define_class calls
/// (property descriptor arrays in the image's data) and the napi_module of napi_module_register.
/// </summary>
public static class NodeApi
{
    /// <param name="Function">RVA of the native callback.</param>
    /// <param name="JsName">Property, function or class name; "Class.method" for class members.</param>
    /// <param name="Kind">function, method, getter, setter, constructor or module_init.</param>
    /// <param name="Call">RVA of the registering call.</param>
    public sealed record Registration(uint Function, string JsName, string Kind, string Via, uint Call);

    public sealed record Result(IReadOnlyList<Registration> Registrations, IReadOnlyList<string> Notes);

    private const int MaxDescriptors = 4096, MaxName = 256;
    private const ulong AutoLength = ulong.MaxValue;
    private const uint NapiStatic = 1 << 10;

    /// <summary>An add-on: exports napi_register_module_v1 / node_register_module_v&lt;n&gt;, or imports napi_* functions.</summary>
    public static bool IsAddon(INativeImage image) =>
        image.Exports.Any(e => e.Name is { } n && (Bare(n) == "napi_register_module_v1" || Bare(n).StartsWith("node_register_module_v", StringComparison.Ordinal)))
        || image.Imports.Any(i => i.Name is { } n && Bare(n).StartsWith("napi_", StringComparison.Ordinal));

    /// <summary>Mach-O symbols carry the C underscore.</summary>
    private static string Bare(string name) => name.StartsWith("_napi_", StringComparison.Ordinal) || name.StartsWith("_node_", StringComparison.Ordinal) ? name[1..] : name;

    public static Result Find(NativeCodeIndex index, CancellationToken ct = default)
    {
        var image = index.Image;
        var found = new List<Registration>();
        var notes = new List<string>();
        Func<NativeImport, IEnumerable<CallSiteInfo>>? calls = CallAnalysis.Supports(index) ? i => CallAnalysis.For(index).CallsTo(i, 10_000, ct)
            : Arm64CallSites.Supports(index) ? i => Arm64CallSites.For(index).CallsTo(i, 10_000, ct)
            : Arm32CallSites.Supports(index) ? i => Arm32CallSites.For(index).CallsTo(i, 10_000, ct)
            : null;
        if (calls == null)
        {
            notes.Add($"call arguments are not recovered for {image.Arch}: registrations not read");
            return new Result(found, notes);
        }
        int unresolved = 0;
        foreach (var import in image.Imports)
        {
            if (import.Name is not { } raw) continue;
            var name = Bare(raw);
            if (name is not ("napi_create_function" or "napi_define_properties" or "napi_define_class" or "napi_module_register")) continue;
            foreach (var site in calls(import))
            {
                ct.ThrowIfCancellationRequested();
                int before = found.Count;
                switch (name)
                {
                    case "napi_create_function":
                        if (Text(image, Arg(site, 1), Number(Arg(site, 2))) is { } fn && Target(index, Arg(site, 3)) is { } cb)
                            found.Add(new Registration(cb, fn, "function", name, site.Rva));
                        break;
                    case "napi_define_properties":
                        Descriptors(index, Arg(site, 3), Number(Arg(site, 2)), null, name, site.Rva, found);
                        break;
                    case "napi_define_class":
                        var cls = Text(image, Arg(site, 1), Number(Arg(site, 2)));
                        if (cls != null && Target(index, Arg(site, 3)) is { } ctor) found.Add(new Registration(ctor, cls, "constructor", name, site.Rva));
                        Descriptors(index, Arg(site, 6), Number(Arg(site, 5)), cls ?? "?", name, site.Rva, found);
                        break;
                    case "napi_module_register":
                        Module(index, Arg(site, 0), site.Rva, found);
                        break;
                }
                if (found.Count == before) unresolved++;
            }
        }
        if (CallAnalysis.Supports(index)) Setters(index, CallAnalysis.For(index), found, ct);
        if (unresolved > 0)
            notes.Add($"{unresolved} registering call(s) with arguments not constant in the caller (built at run time, or passed in by a wrapper such as node-addon-api): get_call_arguments shows them");
        return new Result(found, notes);
    }

    /// <summary>
    /// node-addon-api's exports.Set("name", Function::New(env, callback)): a napi_set_named_property (or napi_set_property
    /// after napi_create_string_utf8) whose name is constant; the callback is the last code address passed to a call of the
    /// same function since the previous setter. A pattern, not a table: recorded with kind function and the setter as Via.
    /// </summary>
    private static void Setters(NativeCodeIndex index, CallAnalysis analysis, List<Registration> found, CancellationToken ct)
    {
        var image = index.Image;
        var known = found.Select(r => r.JsName).ToHashSet(StringComparer.Ordinal);
        var callers = new HashSet<NativeFunction>();
        foreach (var import in image.Imports)
            if (import.Name is { } raw && Bare(raw) is "napi_set_named_property" or "napi_set_property")
                foreach (var site in analysis.CallsTo(import, 10_000, ct)) callers.Add(site.Caller);
        foreach (var f in callers)
        {
            ct.ThrowIfCancellationRequested();
            var sites = analysis.CallsIn(f, ct).OrderBy(s => s.Rva).ToList();
            string? pendingName = null;
            uint? callback = null;
            foreach (var s in sites)
            {
                var callee = s.Import?.Name is { } n ? Bare(n) : null;
                switch (callee)
                {
                    case "napi_create_string_utf8" or "napi_create_string_latin1":
                        pendingName = Text(image, Arg(s, 1), Number(Arg(s, 2)));
                        continue;
                    case "napi_set_named_property" or "napi_set_property":
                        var name = callee == "napi_set_named_property" ? Text(image, Arg(s, 2), null) : pendingName;
                        if (name != null && callback is { } cb && known.Add(name)) found.Add(new Registration(cb, name, "function", callee, s.Rva));
                        pendingName = null;
                        callback = null;
                        continue;
                    case not null when callee.StartsWith("napi_", StringComparison.Ordinal):
                        continue;
                }
                foreach (var a in s.Arguments)
                    if (Target(index, a) is { } t && t != f.Start) callback = t;
            }
        }
    }

    private static CallArgument? Arg(CallSiteInfo site, int index) => site.Arguments.FirstOrDefault(a => a.Index == index);

    private static ulong? Number(CallArgument? a) => a is { Kind: ArgKind.Immediate, Value: { } v } ? v : null;

    /// <summary>The code an argument points at: a named function or an address in executable code.</summary>
    private static uint? Target(NativeCodeIndex index, CallArgument? a) =>
        a is { Kind: ArgKind.Name or ArgKind.Address, Rva: { } rva } && IsCode(index.Image, rva) ? rva : null;

    private static bool IsCode(INativeImage image, uint rva) => rva != 0 && image.SectionAt(rva) is { IsExecutable: true };

    /// <summary>The C string an argument points at, cut to <paramref name="length"/> unless that is NAPI_AUTO_LENGTH.</summary>
    private static string? Text(INativeImage image, CallArgument? a, ulong? length)
    {
        if (a is not { Kind: ArgKind.String or ArgKind.Address, Rva: { } rva }) return null;
        var s = CString(image, rva);
        if (s == null) return null;
        if (length is { } n && n != AutoLength && (n & 0xFFFFFFFF) != 0xFFFFFFFF && n < (ulong)s.Length) s = s[..(int)n];
        return s.Length == 0 ? null : s;
    }

    private static string? CString(INativeImage image, uint rva)
    {
        Span<byte> buffer = stackalloc byte[MaxName];
        int n = image.Read(rva, buffer);
        int end = buffer[..n].IndexOf((byte)0);
        if (end <= 0) return null;
        var s = Encoding.UTF8.GetString(buffer[..end]);
        return s.All(c => c >= 0x20) ? s : null;
    }

    private static uint? Pointer(INativeImage image, uint rva)
    {
        Span<byte> b = stackalloc byte[8];
        int size = image.Is64Bit ? 8 : 4;
        if (image.Read(rva, b[..size]) < size) return null;
        ulong va = size == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(b) : BinaryPrimitives.ReadUInt32LittleEndian(b);
        if (va == 0) return 0;
        return va >= image.ImageBase && va - image.ImageBase < image.SizeOfImage ? (uint)(va - image.ImageBase) : null;
    }

    /// <summary>
    /// napi_property_descriptor[count]: utf8name, name, method, getter, setter, value, attributes, data (pointer-sized fields).
    /// Entries named by a napi_value instead of utf8name are skipped.
    /// </summary>
    private static void Descriptors(NativeCodeIndex index, CallArgument? array, ulong? count, string? owner, string via, uint call, List<Registration> found)
    {
        var image = index.Image;
        if (array is not { Kind: ArgKind.Address or ArgKind.Name or ArgKind.String, Rva: { } at } || count is not { } n || n == 0 || n > MaxDescriptors) return;
        uint ptr = image.Is64Bit ? 8u : 4u;
        for (uint i = 0; i < n; i++)
        {
            uint d = at + i * 8 * ptr;
            if (Pointer(image, d) is not { } namePtr || namePtr == 0 || CString(image, namePtr) is not { } name) continue;
            var attr = new byte[4];
            image.Read(d + 6 * ptr, attr);
            bool isStatic = (BinaryPrimitives.ReadUInt32LittleEndian(attr) & NapiStatic) != 0;
            string js = owner == null ? name : $"{owner}.{name}";
            foreach (var (field, kind) in new[] { (2u, "method"), (3u, "getter"), (4u, "setter") })
                if (Pointer(image, d + field * ptr) is { } fn && IsCode(image, fn))
                    found.Add(new Registration(fn, js, owner == null && kind == "method" ? "function" : isStatic && kind == "method" ? "static method" : kind, via, call));
        }
    }

    /// <summary>napi_module: nm_version, nm_flags (int each), nm_filename, nm_register_func, nm_modname (pointers).</summary>
    private static void Module(NativeCodeIndex index, CallArgument? module, uint call, List<Registration> found)
    {
        var image = index.Image;
        if (module is not { Kind: ArgKind.Address or ArgKind.Name or ArgKind.Global, Rva: { } at }) return;
        uint ptr = image.Is64Bit ? 8u : 4u;
        if (Pointer(image, at + 8 + ptr) is not { } init || !IsCode(image, init)) return;
        var name = Pointer(image, at + 8 + 2 * ptr) is { } modname and not 0 ? CString(image, modname) : null;
        found.Add(new Registration(init, name ?? "(module)", "module_init", "napi_module_register", call));
    }

    /// <summary>The name layer: js_&lt;name&gt; (getters and setters js_get_ / js_set_, class members js_Class_member), commented with the registration.</summary>
    public static (Dictionary<uint, string> Names, Dictionary<uint, string> Comments) Names(INativeImage image, IReadOnlyList<Registration> registrations)
    {
        var names = new Dictionary<uint, string>();
        var comments = new Dictionary<uint, string>();
        var used = new HashSet<string>(StringComparer.Ordinal);
        foreach (var r in registrations)
        {
            var line = $"Node-API {r.Kind} '{r.JsName}' ({r.Via} at 0x{image.ImageBase + r.Call:X})";
            comments[r.Function] = comments.TryGetValue(r.Function, out var c) ? c + "\n" + line : line;
            if (names.ContainsKey(r.Function)) continue;
            var stem = r.Kind switch
            {
                "getter" => "js_get_",
                "setter" => "js_set_",
                "module_init" => "napi_module_init_",
                _ => "js_",
            };
            var name = NativeName.Identifier(stem + r.JsName.Replace('.', '_'));
            if (!used.Add(name)) used.Add(name = $"{name}_{r.Function:X}");
            names[r.Function] = name;
        }
        return (names, comments);
    }
}
