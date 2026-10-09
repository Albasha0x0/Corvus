using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace NetDecompilerMcp.Services.Simplify;

/// <summary>AppDomain.CurrentDomain, under the deterministic environment.</summary>
internal sealed class AppDomainObject : ReflectionObject
{
    protected override string[] Types => ["System.AppDomain", "System.MarshalByRefObject"];
}

/// <summary>
/// The deterministic environment (opt-in, <see cref="SimplifyOptions.DeterministicEnvironment"/>): what initialization
/// code reads of the machine it runs on - the module's own path, the base and current directories, special folders,
/// a fixed set of environment variables, the machine and user names - is pinned to the fixed stand-ins below, the way a
/// test host pins them, and reading the module's own file reads the image as loaded. Path functions use Windows
/// semantics. Without the option these reads bail with external-io.
/// </summary>
internal static class EnvironmentStandIns
{
    public const string InstallDirectory = @"C:\Program Files\App";
    public const string UserProfile = @"C:\Users\User";
    public const string MachineName = "MACHINE";
    public const string UserName = "User";

    /// <summary>Environment.SpecialFolder values and their stand-ins.</summary>
    public static readonly IReadOnlyDictionary<int, (string Name, string Path)> Folders = new Dictionary<int, (string, string)>
    {
        [0] = ("Desktop", UserProfile + @"\Desktop"),
        [5] = ("Personal (MyDocuments)", UserProfile + @"\Documents"),
        [7] = ("Startup", UserProfile + @"\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"),
        [16] = ("DesktopDirectory", UserProfile + @"\Desktop"),
        [26] = ("ApplicationData", UserProfile + @"\AppData\Roaming"),
        [28] = ("LocalApplicationData", UserProfile + @"\AppData\Local"),
        [35] = ("CommonApplicationData", @"C:\ProgramData"),
        [36] = ("Windows", @"C:\Windows"),
        [37] = ("System", @"C:\Windows\system32"),
        [38] = ("ProgramFiles", @"C:\Program Files"),
        [40] = ("UserProfile", UserProfile),
        [42] = ("ProgramFilesX86", @"C:\Program Files (x86)"),
    };

    /// <summary>Environment variables and their stand-ins (names compare ignoring case, as on Windows).</summary>
    public static readonly IReadOnlyDictionary<string, string> Variables = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["APPDATA"] = UserProfile + @"\AppData\Roaming",
        ["LOCALAPPDATA"] = UserProfile + @"\AppData\Local",
        ["PROGRAMDATA"] = @"C:\ProgramData",
        ["USERPROFILE"] = UserProfile,
        ["TEMP"] = UserProfile + @"\AppData\Local\Temp",
        ["TMP"] = UserProfile + @"\AppData\Local\Temp",
        ["ProgramFiles"] = @"C:\Program Files",
        ["ProgramFiles(x86)"] = @"C:\Program Files (x86)",
        ["SystemRoot"] = @"C:\Windows",
        ["windir"] = @"C:\Windows",
        ["SystemDrive"] = "C:",
        ["HOMEDRIVE"] = "C:",
        ["HOMEPATH"] = @"\Users\User",
        ["COMPUTERNAME"] = MachineName,
        ["USERNAME"] = UserName,
    };

    /// <summary>The members pinned, and their stand-ins, as docs/simplify.md lists them.</summary>
    public static IReadOnlyList<(string Member, string Value)> Table(string file) =>
    [
        ("Assembly.Location (of the module's own assembly), Module.FullyQualifiedName", $@"{InstallDirectory}\{file}"),
        ("Assembly.CodeBase, Assembly.EscapedCodeBase", $"file:///C:/Program Files/App/{file} (escaped: %20 for spaces)"),
        ("Module.Name", file),
        ("AppDomain.CurrentDomain.BaseDirectory, AppContext.BaseDirectory", InstallDirectory + @"\"),
        ("Environment.CurrentDirectory, Directory.GetCurrentDirectory()", InstallDirectory),
        ("Assembly.GetEntryAssembly()", "the module's own assembly when the module is an executable (it has an entry point)"),
        ("Environment.GetFolderPath", string.Join("; ", Folders.Values.Select(f => $"{f.Name}: {f.Path}"))),
        ("Path.GetTempPath()", UserProfile + @"\AppData\Local\Temp\"),
        ("Environment.GetEnvironmentVariable", string.Join("; ", Variables.Select(v => $"{v.Key}: {v.Value}")) + "; any other variable is not modelled"),
        ("Environment.MachineName, Environment.UserDomainName", MachineName),
        ("Environment.UserName", UserName),
        ("Environment.NewLine", "\\r\\n"),
        ("File.Exists, File.ReadAllBytes, File.OpenRead, new FileStream(path, FileMode.Open[, FileAccess.Read[, FileShare]]) of the module's own path",
            "the module's image as loaded, read-only; any other path is not modelled"),
        ("Path.GetDirectoryName, GetFileName, GetFileNameWithoutExtension, GetExtension, Combine (2 to 4 parts)",
            "Windows semantics ('\\' and '/' separators, drive roots); paths with repeated separators, UNC paths or invalid characters are not modelled"),
    ];
}

internal sealed partial class IlEvaluator
{
    /// <summary>Pins environment reads to the stand-ins of <see cref="EnvironmentStandIns"/>.</summary>
    public bool DeterministicEnvironment { get; init; }

    private readonly AppDomainObject _appDomain = new();

    private string ModuleFileName => Path.GetFileName(module.Location) is { Length: > 0 } file ? file : module.Name.String;

    private string ModulePath => $@"{EnvironmentStandIns.InstallDirectory}\{ModuleFileName}";

    /// <summary>The module's image as loaded (what reading its own file gives).</summary>
    private byte[] ModuleImage => _image ??= module is ModuleDefMD md
        ? md.Metadata.PEImage.CreateReader().ToArray()
        : throw Bail(FallbackReason.ExternalIo, "the module has no loaded image to read");

    private byte[]? _image;

    /// <summary>
    /// Reads of the environment; null with <paramref name="handled"/> false when the method is not one. Without
    /// <see cref="DeterministicEnvironment"/> they bail with external-io.
    /// </summary>
    private object? EnvironmentCall(IMethod method, Code op, object?[] args, out bool handled)
    {
        handled = false;
        string type = method.DeclaringType?.FullName ?? "";
        string name = method.Name;
        int count = method.MethodSig?.Params.Count ?? 0;
        object? Receiver() => args.Length > 0 ? args[0] is Pointer p ? p.Get() : args[0] : null;
        string? reads = (type, name) switch
        {
            ("System.Reflection.Assembly", "get_Location" or "get_CodeBase" or "get_EscapedCodeBase") when Receiver() is AssemblyObject => "the module's own path",
            ("System.Reflection.Assembly", "GetEntryAssembly") => "the entry assembly",
            ("System.Reflection.Module", "get_FullyQualifiedName" or "get_Name") when Receiver() is ModuleObject => "the module's own path",
            ("System.AppDomain", "get_CurrentDomain" or "get_BaseDirectory") or ("System.AppContext", "get_BaseDirectory") => "the application's base directory",
            ("System.Environment", "get_CurrentDirectory") or ("System.IO.Directory", "GetCurrentDirectory") => "the current directory",
            ("System.Environment", "GetFolderPath") => "a special folder",
            ("System.Environment", "GetEnvironmentVariable") when count == 1 => "an environment variable",
            ("System.Environment", "get_MachineName" or "get_UserName" or "get_UserDomainName" or "get_NewLine") => "the machine's name, user or line ending",
            ("System.IO.Path", "GetTempPath") => "the temporary folder",
            ("System.IO.Path", "GetDirectoryName" or "GetFileName" or "GetFileNameWithoutExtension" or "GetExtension" or "Combine") => "path syntax, which differs between platforms",
            ("System.IO.File", "Exists" or "ReadAllBytes" or "OpenRead") when count == 1 => "a file",
            ("System.IO.FileStream", ".ctor") when op == Code.Newobj => "a file",
            ("System.IO.FileStream", _) when Receiver() is StreamObject { FromFile: true } => "a file",
            _ => null,
        };
        if (reads == null) return null;
        handled = true;
        if (!DeterministicEnvironment && name == "GetEntryAssembly")
            throw Bail(FallbackReason.ExternalIo, "the entry assembly is the host's, which differs between runs (the deterministicEnvironment option pins it when the module is an executable)");
        if (!DeterministicEnvironment)
            throw Bail(type == "System.IO.Path" && reads.StartsWith("path syntax", StringComparison.Ordinal) ? FallbackReason.PlatformDependent : FallbackReason.ExternalIo,
                $"calls {Describe(method)}: reads {reads}, which differs between machines (the deterministicEnvironment option pins it)");

        switch (type, name)
        {
            case ("System.Reflection.Assembly", "get_Location"): return ModulePath;
            case ("System.Reflection.Assembly", "get_CodeBase"): return $"file:///C:/Program Files/App/{ModuleFileName}";
            case ("System.Reflection.Assembly", "get_EscapedCodeBase"): return $"file:///C:/Program%20Files/App/{Uri.EscapeDataString(ModuleFileName)}";
            case ("System.Reflection.Assembly", "GetEntryAssembly"):
                return module.EntryPoint != null ? _assemblyObject : throw Bail(FallbackReason.ExternalIo, "the entry assembly is the host's: the module is not an executable");
            case ("System.Reflection.Module", "get_FullyQualifiedName"): return ModulePath;
            case ("System.Reflection.Module", "get_Name"): return ModuleFileName;
            case ("System.AppDomain", "get_CurrentDomain"): return _appDomain;
            case ("System.AppDomain", "get_BaseDirectory"):
                Of<AppDomainObject>(args[0], "the current AppDomain");
                return EnvironmentStandIns.InstallDirectory + @"\";
            case ("System.AppContext", "get_BaseDirectory"): return EnvironmentStandIns.InstallDirectory + @"\";
            case ("System.Environment", "get_CurrentDirectory"): case ("System.IO.Directory", "GetCurrentDirectory"): return EnvironmentStandIns.InstallDirectory;
            case ("System.Environment", "GetFolderPath"):
            {
                if (count == 2 && I4(args[1]) != 0) throw Bail(FallbackReason.ExternalIo, "GetFolderPath with an option other than SpecialFolderOption.None");
                return EnvironmentStandIns.Folders.TryGetValue(I4(args[0]), out var folder)
                    ? folder.Path
                    : throw Bail(FallbackReason.ExternalIo, $"special folder {I4(args[0])} has no stand-in");
            }
            case ("System.Environment", "GetEnvironmentVariable"):
                return EnvironmentStandIns.Variables.TryGetValue(Str(args[0]), out var value)
                    ? value
                    : throw Bail(FallbackReason.ExternalIo, $"environment variable {Str(args[0])} has no stand-in");
            case ("System.Environment", "get_MachineName"): case ("System.Environment", "get_UserDomainName"): return EnvironmentStandIns.MachineName;
            case ("System.Environment", "get_UserName"): return EnvironmentStandIns.UserName;
            case ("System.Environment", "get_NewLine"): return "\r\n";
            case ("System.IO.Path", "GetTempPath"): return EnvironmentStandIns.UserProfile + @"\AppData\Local\Temp\";
            case ("System.IO.Path", _): return WindowsPath(name, args);
            case ("System.IO.File", "Exists"): return OwnFile(args[0]) ? 1 : throw NotOwnFile(args[0]);
            case ("System.IO.File", "ReadAllBytes"):
                if (!OwnFile(args[0])) throw NotOwnFile(args[0]);
                return NewArray(ModuleImage.ToArray());
            case ("System.IO.File", "OpenRead"):
                if (!OwnFile(args[0])) throw NotOwnFile(args[0]);
                return OpenImage();
            case ("System.IO.FileStream", ".ctor"):
            {
                // (path, FileMode.Open), (path, Open, FileAccess.Read), (path, Open, Read, FileShare): read-only opens of the module's own file.
                var parameters = method.MethodSig!.Params;
                bool readOnly = count >= 2 && parameters[0].ElementType == ElementType.String && I4(args[1]) == (int)FileMode.Open &&
                                (count == 2 || (I4(args[2]) == (int)FileAccess.Read && (count == 3 || parameters[3].FullName == "System.IO.FileShare"))) && count <= 4;
                if (!readOnly) throw Bail(FallbackReason.ExternalIo, $"calls {Describe(method)}: only read-only opens of the module's own file are modelled");
                if (!OwnFile(args[0])) throw NotOwnFile(args[0]);
                return OpenImage();
            }
            default:
                // A FileStream opened on the module's own file reads as any other read-only stream.
                return StreamCall((StreamObject)Receiver()!, method, name, count, args);
        }
    }

    private bool OwnFile(object? path) => string.Equals(Str(path), ModulePath, StringComparison.OrdinalIgnoreCase);

    private static EvaluationBailout NotOwnFile(object? path) =>
        Bail(FallbackReason.ExternalIo, $"reads the file {Str(path)}: only the module's own file is modelled");

    private StreamObject OpenImage()
    {
        var bytes = ModuleImage;
        Allocate(bytes.Length + 64);
        return new StreamObject(bytes) { FromFile = true, Shared = _cctorDepth > 0 };
    }

    /// <summary>System.IO.Path string functions with Windows semantics.</summary>
    private static object? WindowsPath(string name, object?[] args)
    {
        static bool Separator(char c) => c is '\\' or '/';
        static string Checked(object? v)
        {
            var s = Str(v);
            if (s.IndexOfAny(['<', '>', '"', '|', '?', '*', '\0']) >= 0 || s.StartsWith(@"\\", StringComparison.Ordinal) || s.StartsWith("//", StringComparison.Ordinal))
                throw Bail(FallbackReason.UnsupportedValue, $"path syntax of \"{s}\" (invalid characters or a UNC path)");
            for (int i = 1; i < s.Length; i++)
                if (Separator(s[i]) && Separator(s[i - 1])) throw Bail(FallbackReason.UnsupportedValue, $"path syntax of \"{s}\" (repeated separators)");
            return s;
        }
        // "C:\" or "C:" or "\": the root's length.
        static int Root(string s) => s.Length >= 2 && s[1] == ':' && char.IsAsciiLetter(s[0]) ? s.Length >= 3 && Separator(s[2]) ? 3 : 2 : s.Length >= 1 && Separator(s[0]) ? 1 : 0;
        static int FileStart(string s)
        {
            int i = s.Length;
            while (i > 0 && !Separator(s[i - 1]) && !(i == 2 && s[1] == ':')) i--;
            return i;
        }

        switch (name)
        {
            case "Combine":
            {
                if (args.Any(a => a == null)) throw Bail(FallbackReason.RuntimeError, "Path.Combine of null (ArgumentNullException)");
                if (args.Length is < 2 or > 4) throw Bail(FallbackReason.UnsupportedCall, "Path.Combine of an array of parts");
                string result = "";
                foreach (var part in args.Select(Checked))
                {
                    if (part.Length == 0) continue;
                    if (Root(part) > 0) result = part;
                    else if (result.Length == 0 || Separator(result[^1]) || result[^1] == ':') result += part;
                    else result += @"\" + part;
                }
                return result;
            }
            case "GetFileName":
                return args[0] == null ? null : Checked(args[0]) is var f ? f[FileStart(f)..] : null;
            case "GetExtension":
            case "GetFileNameWithoutExtension":
            {
                if (args[0] == null) return null;
                var file = Checked(args[0]) is var p ? p[FileStart(p)..] : "";
                int dot = file.LastIndexOf('.');
                if (name == "GetExtension") return dot < 0 || dot == file.Length - 1 ? "" : file[dot..];
                return dot < 0 ? file : file[..dot];
            }
            case "GetDirectoryName":
            {
                if (args[0] == null) return null;
                var path = Checked(args[0]).Replace('/', '\\');
                int root = Root(path);
                if (path.Length <= root) return null;
                int end = FileStart(path);
                if (end <= root) return path[..root];
                end--; // the separator
                while (end > root && path[end - 1] == '\\') end--;
                return path[..end];
            }
            default:
                throw Bail(FallbackReason.UnsupportedCall, $"Path.{name}");
        }
    }
}
