using System.Text;

namespace Corvus.Services;

/// <summary>
/// What the built-in metadata reader takes from a game (GameAssembly.dll + global-metadata.dat) besides the dummy
/// assemblies: the data Il2CppDumper writes to script.json and stringliteral.json. String literals with their slot RVAs;
/// ScriptMethod entries (every method with code and every generic instantiation, with the method definition each comes
/// from); ScriptMetadata and ScriptMetadataMethod slots; the other function starts (invokers, generic method pointers,
/// reverse P/Invoke wrappers, unresolved-call stubs); and every item that could not be read, with the reason. Stored
/// beside the generated dummy assemblies (<see cref="FileName"/>), so a later load does not read the game again.
/// </summary>
public sealed class Il2CppGameModel
{
    public const string FileName = "il2cpp-model.bin";
    private const uint Magic = 0x4D504932; // "2IPM"
    private const int FormatVersion = 1;

    public required string BinaryPath { get; init; }
    public required string MetadataPath { get; init; }
    /// <summary>The metadata version as LibCpp2IL reads it (24.5, 29.1, 31 ...), and the header's integer version.</summary>
    public required float MetadataVersion { get; init; }
    public required int HeaderVersion { get; init; }
    /// <summary>The Unity version the structures were read for, and where it came from.</summary>
    public required string UnityVersion { get; init; }
    public required string UnityVersionSource { get; init; }
    public required ulong ImageBase { get; init; }
    /// <summary>The binary is a memory image of the loaded module (sections at their RVAs), not the file on disk.</summary>
    public required bool MemoryImage { get; init; }

    public string[] LiteralValues { get; init; } = [];
    /// <summary>Slot RVA of each literal (0 when no slot was found for it).</summary>
    public uint[] LiteralSlots { get; init; } = [];

    public List<Entry> Methods { get; init; } = [];
    public List<ScriptMetadata> Metadata { get; init; } = [];
    public List<ScriptMetadataMethod> MethodInfos { get; init; } = [];
    /// <summary>Function starts that are not method code: invokers, generic method pointers, reverse P/Invoke wrappers ...</summary>
    public uint[] Addresses { get; init; } = [];
    public List<Unreadable> Unreadables { get; init; } = [];
    /// <summary>Counts: images, types, methods, fields, methods with code.</summary>
    public int Images { get; init; }
    public int Types { get; init; }
    public int MethodDefinitions { get; init; }
    public int Fields { get; init; }
    public int MethodsWithCode { get; init; }
    public TimeSpan ReadTime { get; set; }

    /// <summary>A ScriptMethod entry: RVA, Il2CppDumper name ("Ns.Type&lt;args&gt;$$Method"), and the definition it instantiates (image file name, token).</summary>
    public readonly record struct Entry(uint Address, string Name, string Image, uint Token);

    /// <summary>An item that could not be read: what it is, a reason code (snake_case) and the detail.</summary>
    public readonly record struct Unreadable(string Item, string Reason, string Detail);

    public void Write(string path)
    {
        var tmp = path + ".tmp";
        using (var stream = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16))
        using (var w = new BinaryWriter(stream, Encoding.UTF8))
        {
            w.Write(Magic);
            w.Write(FormatVersion);
            w.Write(BinaryPath); w.Write(MetadataPath); w.Write(MetadataVersion); w.Write(HeaderVersion);
            w.Write(UnityVersion); w.Write(UnityVersionSource); w.Write(ImageBase); w.Write(MemoryImage);
            w.Write(Images); w.Write(Types); w.Write(MethodDefinitions); w.Write(Fields); w.Write(MethodsWithCode); w.Write(ReadTime.Ticks);
            w.Write(LiteralValues.Length);
            for (int i = 0; i < LiteralValues.Length; i++) { w.Write(LiteralValues[i]); w.Write(LiteralSlots[i]); }
            w.Write(Methods.Count);
            foreach (var m in Methods) { w.Write(m.Address); w.Write(m.Name); w.Write(m.Image); w.Write(m.Token); }
            w.Write(Metadata.Count);
            foreach (var m in Metadata) { w.Write(m.Address); w.Write(m.Name); w.Write(m.Signature ?? ""); }
            w.Write(MethodInfos.Count);
            foreach (var m in MethodInfos) { w.Write(m.Address); w.Write(m.Name); w.Write(m.MethodAddress); }
            w.Write(Addresses.Length);
            foreach (var a in Addresses) w.Write(a);
            w.Write(Unreadables.Count);
            foreach (var u in Unreadables) { w.Write(u.Item); w.Write(u.Reason); w.Write(u.Detail); }
        }
        File.Move(tmp, path, overwrite: true);
    }

    /// <summary>Reads a model file; IOException when it is not one or is damaged.</summary>
    public static Il2CppGameModel Read(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 1 << 16);
            using var r = new BinaryReader(stream, Encoding.UTF8);
            if (r.ReadUInt32() != Magic || r.ReadInt32() != FormatVersion) throw new IOException($"{path} is not an Il2Cpp model file of this version");
            string binary = r.ReadString(), metadata = r.ReadString();
            float version = r.ReadSingle();
            int header = r.ReadInt32();
            string unity = r.ReadString(), unitySource = r.ReadString();
            ulong imageBase = r.ReadUInt64();
            bool memory = r.ReadBoolean();
            int images = r.ReadInt32(), types = r.ReadInt32(), methodDefs = r.ReadInt32(), fields = r.ReadInt32(), withCode = r.ReadInt32();
            var readTime = TimeSpan.FromTicks(r.ReadInt64());
            int n = Count(r, stream);
            var values = new string[n];
            var slots = new uint[n];
            for (int i = 0; i < n; i++) { values[i] = r.ReadString(); slots[i] = r.ReadUInt32(); }
            n = Count(r, stream);
            var methods = new List<Entry>(n);
            for (int i = 0; i < n; i++) methods.Add(new Entry(r.ReadUInt32(), r.ReadString(), r.ReadString(), r.ReadUInt32()));
            n = Count(r, stream);
            var slotsMeta = new List<ScriptMetadata>(n);
            for (int i = 0; i < n; i++)
            {
                ulong a = r.ReadUInt64();
                string name = r.ReadString(), sig = r.ReadString();
                slotsMeta.Add(new ScriptMetadata(a, name, sig.Length > 0 ? sig : null));
            }
            n = Count(r, stream);
            var infos = new List<ScriptMetadataMethod>(n);
            for (int i = 0; i < n; i++) infos.Add(new ScriptMetadataMethod(r.ReadUInt64(), r.ReadString(), r.ReadUInt64()));
            n = Count(r, stream);
            var addresses = new uint[n];
            for (int i = 0; i < n; i++) addresses[i] = r.ReadUInt32();
            n = Count(r, stream);
            var unreadable = new List<Unreadable>(n);
            for (int i = 0; i < n; i++) unreadable.Add(new Unreadable(r.ReadString(), r.ReadString(), r.ReadString()));
            return new Il2CppGameModel
            {
                BinaryPath = binary, MetadataPath = metadata, MetadataVersion = version, HeaderVersion = header, UnityVersion = unity,
                UnityVersionSource = unitySource, ImageBase = imageBase, MemoryImage = memory, Images = images, Types = types,
                MethodDefinitions = methodDefs, Fields = fields, MethodsWithCode = withCode, ReadTime = readTime,
                LiteralValues = values, LiteralSlots = slots, Methods = methods, Metadata = slotsMeta, MethodInfos = infos,
                Addresses = addresses, Unreadables = unreadable,
            };
        }
        catch (EndOfStreamException ex) { throw new IOException($"{path} is truncated: {ex.Message}", ex); }
        catch (FormatException ex) { throw new IOException($"{path} is damaged: {ex.Message}", ex); }
    }

    private static int Count(BinaryReader r, Stream s)
    {
        int n = r.ReadInt32();
        if (n < 0 || n > s.Length) throw new IOException("damaged model file: bad count");
        return n;
    }
}
