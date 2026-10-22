using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Corvus.Core;
using Corvus.Core.Unity;
using Corvus.Services;
using Corvus.Services.Analysis;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// summarize_file view=unity on serialized files and bundles the tests write: script fields read through a type tree
/// and laid out from a compiled script assembly agree, and what cannot be laid out is unknown with its reason.
/// </summary>
public sealed class UnityFieldTests : IDisposable
{
    private const long ScriptPath = 2, PlayerPath = 10, BrokenPath = 11, BrokenScript = 3, DoorPath = 12, DoorScript = 4, TunedPath = 13, TunedScript = 5;

    private const string Engine = """
        namespace UnityEngine
        {
            public class Object { }
            public class Component : Object { }
            public class Behaviour : Component { }
            public class MonoBehaviour : Behaviour { }
            public class Transform : Component { }
            public struct Vector3 { public float x, y, z; }
            public struct Color { public float r, g, b, a; }
            public sealed class Gradient { }
            [System.AttributeUsage(System.AttributeTargets.Field)] public sealed class SerializeField : System.Attribute { }
        }
        """;

    private const string Scripts = """
        using System;
        using System.Collections.Generic;
        using UnityEngine;

        public enum Mode { Off, On, Auto }

        [Serializable]
        public class Stat
        {
            public string label;
            public int value;
        }

        public class Player : MonoBehaviour
        {
            public int health;
            public float speed;
            public bool alive;
            public string title;
            [SerializeField] private Vector3 spawn;
            public Color tint;
            public Mode mode;
            public int[] scores;
            public List<Stat> stats;
            public Transform target;
            private int hidden;
            public static int shared;
            public readonly int fixedValue;
            [NonSerialized] public int skipped;
            public Dictionary<string, int> table;
            public Action callback;
        }

        public class Broken : MonoBehaviour
        {
            public int before;
            public Gradient curve;
            public int after;
        }

        [Serializable]
        public class Param<T>
        {
            public T value;
        }

        [Serializable]
        public class FloatParam : Param<float> { }

        public enum Small : byte { A, B }

        [Serializable]
        public class Empty { }

        public class Tuned : MonoBehaviour
        {
            public FloatParam strength;
            public Small size;
            public Empty nothing;
            public int last;
        }

        namespace Game
        {
            public class Door : MonoBehaviour
            {
                public byte level;
                public short code;
                public long id;
            }
        }
        """;

    private static readonly string[] PlayerFields =
    [
        "health = 120", "speed = 4.5", "alive = true", "title = \"Knight\"", "spawn = {x = 1, y = 2, z = 3}", "tint = {r = 1, g = 0.5, b = 0.25, a = 1}",
        "mode = 2", "scores = [3] [10, 20, 30]", "stats = [2] [{label = \"str\", value = 5}, {label = \"dex\", value = 7}]",
        "target = PPtr<$Transform>(file 0, path 7)",
    ];

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static readonly Lazy<(byte[] Engine, byte[] Scripts)> Assemblies = new(() =>
    {
        var options = new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, optimizationLevel: OptimizationLevel.Release);
        var engine = Roslyn.Compile("UnityEngine.CoreModule", Engine, options);
        return (engine, Roslyn.Compile("Assembly-CSharp", Scripts, options, [MetadataReference.CreateFromImage(engine)]));
    });

    /// <summary>A game folder: the file in Game_Data, with the compiled scripts in Game_Data/Managed when asked.</summary>
    private string Game(string name, byte[] bytes, bool managed = true)
    {
        var data = Directory.CreateDirectory(Path.Combine(_dir.Path, Guid.NewGuid().ToString("N")[..8], "Game_Data")).FullName;
        if (managed)
        {
            var dir = Directory.CreateDirectory(Path.Combine(data, "Managed")).FullName;
            File.WriteAllBytes(Path.Combine(dir, "UnityEngine.CoreModule.dll"), Assemblies.Value.Engine);
            File.WriteAllBytes(Path.Combine(dir, "Assembly-CSharp.dll"), Assemblies.Value.Scripts);
        }
        var path = Path.Combine(data, name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    internal static UnityFileView.Facts View(string path, string? script = null, long offset = 0, int? limit = null)
    {
        var bytes = File.ReadAllBytes(path);
        var view = new UnityFileView().Inspect(new FileInput(path, bytes, Blob.Identify(bytes)) { Options = new FileViewOptions("unity", Offset: offset, Limit: limit) { Script = script } }, default);
        return Assert.IsType<UnityFileView.Facts>(view!.Detail);
    }

    private static List<TreeNode> Base() =>
    [
        new(0, "MonoBehaviour", "Base", -1),
        new(1, "PPtr<GameObject>", "m_GameObject", 12), new(2, "int", "m_FileID", 4), new(2, "SInt64", "m_PathID", 8),
        new(1, "UInt8", "m_Enabled", 1, 0x4000),
        new(1, "PPtr<MonoScript>", "m_Script", 12), new(2, "int", "m_FileID", 4), new(2, "SInt64", "m_PathID", 8),
        .. Text(1, "m_Name"),
    ];

    private static IEnumerable<TreeNode> Text(int level, string name) =>
        [new(level, "string", name, -1), new(level + 1, "Array", "Array", -1, 0x4000, true), new(level + 2, "int", "size", 4), new(level + 2, "char", "data", 1)];

    private static IEnumerable<TreeNode> Floats(int level, string type, string name, params string[] names) =>
        [new(level, type, name, names.Length * 4), .. names.Select(n => new TreeNode(level + 1, "float", n, 4))];

    /// <summary>The type tree the engine writes for Player, listed by hand.</summary>
    private static List<TreeNode> PlayerTree() =>
    [
        .. Base(),
        new(1, "int", "health", 4), new(1, "float", "speed", 4), new(1, "bool", "alive", 1, 0x4000), .. Text(1, "title"),
        .. Floats(1, "Vector3f", "spawn", "x", "y", "z"), .. Floats(1, "ColorRGBA", "tint", "r", "g", "b", "a"), new(1, "int", "mode", 4),
        new(1, "vector", "scores", -1), new(2, "Array", "Array", -1, 0x4000, true), new(3, "int", "size", 4), new(3, "int", "data", 4),
        new(1, "vector", "stats", -1), new(2, "Array", "Array", -1, 0x4000, true), new(3, "int", "size", 4), new(3, "Stat", "data", -1),
        .. Text(4, "label"), new(4, "int", "value", 4),
        new(1, "PPtr<$Transform>", "target", 12), new(2, "int", "m_FileID", 4), new(2, "SInt64", "m_PathID", 8),
    ];

    private static List<TreeNode> ScriptTree() =>
        [new(0, "MonoScript", "Base", -1), .. Text(1, "m_Name"), new(1, "int", "m_ExecutionOrder", 4), new(1, "Hash128", "m_PropertiesHash", 16),
         .. Text(1, "m_ClassName"), .. Text(1, "m_Namespace"), .. Text(1, "m_AssemblyName")];

    private static UnityFileWriter.Data Behaviour(long script, string name) =>
        new UnityFileWriter.Data().Pointer(0, 0).U8(1).Align().Pointer(0, script).String(name);

    private static byte[] PlayerData(int extra = 0) => Behaviour(ScriptPath, "Hero")
        .I32(120).F32(4.5f).Bool(true).Align().String("Knight").F32(1).F32(2).F32(3).F32(1).F32(0.5f).F32(0.25f).F32(1).I32(2)
        .I32(3).I32(10).I32(20).I32(30).I32(2).String("str").I32(5).String("dex").I32(7).Pointer(0, 7).Zero(extra).ToArray();

    private static byte[] Script(string className, string ns = "") =>
        new UnityFileWriter.Data().String(className).I32(0).Zero(16).String(className).String(ns).String("Assembly-CSharp.dll").ToArray();

    /// <summary>A file with the Player asset and its MonoScript, with or without type trees.</summary>
    private static byte[] PlayerFile(bool typeTrees, int format = 22, int extra = 0)
    {
        var w = new UnityFileWriter(format, typeTrees);
        w.Types.Add(new(SerializedFile.ClassMonoBehaviour, 0, typeTrees ? PlayerTree() : null));
        w.Types.Add(new(SerializedFile.ClassMonoScript, -1, typeTrees ? ScriptTree() : null));
        w.Objects.Add((ScriptPath, 1, Script("Player")));
        w.Objects.Add((PlayerPath, 0, PlayerData(extra)));
        return w.Build();
    }

    [Fact]
    public void Script_fields_from_the_type_tree_match_those_laid_out_from_the_assembly()
    {
        var tree = View(Game("level0", PlayerFile(typeTrees: true))).Assets.Single();
        var laid = View(Game("level0", PlayerFile(typeTrees: false))).Assets.Single();
        Assert.Equal(("type tree", "read", "Hero", "Player"), (tree.Layout, tree.State, tree.Name, tree.Script));
        Assert.Equal(("assembly", "read", "Hero", "Player", "Assembly-CSharp.dll"), (laid.Layout, laid.State, laid.Name, laid.Script, laid.Assembly));
        Assert.Equal(PlayerFields, tree.Fields);
        Assert.Equal(PlayerFields, laid.Fields);
    }

    [Fact]
    public void A_format_17_file_aligns_fields_shorter_than_four_bytes_and_names_the_namespace()
    {
        var w = new UnityFileWriter(17, typeTrees: false, "5.6.7f1");
        w.Types.Add(new(SerializedFile.ClassMonoBehaviour, 0, null));
        w.Types.Add(new(SerializedFile.ClassMonoScript, -1, null));
        w.Objects.Add((DoorScript, 1, Script("Door", "Game")));
        w.Objects.Add((DoorPath, 0, Behaviour(DoorScript, "Gate").U8(3).Align().I16(-2).Align().I64(1234567890123).ToArray()));
        var facts = View(Game("sharedassets0.assets", w.Build()), script: "game.door");
        var door = facts.Assets.Single();
        Assert.Equal(17, facts.Files.Single().Format);
        Assert.Equal(("assembly", "read", "Game.Door"), (door.Layout, door.State, door.Script));
        Assert.Equal(["level = 3", "code = -2", "id = 1234567890123"], door.Fields);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void A_bundle_entry_reads_like_the_file_it_holds(int codec)
    {
        var bundle = UnityFileWriter.Bundle(codec, ("CAB-0a1b2c", PlayerFile(typeTrees: false)), ("CAB-0a1b2c.resS", new byte[100]));
        Assert.Empty(UnityFsBundle.Read(bundle, 1 << 20).Issues);
        var facts = View(Game("player.bundle", bundle));
        Assert.Equal("bundle", facts.Container);
        Assert.Equal(PlayerFields, facts.Assets.Single().Fields);
        Assert.Equal("CAB-0a1b2c", facts.Assets.Single().File);
    }

    [Fact]
    public void A_field_the_assembly_cannot_lay_out_is_unknown_with_its_reason()
    {
        var w = new UnityFileWriter(22, typeTrees: false);
        w.Types.Add(new(SerializedFile.ClassMonoBehaviour, 0, null));
        w.Types.Add(new(SerializedFile.ClassMonoScript, -1, null));
        w.Objects.Add((BrokenScript, 1, Script("Broken")));
        w.Objects.Add((BrokenPath, 0, Behaviour(BrokenScript, "Odd").I32(1).Zero(40).I32(2).ToArray()));
        var odd = View(Game("level1", w.Build())).Assets.Single();
        Assert.Equal(("assembly", "partial"), (odd.Layout, odd.State));
        Assert.Equal(["before = 1", "curve = unknown"], odd.Fields);
        Assert.Contains("engine type UnityEngine.Gradient", odd.Reason);
    }

    [Fact]
    public void A_generic_base_binds_its_argument_and_a_byte_enum_keeps_its_size()
    {
        var w = new UnityFileWriter(22, typeTrees: false);
        w.Types.Add(new(SerializedFile.ClassMonoBehaviour, 0, null));
        w.Types.Add(new(SerializedFile.ClassMonoScript, -1, null));
        w.Objects.Add((TunedScript, 1, Script("Tuned")));
        w.Objects.Add((TunedPath, 0, Behaviour(TunedScript, "Knob").F32(0.5f).U8(1).Align().I32(9).ToArray()));
        var knob = View(Game("level2", w.Build())).Assets.Single();
        Assert.Equal(("assembly", "read"), (knob.Layout, knob.State));
        Assert.Equal(["strength = {value = 0.5}", "size = 1", "nothing = {}", "last = 9"], knob.Fields);
    }

    [Fact]
    public void A_layout_that_misses_the_object_size_shows_no_values()
    {
        var asset = View(Game("level0", PlayerFile(typeTrees: false, extra: 4))).Assets.Single();
        Assert.Equal(("assembly", "unknown"), (asset.Layout, asset.State));
        Assert.Empty(asset.Fields);
        Assert.Contains("reads 148 of the object's 152 bytes", asset.Reason);
    }

    [Fact]
    public void A_script_without_its_assembly_is_unknown_and_names_what_was_looked_for()
    {
        var asset = View(Game("level0", PlayerFile(typeTrees: false), managed: false)).Assets.Single();
        Assert.Equal(("none", "unknown", "Player"), (asset.Layout, asset.State, asset.Script));
        Assert.Contains("Assembly-CSharp.dll is not in a Managed folder", asset.Reason);
    }

    [Fact]
    public void A_script_filter_that_matches_nothing_lists_the_classes()
    {
        var e = Assert.Throws<ToolError>(() => View(Game("level0", PlayerFile(typeTrees: true)), script: "Enemy"));
        Assert.Equal(ErrorCode.NotFound, e.Code);
        Assert.Contains("Player", e.Message + e.Remediation);
    }

    [Fact]
    public void Il2Cpp_metadata_leaves_a_private_field_unknown()
    {
        using var module = dnlib.DotNet.ModuleDefMD.Load(Assemblies.Value.Scripts);
        // Il2Cpp dummy assemblies keep field flags but no custom attributes.
        foreach (var f in module.GetTypes().SelectMany(t => t.Fields)) f.CustomAttributes.Clear();
        var layout = UnityScriptLayout.Build(module.Find("Player", false), 22, attributesKept: false);
        Assert.StartsWith("spawn: a private field", layout.Unknown);
        var names = layout.Tree.Where(n => n.Level == 1).Select(n => n.Name).ToList();
        Assert.Equal(["m_GameObject", "m_Enabled", "m_Script", "m_Name", "health", "speed", "alive", "title"], names);
    }

    [Fact]
    public void The_overview_lists_the_view_and_counts_the_assets()
    {
        var path = Game("level0", PlayerFile(typeTrees: true));
        var summary = new InspectionService(new AssemblyWorkspace()).Summarize(null, path, default);
        Assert.Contains(summary.Highlights, h => h.Contains("1 MonoBehaviour assets", StringComparison.Ordinal));
        Assert.True(summary.Views.ContainsKey("unity"));
    }

    [Fact]
    [FuzzEntry(typeof(SerializedFile), typeof(UnityFsBundle), typeof(UnityFileView))]
    public void Fuzzed_unity_files_never_throw_unexpectedly()
    {
        var seeds = new[] { ("level0", PlayerFile(typeTrees: true)), ("level1", PlayerFile(typeTrees: false)), ("x.bundle", UnityFileWriter.Bundle(2, ("CAB-1", PlayerFile(typeTrees: false)))) };
        foreach (var (name, seed) in seeds)
        {
            var path = Game(name, seed);
            var failures = FormatFuzz.Run(seed, b =>
            {
                SerializedFile.Read(b, name);
                UnityFsBundle.Read(b, 1 << 20);
                try { new UnityFileView().Inspect(new FileInput(path, b, Blob.Identify(b)) { Options = new FileViewOptions("unity") }, default); }
                catch (ToolError) { }
            }, 300);
            Assert.True(failures.Count == 0, name + ": " + string.Join("\n", failures.Take(10)));
        }
    }
}

/// <summary>
/// view=unity on the Unity titles of CORVUS_UNITY_TITLES (';'-separated game folders): every asset read, and the assets
/// whose bundles keep type trees laid out again from the scripts' assemblies or Il2Cpp metadata and compared.
/// </summary>
[Trait("Speed", "Slow")]
public sealed class UnityFieldRealTests(ITestOutputHelper output)
{
    [Fact]
    public void Real_titles_lay_out_their_scripts_as_their_type_trees_do()
    {
        var titles = (Environment.GetEnvironmentVariable("CORVUS_UNITY_TITLES") ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(Directory.Exists).ToList();
        if (titles.Count == 0) { output.WriteLine("No Unity titles (CORVUS_UNITY_TITLES)."); return; }
        foreach (var title in titles) Title(title);
    }

    private void Title(string title)
    {
        int both = 0, same = 0, partial = 0, unknown = 0, different = 0;
        static List<string> Known(IEnumerable<string> lines) => [.. lines.Where(l => !l.EndsWith(" = unknown", StringComparison.Ordinal))];
        var states = new Dictionary<string, int>();
        var reasons = new Dictionary<string, int>();
        var differ = new List<string>();
        // An Il2Cpp title is read first, as load_assembly reads it, so its metadata gives the layouts.
        foreach (var metadata in Directory.EnumerateFiles(title, Il2CppGameFiles.MetadataFileName, SearchOption.AllDirectories))
        {
            try
            {
                if (Il2CppGameFiles.Find(metadata) is { Binary.Length: > 0 } game)
                {
                    using var workspace = new AssemblyWorkspace();
                    new Il2CppRawLoader(workspace).Load(game, loadBinary: false, null, default);
                }
            }
            catch (ToolError e)
            {
                output.WriteLine($"{metadata}: not read ({e.Message})");
            }
        }
        foreach (var file in Directory.EnumerateFiles(title, "*", SearchOption.AllDirectories))
        {
            if (new FileInfo(file).Length is < 64 or > 512L << 20) continue;
            var head = new byte[64];
            using (var s = File.OpenRead(file)) s.ReadAtLeast(head, head.Length, false);
            if (!UnityFsBundle.IsBundle(head) && !SerializedFile.IsSerializedFile(head, new FileInfo(file).Length)) continue;
            for (long offset = 0; ;)
            {
                var page = UnityFieldTests.View(file, offset: offset, limit: 200);
                foreach (var a in page.Assets)
                {
                    var key = $"{a.Layout} {a.State}";
                    states[key] = states.GetValueOrDefault(key) + 1;
                    if (a.Reason != null)
                    {
                        var reason = System.Text.RegularExpressions.Regex.Replace(a.Reason, @"\d[\d,]*", "N");
                        reasons[reason] = reasons.GetValueOrDefault(reason) + 1;
                    }
                }
                if (page.Next is not { } next) break;
                offset = next;
            }
            foreach (var (tree, laid) in UnityFileView.BothLayouts(file, File.ReadAllBytes(file)))
            {
                if (tree.State == "unknown" || laid.Layout is not ("assembly" or "metadata")) continue;
                both++;
                var (t, l) = (Known(tree.Fields), Known(laid.Fields));
                if (laid.State == "unknown") unknown++;
                else if (tree.State == "read" && laid.State == "read" ? t.SequenceEqual(l) : t.Take(l.Count).SequenceEqual(l.Take(t.Count)))
                {
                    if (tree.State == "read" && laid.State == "read") same++;
                    else partial++;
                }
                else if (++different <= 10) differ.Add($"{Path.GetFileName(file)} {tree.Script}: {string.Join("; ", t.Except(l).Take(3))} vs {string.Join("; ", l.Except(t).Take(3))}");
            }
        }
        output.WriteLine($"{Path.GetFileName(title)}: {both} assets with both layouts: {same} equal, {partial} equal up to an unknown field, {unknown} unknown, {different} differ");
        foreach (var d in differ) output.WriteLine(d);
        output.WriteLine("assets by layout and state: " + string.Join(", ", states.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => $"{p.Key} {p.Value}")));
        foreach (var (reason, n) in reasons.OrderByDescending(p => p.Value).Take(12)) output.WriteLine($"{n} x {reason}");
        // A layout the assembly gives equals the type tree up to any unknown field, or is reported unknown; values never differ.
        Assert.Empty(differ);
    }
}
