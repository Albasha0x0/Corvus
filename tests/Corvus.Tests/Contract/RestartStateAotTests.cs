using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native.Annotations;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>The AOT tools answer the same after a restart.</summary>
public sealed partial class RestartStateAotTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [GeneratedRegex(@"\b\d+(\.\d+)? ?(ms|s)\b|""elapsedMs"":\d+")]
    private static partial Regex Timing();

    /// <summary>One server process on a shared annotation folder.</summary>
    private sealed class Process : IDisposable
    {
        public readonly Env Env;
        public readonly NativeCodeService Code;
        public readonly LoadedNative Native;

        public Process(string dummyDll, string binary, string annotations)
        {
            Env = new Env(dummyDll);
            Code = new NativeCodeService(Env.Workspace, Env.Options, null, new AnnotationStore(annotations));
            Native = Env.Workspace.LoadAny(binary).Native!;
            Code.Index(Native, null, default).GetAwaiter().GetResult();
            _ = new AotNativeNames(Env.AotMetadata, Env.AotNavigator, Code);
        }

        public void Dispose() => Env.Dispose();

        public async Task<Dictionary<string, string>> Reads()
        {
            var methods = Env.MethodAddressTools();
            var native = new NativeCodeTools(Env.Workspace, Code, Env.Pager);
            return new(StringComparer.Ordinal)
            {
                ["get_method_addresses"] = await methods.GetMethodAddresses("Fixture.Native.NativeThing"),
                ["find_method_by_address"] = await methods.FindMethodByAddress("0x1100"),
                ["search_native_strings"] = await native.SearchNativeStrings(Native.Id, "hello"),
                ["disassemble"] = await native.Disassemble(Native.Id, "0x1000"),
            };
        }
    }

    // The second process never runs apply_metadata_names.
    [Fact]
    public async Task Aot_tools_answer_the_same_from_a_restored_name_layer_as_after_apply()
    {
        var (dll, binary) = AotNativeNamesTests.CreateDump(_dir);
        var annotations = _dir.File("annotations");
        Dictionary<string, string> first;
        string applied;
        using (var a = new Process(dll, binary, annotations))
        {
            var tools = new MetadataNameTools(a.Env.Workspace, a.Code, new AotNativeNames(a.Env.AotMetadata, a.Env.AotNavigator, a.Code));
            applied = Timing().Replace(await tools.ApplyMetadataNames(a.Native.Id), "~");
            first = await a.Reads();
        }

        using var b = new Process(dll, binary, annotations);
        // Regression for the failure at 18020f0c8: a collection dropped the
        // restoring instance nothing else referenced.
        GC.Collect();
        GC.WaitForPendingFinalizers();
        var second = await b.Reads();
        var differing = first
            .Where(p => Timing().Replace(p.Value, "~") != Timing().Replace(second[p.Key], "~"))
            .Select(p => p.Key).ToList();
        Assert.True(differing.Count == 0, "answers differ after a restart: " + string.Join("; ", differing) +
            string.Concat(differing.Select(k => $"\n--- {k} after apply\n{first[k]}\n--- {k} after restart\n{second[k]}")));
        Assert.All(first, p => Assert.False(string.IsNullOrWhiteSpace(p.Value), p.Key));
        Assert.Contains("metadata \"hello aot\"", second["search_native_strings"]);
        Assert.Contains("Fixture_Native_NativeThing__First", second["disassemble"]);

        // Applying again in the second process names the same counts.
        var again = new MetadataNameTools(b.Env.Workspace, b.Code, new AotNativeNames(b.Env.AotMetadata, b.Env.AotNavigator, b.Code));
        var repeated = await again.ApplyMetadataNames(b.Native.Id);
        Assert.Equal(applied, Timing().Replace(repeated, "~"));
    }
}
