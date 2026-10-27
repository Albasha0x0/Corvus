using System.Diagnostics;
using Corvus.Native.Annotations;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ida;
using Corvus.Services;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Metadata and user names pushed into IDA: they reach the pseudocode, persist in the .i64, and batches scale.</summary>
[Trait("Speed", "Slow")]
public sealed class AotIdaTests(ITestOutputHelper output) : IDisposable
{
    private static readonly NativeOpenOptions Offline = new() { Symbols = SymbolMode.Off };
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private IdaProvider Provider() => new(new IdaProviderOptions { CacheRoot = _dir.File("cache") });

    [IdaFact]
    public async Task Metadata_names_reach_the_pseudocode_and_persist_in_the_database()
    {
        var (dll, binary) = AotNativeNamesTests.CreateDump(_dir);
        using var env = new Env(dll);
        var code = new NativeCodeService(env.Workspace, env.Options, null, new AnnotationStore(_dir.File("ann")));
        var native = env.Workspace.LoadAny(binary).Native!;
        var index = await code.Index(native, null, default);
        new AotNativeNames(env.AotMetadata, env.AotNavigator, code).Apply(native, index, env.Workspace.Assemblies, default);
        new NativeEditService(env.Workspace, code).Rename(native, index, 0x1300, "MyUint", false);

        using var provider = Provider();
        await using (var session = await provider.OpenAsync(binary, null, Offline))
        {
            var pushed = await new NativeNamePush(code).EnsureAsync(native, session, default);
            output.WriteLine(NativeNamePush.Describe(pushed));
            Assert.Equal(11, pushed!.Sent);
            Assert.Equal(0, pushed.Totals!.NameFailures);
            var text = (await session.DecompileAsync(0x1000)).Text;
            output.WriteLine(text);
            Assert.Contains("Fixture_Native_NativeThing__First", text);
            Assert.Contains("Fixture_Native_NativeThing__Second", text);
            Assert.Contains("StringLiteral_0", text);
            // The function comment.
            Assert.Contains("Fixture.Native.NativeThing::First()", text);
            var functions = await session.ListFunctionsAsync();
            Assert.Contains(functions, f => f is { StartRva: 0x1300, Name: "MyUint" });
        }
        await using (var session = await provider.OpenAsync(binary, null, Offline))
        {
            Assert.True(session.ReusedDatabase);
            var again = await new NativeNamePush(code).EnsureAsync(native, session, default);
            Assert.True(again!.AlreadyInDatabase);
            Assert.Contains("Fixture_Native_NativeThing__Second", (await session.DecompileAsync(0x1000)).Text);
        }
    }

    /// <summary>Tens of thousands of names in batches against one request per name (measured on a sample, extrapolated).</summary>
    [IdaFact]
    public async Task Batched_names_scale_past_one_request_per_name()
    {
        const int count = 50_000;
        var b = new PeBuilder { ImageBase = 0x180000000 };
        var code = new byte[count * 16];
        Array.Fill(code, (byte)0xCC);
        for (int i = 0; i < count; i++) { code[i * 16] = 0x31; code[i * 16 + 1] = 0xC0; code[i * 16 + 2] = 0xC3; } // xor eax,eax; ret
        b.Add(".text", code, 0x60000020);
        var path = _dir.File("many.dll");
        File.WriteAllBytes(path, b.Build());

        using var provider = Provider();
        await using var session = await provider.OpenAsync(path, null, Offline);
        var items = Enumerable.Range(0, count)
            .Select(i => new NativeNameItem(0x1000 + (uint)i * 16, $"App_Ns_Type{i / 20}__Method{i}", $"App.Ns.Type{i / 20}::Method{i}(int, string)", true))
            .ToList();
        var clock = Stopwatch.StartNew();
        int named = 0, created = 0;
        for (int i = 0; i < items.Count; i += NativeNamePush.BatchSize)
        {
            var r = await session.ApplyNamesAsync(items.GetRange(i, Math.Min(NativeNamePush.BatchSize, items.Count - i)), save: i + NativeNamePush.BatchSize >= items.Count);
            named += r.Named;
            created += r.FunctionsCreated;
        }
        var batched = clock.Elapsed;
        Assert.Equal(count, named);

        const int sample = 300;
        clock.Restart();
        for (int i = 0; i < sample; i++) await session.SetNameAsync(0x1000 + (uint)i * 16, $"Single{i}");
        var perCall = clock.Elapsed / sample;
        output.WriteLine($"{count} names + comments ({created} functions created) in batches of {NativeNamePush.BatchSize}: {batched.TotalSeconds:0.0} s " +
                         $"({batched.TotalMilliseconds * 1000 / count:0} us per name); one request per name: {perCall.TotalMilliseconds:0.00} ms each, " +
                         $"{(perCall * count).TotalSeconds:0} s extrapolated");
    }
}
