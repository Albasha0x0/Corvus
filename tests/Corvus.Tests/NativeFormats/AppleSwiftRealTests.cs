using Corvus.Native.MachO;
using Corvus.Native.Swift;
using Xunit.Abstractions;

namespace Corvus.Tests.NativeFormats;

/// <summary>The Swift metadata of a real framework (Stripe UI core, from a Swift binding package); its .abi.json is the oracle for names.</summary>
public sealed class AppleSwiftRealTests(ITestOutputHelper output)
{
    [Fact]
    public void A_Swift_framework_reads_types_fields_conformances_and_names()
    {
        var image = MachOFile.Open(AppleObjcRealTests.StripeUICore);
        var swift = AppleSwiftMetadata.Read(image);
        Assert.Empty(swift.Issues);
        int fields = swift.Types.Sum(t => t.Fields.Count);
        output.WriteLine($"{swift.Types.Count} types, {fields} fields, {swift.Protocols.Count} protocols, {swift.Conformances.Count} conformances");
        Assert.Equal(136, swift.Types.Count);
        Assert.Equal(540, fields);
        Assert.Equal(17, swift.Protocols.Count);
        Assert.Equal(174, swift.Conformances.Count);
        // Every field type demangles, symbolic references included.
        Assert.DoesNotContain(swift.Types.SelectMany(t => t.Fields), f => f.Type != null && f.Type.Contains("<ref>", StringComparison.Ordinal));

        var button = swift.Types.Single(t => t.Name == "StripeUICore.Button");
        Assert.Equal(("class", "__C.UIControl"), (button.Kind, button.Superclass));
        Assert.Contains(button.Fields, f => f.Name == "icon" && f.Type == "__C.UIImage?");
        var representable = swift.Types.Single(t => t.Name == "StripeUICore.OneTimeCodeTextFieldRepresentable");
        Assert.Contains(representable.Fields, f => f.Name == "_text" && f.Type == "SwiftUI.Binding<Swift.String>");
        Assert.Contains(swift.Conformances, c => c.Type == "StripeUICore.ActivityIndicator.Size" && c.Protocol == "Swift.Hashable" && c.ProtocolExternal);

        // The public API's mangled names (abi.json, word-substituted) demangle to types the metadata names.
        var abi = File.ReadAllText(Path.Combine(Path.GetDirectoryName(AppleObjcRealTests.StripeUICore)!, "Modules", "StripeUICore.swiftmodule", "arm64-apple-ios.abi.json"));
        var nominal = System.Text.RegularExpressions.Regex.Matches(abi, "\"mangledName\": \"(\\$s12StripeUICore[0-9A-Za-z_]+[CVO])\"")
            .Select(m => m.Groups[1].Value).Distinct().ToList();
        var ours = swift.Types.Select(t => t.Name).ToHashSet();
        var missing = nominal.Select(SwiftDemangler.Demangle).Where(d => d != null && !ours.Contains(d)).ToList();
        output.WriteLine($"abi.json nominal types {nominal.Count}, not in metadata: {string.Join(", ", missing.Take(10))}");
        Assert.True(nominal.Count > 20);
        Assert.Empty(missing);

        var names = AppleSwiftNames.Build(image, swift);
        output.WriteLine($"swift layer: {names.Names.Count} names, {names.Comments.Count} comments, {names.FunctionStarts.Length} function starts, {names.Methods} vtable methods named");
        Assert.All(names.Names.Values, n => Assert.NotNull(SwiftDemangler.Demangle(n)));
        Assert.True(names.Methods > 10);
    }

    /// <summary>The .NET runtime's Apple crypto shim binds CryptoKit through Swift: its records read without issues.</summary>
    [Fact]
    [Trait("Speed", "Slow")]
    public void The_NET_Apple_crypto_shim_reads_without_issues()
    {
        var path = RealPackages.File("Microsoft.NETCore.App.Runtime.osx-arm64", "10.0.11", "runtimes/osx-arm64/native/libSystem.Security.Cryptography.Native.Apple.dylib");
        var image = MachOFile.Open(path);
        var swift = AppleSwiftMetadata.Read(image);
        var objc = AppleObjcMetadata.Read(image);
        output.WriteLine($"{swift.Types.Count} types, {swift.Conformances.Count} conformances, {objc.References.Count} objc references; " +
                         string.Join("; ", swift.Conformances.Take(5).Select(c => $"{c.Type} : {c.Protocol}")));
        Assert.Empty(swift.Issues);
        Assert.Empty(objc.Issues);
        Assert.Contains(swift.Conformances, c => c.Type == "CryptoKit.AES.GCM" && c.Protocol == "pal_swiftbindings.AEADSymmetricAlgorithm" && !c.ProtocolExternal);
        Assert.All(swift.Conformances, c => Assert.DoesNotContain("?", c.Protocol, StringComparison.Ordinal));
    }
}
