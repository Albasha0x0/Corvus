using Corvus.Native.MachO;
using Xunit.Abstractions;

namespace Corvus.Tests.NativeFormats;

/// <summary>Apple binaries from NuGet: the Xamarin.Mac runtime, whose local symbols name every method, and a stripped Swift framework.</summary>
public sealed class AppleObjcRealTests(ITestOutputHelper output)
{
    internal static string XamarinDylib => RealPackages.File("Microsoft.macOS.Runtime.osx-arm64", "14.2.8078", "runtimes", "osx-arm64", "native", "libxamarin-dotnet.dylib");
    internal static string StripeUICore => RealPackages.File("SwiftBindings.Stripe.UICore", "26.11.0", "runtimes", "ios-arm64", "native", "StripeUICore.xcframework",
        "ios-arm64", "StripeUICore.framework", "StripeUICore");

    internal static string MethodName(string cls, ObjcMethod m) => $"{(m.IsClassMethod ? '+' : '-')}[{cls} {m.Selector}]";

    /// <summary>Every class, the category and every method of the runtime in the header, each method type encoding read.</summary>
    [Fact]
    public void XamarinRuntime_Header()
    {
        var objc = AppleObjcMetadata.Read(MachOFile.Open(XamarinDylib));
        var header = ObjcHeader.Render(objc, null, "libxamarin-dotnet.dylib");
        foreach (var c in objc.Classes) Assert.Contains($"\n@interface {c.Name} : NSObject", header);
        Assert.Contains("\n@interface NSObject (NonXamarinObject)\n", header);
        Assert.DoesNotContain("types not read", header);
        var methodLines = header.Split('\n').Count(l => l.StartsWith("- (", StringComparison.Ordinal) || l.StartsWith("+ (", StringComparison.Ordinal));
        int accessors = objc.Classes.Sum(c => c.Methods.Count(m => !m.IsClassMethod && c.Properties.Any(p => p.Name == m.Selector || "set" + char.ToUpperInvariant(p.Name[0]) + p.Name[1..] + ":" == m.Selector)));
        Assert.Equal(objc.Classes.Sum(c => c.Methods.Count) + objc.Categories.Sum(c => c.Methods.Count) - accessors, methodLines);
        output.WriteLine(header);
    }

    [Fact]
    public void Xamarin_runtime_methods_match_the_symbol_table()
    {
        var image = MachOFile.Open(XamarinDylib);
        var objc = AppleObjcMetadata.Read(image);
        Assert.Empty(objc.Issues);
        Assert.Equal(["XamarinNSThreadObject", "XamarinCocoaThreadInitializer", "XamarinAssociatedObject", "XamarinGCHandle", "XamarinGCSupport"],
            objc.Classes.Select(c => c.Name));
        Assert.All(objc.Classes, c => Assert.Equal(("NSObject", true), (c.Superclass, c.SuperclassExternal)));
        var category = Assert.Single(objc.Categories);
        Assert.Equal(("NSObject", "NonXamarinObject", true), (category.ClassName, category.Name, category.ClassExternal));

        var ours = objc.Classes.SelectMany(c => c.Methods.Select(m => (Name: MethodName(c.Name, m), m.Imp)))
            .Concat(category.Methods.Select(m => (Name: MethodName($"{category.ClassName}({category.Name})", m), m.Imp))).ToList();
        var symbols = image.Symbols.Where(s => s.Name.StartsWith("-[", StringComparison.Ordinal) || s.Name.StartsWith("+[", StringComparison.Ordinal))
            .Select(s => (s.Name, Imp: image.ImageBase + s.Rva)).OrderBy(s => s.Name, StringComparer.Ordinal).ToList();
        Assert.Equal(14, symbols.Count);
        Assert.Equal(symbols, ours.OrderBy(s => s.Name, StringComparer.Ordinal));
        var ivar = objc.Classes[0].Ivars.Single(v => v.Name == "selector");
        Assert.Equal((":", 16u, 8u), (ivar.Type, ivar.Offset!.Value, ivar.Size));
        Assert.Contains(objc.References, r => r is { Kind: "class", Name: "NSThread", External: true });

        // The name layer gives every implementation the name clang gave its local symbol.
        var names = AppleObjcNames.Build(image, objc);
        Assert.All(image.Symbols.Where(x => x.Name.StartsWith("-[", StringComparison.Ordinal) || x.Name.StartsWith("+[", StringComparison.Ordinal)),
            x => Assert.Equal(x.Name, names.Names[x.Rva]));
        Assert.Equal("_OBJC_CLASS_$_XamarinGCHandle", names.Names[(uint)(objc.Classes.Single(c => c.Name == "XamarinGCHandle").Va - image.ImageBase)]);
    }

    /// <summary>IDA 9.3 names 245 -[...] / +[...] functions here: the 244 the metadata lists plus a duplicate it creates at 0x17C90.</summary>
    [Fact]
    public void A_Swift_framework_reads_classes_and_implementations()
    {
        var objc = AppleObjcMetadata.Read(MachOFile.Open(StripeUICore));
        Assert.Empty(objc.Issues);
        int methods = objc.Classes.Sum(c => c.Methods.Count);
        int imps = objc.Classes.SelectMany(c => c.Methods).Select(m => m.Imp).Where(i => i != 0).Distinct().Count();
        output.WriteLine($"{objc.Classes.Count} classes, {methods} methods, {imps} implementations, {objc.Protocols.Count} protocols, {objc.References.Count} references");
        Assert.Equal(51, objc.Classes.Count);
        Assert.Equal(244, imps);
        Assert.Equal(methods, imps);
        Assert.Equal(12, objc.Protocols.Count);
        Assert.All(objc.Classes.Where(c => c.Name.StartsWith("_Tt", StringComparison.Ordinal)), c => Assert.NotNull(c.SwiftName));
        Assert.Contains(objc.Classes, c => c.DisplayName == "StripeUICore.OneTimeCodeTextField.TextStorage" && c.Superclass == "_TtCs12_SwiftObject");
        Assert.True(objc.Classes.Single(c => c.Name == "STP_Internal_Button").IsSwift);
    }
}
