using Corvus.Native.MachO;
using Xunit.Abstractions;

namespace Corvus.Tests.NativeFormats;

/// <summary>
/// Real Apple binaries from NuGet: the Xamarin.Mac runtime (ObjC classes, a category on NSObject, local symbols naming
/// every method: the oracle) and a Swift framework of a Stripe binding package (Swift classes exposed to ObjC, stripped).
/// </summary>
public sealed class AppleObjcRealTests(ITestOutputHelper output)
{
    internal static string XamarinDylib => RealPackages.File("Microsoft.macOS.Runtime.osx-arm64", "14.2.8078", "runtimes", "osx-arm64", "native", "libxamarin-dotnet.dylib");
    internal static string StripeUICore => RealPackages.File("SwiftBindings.Stripe.UICore", "26.11.0", "runtimes", "ios-arm64", "native", "StripeUICore.xcframework",
        "ios-arm64", "StripeUICore.framework", "StripeUICore");

    internal static string MethodName(string cls, ObjcMethod m) => $"{(m.IsClassMethod ? '+' : '-')}[{cls} {m.Selector}]";

    [Fact]
    public void XamarinRuntime_MethodsMatchTheSymbolTable()
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
    }

    /// <summary>
    /// IDA 9.3 names 245 functions -[...] / +[...] in this binary: the 244 implementations the metadata lists, plus a
    /// "-[STP_Internal_OneTimeCodeTextField markedTextStyle]_0" that IDA gives a second function at 0x17C90.
    /// </summary>
    [Fact]
    public void StripeSwiftFramework_ClassesAndImplementations()
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
