using System.Diagnostics;
using Corvus.Native.Swift;
using Xunit.Abstractions;

namespace Corvus.Tests.NativeFormats;

public sealed class SwiftDemangleTests(ITestOutputHelper output)
{
    /// <summary>The corpus lines swift-demangle's own test reads: "mangled ---> expected", with the {...} classification prefix dropped.</summary>
    private static List<(string Mangled, string Expected)> Corpus()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "NativeFormats", "SwiftManglings.txt");
        var rows = new List<(string, string)>();
        foreach (var line in File.ReadLines(path))
        {
            int arrow = line.IndexOf("--->", StringComparison.Ordinal);
            if (arrow < 0) continue;
            var mangled = line[..arrow].TrimEnd(' ');
            var expected = line[(arrow + 4)..].TrimStart(' ');
            if (expected.StartsWith('{') && expected.IndexOf("} ", StringComparison.Ordinal) is var close and > 0) expected = expected[(close + 2)..];
            rows.Add((mangled, expected));
        }
        return rows;
    }

    [Fact]
    public void The_corpus_matches_swift_demangle()
    {
        var corpus = Corpus();
        var failures = new List<string>();
        foreach (var (mangled, expected) in corpus)
        {
            var got = SwiftDemangler.Demangle(mangled) ?? mangled;
            if (got != expected) failures.Add($"{mangled}\n  expected {expected}\n  got      {got}");
        }
        double rate = 1 - (double)failures.Count / corpus.Count;
        output.WriteLine($"{corpus.Count - failures.Count} of {corpus.Count} match ({rate:P2})");
        foreach (var f in failures) output.WriteLine(f);
        Assert.True(corpus.Count > 500, $"only {corpus.Count} corpus lines");
        Assert.True(rate >= 0.99, $"{failures.Count} of {corpus.Count} differ:\n" + string.Join("\n", failures.Take(15)));
    }

    [Theory]
    [InlineData("_$s12StripeUICore14STPAddressViewC5frameACSo6CGRectV_tcfc", "StripeUICore.STPAddressView.init(frame: __C.CGRect) -> StripeUICore.STPAddressView")]
    [InlineData("__T04main3FooC3barSiyF", "main.Foo.bar() -> Swift.Int")]
    [InlineData("_TtC12StripeUICore14STPAddressView", "StripeUICore.STPAddressView")]
    [InlineData("$sSo8NSObjectC10ObjectiveCE4hashSivg", "(extension in ObjectiveC):__C.NSObject.hash.getter : Swift.Int")]
    public void Symbol_names_demangle(string mangled, string expected) => Assert.Equal(expected, SwiftDemangler.Demangle(mangled));

    [Theory]
    [InlineData("_ZN1A1fEv")]
    [InlineData("-[NSObject init]")]
    [InlineData("main")]
    [InlineData("")]
    public void NotSwift_IsNull(string name) => Assert.Null(SwiftDemangler.Demangle(name));

    /// <summary>Corpus names with random edits: no exception escapes, bounded time.</summary>
    [Fact]
    public void MutatedNames_NeverThrow()
    {
        var names = Corpus().Select(r => r.Mangled).ToList();
        var rng = new Random(20261012);
        const string alphabet = "_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz$.";
        var sw = Stopwatch.StartNew();
        foreach (var name in names)
            for (int k = 0; k < 8; k++)
            {
                var chars = name.ToCharArray().ToList();
                for (int e = rng.Next(1, 4); e > 0 && chars.Count > 3; e--)
                {
                    int at = rng.Next(3, chars.Count);
                    switch (rng.Next(3))
                    {
                        case 0: chars[at] = alphabet[rng.Next(alphabet.Length)]; break;
                        case 1: chars.RemoveAt(at); break;
                        default: chars.Insert(at, alphabet[rng.Next(alphabet.Length)]); break;
                    }
                }
                SwiftDemangler.Demangle(new string([.. chars]));
            }
        // Substitution chains that would print exponentially stop at the output cap.
        Assert.Null(SwiftDemangler.Demangle("$s1a1bV" + string.Concat(Enumerable.Repeat("yAC_ACtG", 40)) + "D"));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), $"took {sw.Elapsed}");
    }
}
