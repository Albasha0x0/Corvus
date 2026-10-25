using System.Text;
using System.Text.RegularExpressions;
using Corvus.Native;
using Corvus.Native.MachO;
using Corvus.Native.Providers;
using Xunit.Abstractions;

namespace Corvus.Tests.NativeFormats;

/// <summary>Code requirements decoded from a Mach-O signature's requirement set into codesign's text form.</summary>
public sealed partial class CodeRequirementsTests(ITestOutputHelper output)
{
    private const string DeveloperIdCa = "1.2.840.113635.100.6.2.6", DeveloperIdLeaf = "1.2.840.113635.100.6.1.13";

    /// <summary>Compiles requirement expressions as csreq does: big-endian opcodes, data as a length then bytes padded to 4.</summary>
    internal static class Req
    {
        public static byte[] Op(uint op, params byte[][] operands)
        {
            var w = new ByteWriter(true);
            w.U32(op);
            foreach (var o in operands) w.Bytes(o);
            return w.ToArray();
        }

        public static byte[] U32(uint v) => Op(v);
        public static byte[] Data(byte[] bytes)
        {
            var w = new ByteWriter(true);
            w.U32((uint)bytes.Length);
            w.Bytes(bytes);
            w.Align(4);
            return w.ToArray();
        }

        public static byte[] Text(string s) => Data(Encoding.ASCII.GetBytes(s));
        public static byte[] Identifier(string s) => Op(2, Text(s));
        public static byte[] AppleAnchor => Op(3);
        public static byte[] AppleGenericAnchor => Op(15);
        public static byte[] And(byte[] a, byte[] b) => Op(6, a, b);
        public static byte[] Or(byte[] a, byte[] b) => Op(7, a, b);
        public static byte[] Not(byte[] a) => Op(9, a);
        public static byte[] CertField(int slot, string field, uint match, string? value = null) =>
            Op(11, U32((uint)slot), Text(field), U32(match), value == null ? [] : Text(value));
        public static byte[] CertGeneric(int slot, string oid, uint match) => Op(14, U32((uint)slot), Data(Oid(oid)), U32(match));
        public static byte[] CdHash(byte[] hash) => Op(8, Data(hash));

        /// <summary>A requirement set of (type, expression) entries, each wrapped as an expression requirement.</summary>
        public static byte[] Set(params (uint Type, byte[] Expr)[] entries)
        {
            var blobs = entries.Select(e =>
            {
                var w = new ByteWriter(true);
                w.U32(0xFADE0C00); w.U32((uint)e.Expr.Length + 12); w.U32(1); w.Bytes(e.Expr);
                return w.ToArray();
            }).ToList();
            var set = new ByteWriter(true);
            set.U32(0xFADE0C01);
            set.U32((uint)(12 + 8 * blobs.Count + blobs.Sum(b => b.Length)));
            set.U32((uint)blobs.Count);
            int at = 12 + 8 * blobs.Count;
            for (int i = 0; i < blobs.Count; i++) { set.U32(entries[i].Type); set.U32((uint)at); at += blobs[i].Length; }
            foreach (var b in blobs) set.Bytes(b);
            return set.ToArray();
        }

        private static byte[] Oid(string dotted)
        {
            var parts = dotted.Split('.').Select(ulong.Parse).ToArray();
            var bytes = new List<byte> { (byte)(parts[0] * 40 + parts[1]) };
            foreach (var p in parts.Skip(2))
            {
                var chunk = new Stack<byte>();
                chunk.Push((byte)(p & 0x7F));
                for (var v = p >> 7; v != 0; v >>= 7) chunk.Push((byte)(0x80 | (v & 0x7F)));
                bytes.AddRange(chunk);
            }
            return [.. bytes];
        }
    }

    private static IReadOnlyList<CodeRequirement> Read(byte[] set)
    {
        var w = FormatWriterTests.SampleMachO();
        w.CodeSignature = new("com.example.ledger", "ABCDE12345", Requirements: set);
        var m = MachOFile.FromBytes(w.Build());
        Assert.Empty(m.Issues);
        return m.CodeSignature!.Requirements!;
    }

    [Fact]
    public void A_Developer_ID_designated_requirement_reads_as_codesign_prints_it()
    {
        var designated = Req.And(Req.Identifier("com.example.ledger"), Req.And(Req.AppleGenericAnchor, Req.And(Req.CertGeneric(1, DeveloperIdCa, 0),
            Req.And(Req.CertGeneric(0, DeveloperIdLeaf, 0), Req.CertField(0, "subject.OU", 1, "ABCDE12345")))));
        var r = Assert.Single(Read(Req.Set((3, designated))));
        Assert.Equal("designated => identifier \"com.example.ledger\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */" +
            " and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = ABCDE12345", r.ToString());
        Assert.False(r.Partial);
    }

    [Fact]
    public void An_or_inside_an_and_keeps_its_parentheses_and_values_are_quoted_only_when_needed()
    {
        var host = Req.And(Req.Or(Req.Identifier("com.example.a"), Req.Identifier("b")), Req.Not(Req.Or(Req.AppleAnchor, Req.CdHash([0xAB, 0xCD]))));
        var library = Req.Or(Req.And(Req.AppleAnchor, Req.CertField(-1, "subject.CN", 3, "Example CA")), Req.CertField(0, "subject.OU", 1, "9ABCDE1234"));
        var list = Read(Req.Set((1, host), (4, library)));
        Assert.Equal(["host => (identifier \"com.example.a\" or identifier b) and ! (anchor apple or cdhash H\"abcd\")",
            "library => anchor apple and certificate root[subject.CN] = \"Example CA\"* or certificate leaf[subject.OU] = \"9ABCDE1234\""], list.Select(r => r.ToString()));
    }

    [Fact]
    public void An_unknown_opcode_keeps_the_text_before_it_and_marks_the_requirement_partial()
    {
        var r = Assert.Single(Read(Req.Set((3, Req.And(Req.Identifier("ledger"), Req.Op(99))))));
        Assert.Equal("identifier ledger and /* unknown opcode 99 */", r.Text);
        Assert.True(r.Partial);
    }

    [Fact]
    [FuzzEntry(typeof(CodeRequirements))]
    public void Mutated_requirement_sets_never_throw()
    {
        var seed = Req.Set((3, Req.And(Req.Identifier("com.example.ledger"), Req.And(Req.AppleGenericAnchor, Req.CertGeneric(1, DeveloperIdCa, 0)))),
            (1, Req.Or(Req.Not(Req.CdHash([1, 2, 3])), Req.CertField(-1, "subject.CN", 4, "CA"))));
        var failures = FormatFuzz.Run([seed], 3000, 20261025, bytes => _ = CodeRequirements.Parse(bytes, new Corvus.Native.Pe.IssueLog("fuzz")).Sum(r => r.Text.Length));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }

    // rcodesign's form parenthesizes every operand and quotes every string; without both, the tokens must be equal.
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_RCODESIGN")]
    public void Real_signed_libraries_read_the_requirements_rcodesign_prints()
    {
        var files = new[]
        {
            RealPackages.File("Microsoft.Diagnostics.DbgShim.osx-arm64", "9.0.621003", "runtimes", "osx-arm64", "native", "libdbgshim.dylib"),
            RealPackages.File("Microsoft.Diagnostics.DbgShim.osx-x64", "9.0.621003", "runtimes", "osx-x64", "native", "libdbgshim.dylib"),
            RealPackages.File("Microsoft.NETCore.App.Host.osx-arm64", "10.0.11", "runtimes", "osx-arm64", "native", "libnethost.dylib"),
        };
        var tool = ExternalTools.Locate(ExternalTools.RCodesign)!.Value.Path;
        foreach (var file in files)
        {
            var run = ExternalTools.Run(tool, ExternalTools.Arguments(ExternalTools.RCodesign, "signature", ("file", file)), TimeSpan.FromMinutes(2), 1 << 22, default);
            Assert.True(run.ExitCode == 0, run.Stderr);
            var expected = RCodesignRequirement().Matches(run.Text).Select(m => $"{m.Groups["type"].Value} => {Tokens(m.Groups["expr"].Value)}").ToList();
            var ours = ((MachOFile)NativeImageLoader.Open(file)).CodeSignature!.Requirements!;
            output.WriteLine($"{Path.GetFileName(file)}: {string.Join("; ", ours)}");
            Assert.NotEmpty(expected);
            Assert.Equal(expected, ours.Select(r => $"{r.TypeName} => {Tokens(r.Text)}"));
            Assert.All(ours, r => Assert.False(r.Partial));
        }

        static string Tokens(string text) => text.Replace("(", "", StringComparison.Ordinal).Replace(")", "", StringComparison.Ordinal).Replace("\"", "", StringComparison.Ordinal);
    }

    // - 'designated(3): 0: (identifier "x") and (...);'
    [GeneratedRegex(@"- '(?<type>[a-z]+)\(\d+\): \d+: (?<expr>.*);'")]
    private static partial Regex RCodesignRequirement();
}
