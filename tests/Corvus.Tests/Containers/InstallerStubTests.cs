using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Core.Installers;

namespace Corvus.Tests;

/// <summary>Installers whose payload rides on a native stub: the payload found from the PE layout, listed and extracted.</summary>
public sealed class InstallerStubTests
{
    /// <summary>A PE32 stub with one resource: <paramref name="type"/> is a name, or #n for a numbered type.</summary>
    internal static byte[] Stub(string type, uint id, byte[] data, byte[]? overlay = null)
    {
        var pe = new PeBuilder { Is64 = false, Machine = 0x14C, ImageBase = 0x400000, Characteristics = 0x0102 };
        pe.Add(".text", [0xC3]);
        var rsrc = pe.Add(".rsrc", rva =>
        {
            var b = new PeBlob(rva);
            bool named = !type.StartsWith('#');
            uint Directory(bool name) { b.Zero(12); b.U16((ushort)(name ? 1 : 0)); b.U16((ushort)(name ? 0 : 1)); var entry = b.U32(0); b.U32(0); return entry; }
            var typeEntry = Directory(named);
            var nameDir = b.Here;
            var nameEntry = Directory(false);
            var languageDir = b.Here;
            var languageEntry = Directory(false);
            var leaf = b.Here;
            var dataRva = b.U32(0); b.U32((uint)data.Length); b.U32(0); b.U32(0);
            uint typeName = 0;
            if (named) { typeName = b.Here; b.U16((ushort)type.Length); b.Utf16(type); }
            b.Align(4);
            b.Patch32(dataRva, b.Bytes(data));
            b.Patch32(typeEntry, named ? 0x80000000 | (typeName - rva) : uint.Parse(type[1..]));
            b.Patch32(typeEntry + 4, 0x80000000 | (nameDir - rva));
            b.Patch32(nameEntry, id);
            b.Patch32(nameEntry + 4, 0x80000000 | (languageDir - rva));
            b.Patch32(languageEntry, 1033);
            b.Patch32(languageEntry + 4, leaf - rva);
            return b.ToArray();
        });
        pe.Directories[2] = (rsrc.Rva, (uint)rsrc.Data.Length);
        pe.Overlay = overlay ?? [];
        return pe.Build();
    }

    /// <summary>A cabinet with one stored folder (no checksums).</summary>
    internal static byte[] Cab(params (string Name, byte[] Data)[] files)
    {
        var data = files.SelectMany(f => f.Data).ToArray();
        var blocks = data.Chunk(32768).ToList();
        int filesAt = 36 + 8, entries = files.Sum(f => 16 + Encoding.ASCII.GetByteCount(f.Name) + 1);
        int dataAt = filesAt + entries, size = dataAt + blocks.Sum(b => 8 + b.Length);
        var o = new BinaryWriter(new MemoryStream());
        o.Write("MSCF"u8); o.Write(0); o.Write(size); o.Write(0); o.Write(filesAt); o.Write(0);
        o.Write((byte)3); o.Write((byte)1); o.Write((ushort)1); o.Write((ushort)files.Length); o.Write((ushort)0); o.Write((ushort)0); o.Write((ushort)0);
        o.Write(dataAt); o.Write((ushort)blocks.Count); o.Write((ushort)0);
        uint offset = 0;
        foreach (var (name, bytes) in files)
        {
            o.Write(bytes.Length); o.Write(offset); o.Write((ushort)0); o.Write((ushort)0x5A21); o.Write((ushort)0); o.Write((ushort)0x20);
            o.Write(Encoding.ASCII.GetBytes(name)); o.Write((byte)0);
            offset += (uint)bytes.Length;
        }
        foreach (var b in blocks) { o.Write(0); o.Write((ushort)b.Length); o.Write((ushort)b.Length); o.Write(b); }
        return ((MemoryStream)o.BaseStream).ToArray();
    }

    /// <summary>A Burn stub: a .wixburn section sizing <paramref name="cabinets"/>, which follow the image unsigned.</summary>
    internal static byte[] BurnStub(params byte[][] cabinets)
    {
        var pe = new PeBuilder { Is64 = false, Machine = 0x14C, ImageBase = 0x400000, Characteristics = 0x0102 };
        pe.Add(".text", [0xC3]);
        var header = new byte[48 + 4 * cabinets.Length];
        var section = pe.Add(".wixburn", header);
        pe.Overlay = [.. cabinets.SelectMany(c => c)];
        var image = pe.Build();
        int stub = image.Length - pe.Overlay.Length;
        var w = new BinaryWriter(new MemoryStream(header));
        w.Write(0x00F14300); w.Write(2); w.Write(Guid.Parse("11111111-2222-3333-4444-555555555555").ToByteArray());
        w.Write(stub); w.Write(0); w.Write(0); w.Write(0); w.Write(1); w.Write(cabinets.Length);
        foreach (var c in cabinets) w.Write(c.Length);
        var raw = (int)BitConverter.ToUInt32(image, pe.SectionTableOffset + 40 + 20); // the second section's PointerToRawData
        header.CopyTo(image, raw);
        return image;
    }

    private static byte[] Zip(params (string Name, byte[] Data)[] files)
    {
        var o = new MemoryStream();
        using (var z = new ZipArchive(o, ZipArchiveMode.Create, leaveOpen: true))
            foreach (var (name, data) in files)
                using (var s = z.CreateEntry(name).Open()) s.Write(data);
        return o.ToArray();
    }

    [Fact]
    public void A_Squirrel_setup_lists_its_release_zip_and_names_the_releases()
    {
        var package = Zip(("App.nuspec", "<package/>"u8.ToArray()), ("lib/net45/App.exe", File.ReadAllBytes(Env.FixturePath)));
        var releases = Encoding.ASCII.GetBytes($"{new string('A', 40)} App-1.2.3-full.nupkg {package.Length}\n");
        var setup = Stub("DATA", 131, Zip(("RELEASES", releases), ("App-1.2.3-full.nupkg", package)));
        var reader = new SquirrelSetupReader();
        Assert.True(reader.Accepts(setup, "Setup.exe"));
        Assert.False(reader.Accepts(Stub("DATA", 132, [1]), "Other.exe"));

        var c = Containers.Open(setup, "Setup.exe", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("Squirrel installer", c.Kind);
        Assert.Contains($"Release App-1.2.3-full.nupkg: {package.Length:N0} bytes, SHA-1 {new string('a', 40)}.", c.Notes);
        Assert.Contains(c.Items, i => i.Name == "App-1.2.3-full.nupkg" && i.Bytes.SequenceEqual(package));
    }

    private static byte[] BurnFixture()
    {
        var manifest = """
            <?xml version="1.0" encoding="utf-8"?>
            <BurnManifest xmlns="http://wixtoolset.org/schemas/v4/2008/Burn">
              <UX><Payload Id="ba" FilePath="BA.dll" SourcePath="u0" Packaging="embedded" /></UX>
              <Payload Id="app" FilePath="packages\app.msi" SourcePath="a0" Container="WixAttachedContainer" Packaging="embedded" />
              <Payload Id="web" FilePath="runtime.exe" FileSize="1234" DownloadUrl="https://example.org/runtime.exe" Packaging="external" />
              <Registration><Arp DisplayName="Sample Bundle" DisplayVersion="1.2.3" Publisher="Sample Publisher" /></Registration>
              <Chain><MsiPackage Id="App" /><ExePackage Id="Runtime" /></Chain>
            </BurnManifest>
            """u8.ToArray();
        return BurnStub(Cab(("0", manifest), ("u0", [0x4D, 0x5A, 1])), Cab(("a0", "app package"u8.ToArray())));
    }

    [Fact]
    public void A_Burn_bundle_lists_its_payloads_under_their_manifest_paths()
    {
        var bundle = BurnFixture();
        Assert.True(new BurnBundleReader().Accepts(bundle, "bundle.exe"));
        var c = Containers.Open(bundle, "bundle.exe", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("WiX Burn bundle", c.Kind);
        Assert.Contains("WiX Burn bundle Sample Bundle 1.2.3 by Sample Publisher: bundle id {11111111-2222-3333-4444-555555555555}, 2 cabinet(s), 2 package(s) (1 MsiPackage, 1 ExePackage).", c.Notes);
        Assert.Equal(["ux/manifest.xml", "ux/BA.dll", "packages/app.msi"], c.Items.Select(i => i.Name));
        Assert.Equal("app package"u8.ToArray(), c.Items[2].Bytes);
        Assert.Contains(c.Entries!, e => e is { Path: "runtime.exe", Size: 1234, Detail: "downloaded at install from https://example.org/runtime.exe" });
    }

    /// <summary>
    /// A Unicode NSIS installer, one solid deflate stream: SetOutPath $INSTDIR\sub, File a.txt, File /oname=$PLUGINSDIR\p.dll,
    /// WriteUninstaller $INSTDIR\uninst.exe. <paramref name="wide"/> writes the block headers of a 64-bit build (8-byte offsets).
    /// </summary>
    private static byte[] NsisFixture(bool wide = false)
    {
        var strings = new MemoryStream();
        strings.Write([0, 0]);
        int String(params object[] parts)
        {
            int index = (int)strings.Length / 2;
            foreach (var part in parts)
                strings.Write(part is int variable ? [3, 0, (byte)(variable | 0x80), 0x80] : Encoding.Unicode.GetBytes((string)part));
            strings.Write([0, 0]);
            return index;
        }
        const int InstDir = 21, PluginsDir = 26;
        int[][] code =
        [
            [11, String(InstDir, @"\sub"), 1, 0, 0, 0, 0],
            [20, 0, String("a.txt"), 0, 0, 0, 0],
            [20, 0, String(PluginsDir, @"\p.dll"), 9, 0, 0, 0],
            [62, String(InstDir, @"\uninst.exe"), 16, 0, 0, 0, 0],
        ];
        int entriesAt = 4 + 8 * (wide ? 12 : 8), stringsAt = entriesAt + code.Length * 28, langAt = stringsAt + (int)strings.Length;
        var header = new BinaryWriter(new MemoryStream());
        header.Write(0);
        for (int i = 0; i < 8; i++)
        {
            var (at, count) = i switch { 2 => (entriesAt, code.Length), 3 => (stringsAt, 0), 4 => (langAt, 0), _ => (0, 0) };
            if (wide) header.Write((long)at);
            else header.Write(at);
            header.Write(count);
        }
        foreach (var entry in code) foreach (var v in entry) header.Write(v);
        header.Write(strings.ToArray());
        var h = ((MemoryStream)header.BaseStream).ToArray();

        var data = new BinaryWriter(new MemoryStream());
        foreach (var block in new[] { h, "hello"u8.ToArray(), [0x4D, 0x5A, 0x90], [1, 2] }) { data.Write(block.Length); data.Write(block); }
        var packed = new MemoryStream();
        using (var deflate = new DeflateStream(packed, CompressionLevel.Optimal, leaveOpen: true)) deflate.Write(((MemoryStream)data.BaseStream).ToArray());

        var pe = new PeBuilder { Is64 = false, Machine = 0x14C, ImageBase = 0x400000, Characteristics = 0x0102 };
        pe.Add(".text", [0xC3]);
        int image = pe.Build().Length, first = (image + 511) / 512 * 512;
        var tail = new BinaryWriter(new MemoryStream());
        tail.Write(new byte[first - image]);
        tail.Write(0); tail.Write(0xDEADBEEF); tail.Write("NullsoftInst"u8); tail.Write(h.Length); tail.Write(28 + (int)packed.Length);
        tail.Write(packed.ToArray());
        pe.Overlay = ((MemoryStream)tail.BaseStream).ToArray();
        return pe.Build();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void An_NSIS_installer_lists_its_files_under_their_install_paths(bool wideBlockHeaders)
    {
        var setup = NsisFixture(wideBlockHeaders);
        Assert.True(new NsisInstallerReader().Accepts(setup, "setup.exe"));
        var c = Containers.Open(setup, "setup.exe", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("NSIS installer", c.Kind);
        Assert.Contains(c.Notes, n => n.StartsWith("NSIS installer, Unicode strings: Deflate solid, header of ", StringComparison.Ordinal) && n.EndsWith(" bytes, 2 file(s), an uninstaller.", StringComparison.Ordinal));
        Assert.Equal(["sub/a.txt", "$PLUGINSDIR/p.dll"], c.Items.Select(i => i.Name));
        Assert.Equal("hello"u8.ToArray(), c.Items[0].Bytes);
        Assert.Contains(c.Entries!, e => e.Path == "uninst.exe" && e.Detail!.StartsWith("uninstaller written at install time", StringComparison.Ordinal));
    }

    /// <summary>
    /// An Inno Setup 6.7.0 installer (with <paramref name="older"/>, data 5.5.7 (u): 32-bit sizes, SHA-1, no encryption header)
    /// with uncompressed setup-0 blocks: AppName "Sample", one stored file {app}\a.txt and the uninstaller entry; the offset
    /// table (RCDATA 11111) points past the image.
    /// </summary>
    private static byte[] InnoFixture(bool older = false)
    {
        var content = "inno file"u8.ToArray();
        byte[] Block(byte[] data)
        {
            var o = new BinaryWriter(new MemoryStream());
            var chunks = data.Chunk(4096).ToList();
            var header = new byte[older ? 5 : 9];
            int stored = chunks.Sum(c => 4 + c.Length);
            if (older) BitConverter.TryWriteBytes(header, stored);
            else BitConverter.TryWriteBytes(header, (long)stored);
            o.Write(System.IO.Hashing.Crc32.HashToUInt32(header)); o.Write(header);
            foreach (var c in chunks) { o.Write(System.IO.Hashing.Crc32.HashToUInt32(c)); o.Write(c); }
            return ((MemoryStream)o.BaseStream).ToArray();
        }
        static void Record(BinaryWriter w, string[] strings, int ansi, byte[] fixedPart)
        {
            foreach (var s in strings) { var b = Encoding.Unicode.GetBytes(s); w.Write(b.Length); w.Write(b); }
            for (int i = 0; i < ansi; i++) w.Write(0);
            w.Write(fixedPart);
        }
        var first = new BinaryWriter(new MemoryStream());
        // field offsets per format: header (file counts, strings), file entry (size, strings, location, type)
        var (headerSize, files, strings, fileSize, fileStrings, fileAnsi, locationAt, typeAt) = older ? (157, 28, 28, 43, 10, 0, 20, 42) : (162, 32, 39, 80, 15, 1, 53, 79);
        var header = new byte[headerSize];
        BitConverter.TryWriteBytes(header.AsSpan(files), 2); // file entries
        BitConverter.TryWriteBytes(header.AsSpan(files + 4), 1); // file locations
        Record(first, ["Sample", .. Enumerable.Repeat("", 8), "1.0", .. Enumerable.Repeat("", strings - 10)], 4, header);
        var file = new byte[fileSize];
        BitConverter.TryWriteBytes(file.AsSpan(locationAt), 0);
        Record(first, ["a.txt", @"{app}\a.txt", .. Enumerable.Repeat("", fileStrings - 2)], fileAnsi, file);
        var uninstaller = new byte[fileSize];
        BitConverter.TryWriteBytes(uninstaller.AsSpan(locationAt), -1);
        uninstaller[typeAt] = 1;
        Record(first, ["", @"{app}\unins000.exe", .. Enumerable.Repeat("", fileStrings - 2)], fileAnsi, uninstaller);
        var location = new byte[older ? 74 : 89];
        int sizes = older ? 20 : 24;
        BitConverter.TryWriteBytes(location.AsSpan(sizes), (long)content.Length);
        BitConverter.TryWriteBytes(location.AsSpan(sizes + 8), (long)content.Length);
        (older ? System.Security.Cryptography.SHA1.HashData(content) : System.Security.Cryptography.SHA256.HashData(content)).CopyTo(location, sizes + 16);

        var setup0 = new BinaryWriter(new MemoryStream());
        setup0.Write(Encoding.ASCII.GetBytes((older ? "Inno Setup Setup Data (5.5.7) (u)" : "Inno Setup Setup Data (6.7.0)").PadRight(64, '\0')));
        if (!older)
        {
            var encryption = new byte[49];
            setup0.Write(System.IO.Hashing.Crc32.HashToUInt32(encryption)); setup0.Write(encryption);
        }
        setup0.Write(Block(((MemoryStream)first.BaseStream).ToArray()));
        setup0.Write(Block(location));
        byte[] tail = [.. ((MemoryStream)setup0.BaseStream).ToArray(), .. "zlb\x1a"u8, .. content];

        byte[] Table(long image)
        {
            var t = new byte[64];
            "rDlPtS"u8.CopyTo(t); new byte[] { 0xCD, 0xE6, 0xD7, 0x7B, 0x0B, 0x2A }.CopyTo(t, 6);
            long setup1 = image + tail.Length - 4 - content.Length;
            BitConverter.TryWriteBytes(t.AsSpan(12), older ? 1 : 2);
            if (older) { BitConverter.TryWriteBytes(t.AsSpan(32), (uint)image); BitConverter.TryWriteBytes(t.AsSpan(36), (uint)setup1); }
            else { BitConverter.TryWriteBytes(t.AsSpan(40), image); BitConverter.TryWriteBytes(t.AsSpan(48), setup1); }
            return t;
        }
        int imageSize = Stub("#10", 11111, Table(0), tail).Length - tail.Length;
        return Stub("#10", 11111, Table(imageSize), tail);
    }

    [Fact]
    public void An_Inno_Setup_installer_lists_its_files_under_their_destination_names()
    {
        var setup = InnoFixture();
        Assert.True(new InnoSetupReader().Accepts(setup, "setup.exe"));
        var c = Containers.Open(setup, "setup.exe", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("Inno Setup installer", c.Kind);
        Assert.Contains("Inno Setup installer (data 6.7.0) Sample 1.0: 2 file(s) in 1 data block(s), stored.", c.Notes);
        Assert.Equal("inno file"u8.ToArray(), Assert.Single(c.Items, i => i.Name == "{app}/a.txt").Bytes);
        Assert.Contains(c.Entries!, e => e.Path == "{app}/unins000.exe" && e.Detail!.StartsWith("uninstaller", StringComparison.Ordinal));
        Assert.DoesNotContain(c.Notes, n => n.Contains("stored hash", StringComparison.Ordinal));
    }

    [Fact]
    public void An_Inno_Setup_5_installer_reads_its_32_bit_sizes_and_SHA_1()
    {
        var c = Containers.Open(InnoFixture(older: true), "setup.exe", AnalysisLimits.Default, default, allFiles: true);
        Assert.Contains("Inno Setup installer (data 5.5.7 (u)) Sample 1.0: 2 file(s) in 1 data block(s), stored.", c.Notes);
        Assert.Equal("inno file"u8.ToArray(), Assert.Single(c.Items, i => i.Name == "{app}/a.txt").Bytes);
        Assert.DoesNotContain(c.Notes, n => n.Contains("stored hash", StringComparison.Ordinal));
    }

    [Fact]
    [FuzzEntry(typeof(SquirrelSetupReader), typeof(BurnBundleReader), typeof(NsisInstallerReader), typeof(InnoSetupReader))]
    public void Fuzzed_installer_stubs_never_throw_past_a_tool_error()
    {
        var squirrel = Stub("DATA", 131, Zip(("RELEASES", Encoding.ASCII.GetBytes($"{new string('A', 40)} A-1-full.nupkg 3\n")), ("A-1-full.nupkg", [1, 2, 3])));
        foreach (var seed in new[] { squirrel, BurnFixture(), NsisFixture(), InnoFixture() })
        {
            var failures = FormatFuzz.Run(seed, b =>
            {
                try { Containers.Open(b, "Setup.exe", AnalysisLimits.Default, default, allFiles: true); } catch (ToolError) { }
            }, 300);
            Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
        }
    }
}
