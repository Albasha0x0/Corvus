using System.Formats.Tar;
using System.IO.Compression;
using System.Numerics;
using System.Text;
using FsCheck;
using FsCheck.Fluent;
using Corvus.Core;
using Corvus.Core.Mobile;
using Corvus.Core.Protobuf;
using Corvus.Core.WebAssembly;
using Corvus.Native.Dump;
using Corvus.Native.Elf;
using Corvus.Native.Pe;
using Corvus.Tests.NativeFormats;

namespace Corvus.Tests;

/// <summary>Generated inputs written by test writers read back as written; a failure prints the input and its seed.</summary>
public sealed class ReaderPropertyTests
{
    // Inputs per property in the quick set; 3,000 each ran clean once.
    private const int Runs = 150;

    private static void Holds<T>(Gen<T> gen, Action<T> property) =>
        Check.One(Config.QuickThrowOnFailure.WithMaxTest(Runs).WithQuietOnSuccess(true), Prop.ForAll(gen.ToArbitrary(), property));

    private static Gen<string> Word(int min = 1, int max = 8, string chars = "abcdefghijklmnopqrstuvwxyz0123456789_") =>
        from n in Gen.Choose(min, max)
        from cs in Gen.ArrayOf(Gen.Elements(chars.ToCharArray()), n)
        select new string(cs);

    private static Gen<byte[]> Bytes(int max) =>
        from n in Gen.Choose(0, max)
        from bs in Gen.ArrayOf(Gen.Choose(0, 255).Select(b => (byte)b), n)
        select bs;

    private static Gen<List<T>> Distinct<T, TKey>(Gen<T> item, Func<T, TKey> key, int max) =>
        from n in Gen.Choose(0, max)
        from items in Gen.ListOf(item, n)
        select items.DistinctBy(key).ToList();

    // Binary property lists.

    private static Gen<PlistNode> PlistLeaf() => Gen.OneOf(
        Gen.Choose(int.MinValue, int.MaxValue).Select(i => (PlistNode)new PlistInteger(i)),
        Gen.Elements(long.MaxValue, long.MinValue, (BigInteger)ulong.MaxValue, BigInteger.Pow(2, 100), -BigInteger.Pow(2, 90)).Select(i => (PlistNode)new PlistInteger(i)),
        Gen.Choose(-1_000_000, 1_000_000).Select(i => (PlistNode)new PlistReal(i / 64.0)),
        Gen.Elements(true, false).Select(b => (PlistNode)new PlistBool(b)),
        Gen.Choose(-1_000_000_000, 1_000_000_000).Select(s => (PlistNode)new PlistDate(new DateTimeOffset(2001, 1, 1, 0, 0, 0, TimeSpan.Zero).AddSeconds(s))),
        Bytes(40).Select(b => (PlistNode)new PlistData(b)),
        Word(0, 20).Select(s => (PlistNode)new PlistString(s)),
        Word(1, 20, "aé漢Ωz ").Select(s => (PlistNode)new PlistString(s)),
        Gen.Choose(0, 255).Select(u => (PlistNode)new PlistUid((ulong)u)));

    private static Gen<PlistNode> PlistTree(int size) => size <= 0 ? PlistLeaf() : Gen.Frequency(
        (3, PlistLeaf()),
        (1, from items in Gen.ListOf(PlistTree(size / 3), Math.Min(size, 6))
            from set in Gen.Elements(false, true)
            select (PlistNode)new PlistArray(items, set)),
        (1, from entries in Distinct(Gen.Zip(Word(), PlistTree(size / 3)), e => e.Item1, Math.Min(size, 6))
            select (PlistNode)new PlistDict(entries.Select(e => KeyValuePair.Create(e.Item1, e.Item2)).ToList())));

    [Fact]
    public void A_binary_plist_reads_back_as_the_tree_written()
    {
        Holds(Gen.Sized(s => PlistTree(Math.Min(s, 30))), tree =>
        {
            var doc = Plist.Read(BplistWriter.Write(tree));
            Assert.Empty(doc.Issues);
            Assert.Equal("binary", doc.Format);
            Assert.Equal(Plist.ToJson(tree), Plist.ToJson(doc.Root!));
            Assert.Equal(Sets(tree), Sets(doc.Root!));
        });

        static string Sets(PlistNode n) => n switch
        {
            PlistArray a => (a.IsSet ? "s" : "a") + "(" + string.Concat(a.Items.Select(Sets)) + ")",
            PlistDict d => "d(" + string.Concat(d.Entries.Select(e => Sets(e.Value))) + ")",
            _ => ".",
        };
    }

    // Protobuf file descriptors.

    private sealed record ProtoFieldSpec(string Name, int Number, int Type, int Label);
    private sealed record ProtoMessageSpec(string Name, List<ProtoFieldSpec> Fields);

    // Scalar FieldDescriptorProto types (no message, enum or group references).
    private static readonly int[] ScalarTypes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13, 15, 16, 17, 18];

    private static readonly Gen<ProtoMessageSpec> ProtoMessageGen =
        from name in Word().Select(w => "M" + w)
        from fields in Distinct(
            from n in Word() from number in Gen.Choose(1, 536_870_911) from type in Gen.Elements(ScalarTypes) from label in Gen.Elements(1, 3)
            select new ProtoFieldSpec("f_" + n, number, type, label), f => f.Name, 8)
        select new ProtoMessageSpec(name, fields.DistinctBy(f => f.Number).ToList());

    [Fact]
    public void A_file_descriptor_reads_back_with_its_messages_and_fields()
    {
        var gen = from file in Word().Select(w => w + ".proto")
                  from package in Word()
                  from messages in Distinct(ProtoMessageGen, m => m.Name, 5)
                  select (file, package, messages);
        Holds(gen, spec =>
        {
            var w = new ProtoWriter().Str(1, spec.file).Str(2, spec.package);
            foreach (var m in spec.messages)
                w.Msg(4, mw =>
                {
                    mw.Str(1, m.Name);
                    foreach (var f in m.Fields) mw.Field(2, f.Name, f.Number, f.Type, f.Label);
                });
            var read = ProtoFile.Read(w.Str(12, "proto3").ToArray());
            Assert.NotNull(read);
            Assert.Equal(spec.file, read.Name);
            Assert.Equal(spec.package, read.Package);
            Assert.Equal("proto3", read.Syntax);
            Assert.Equal(spec.messages.Select(m => m.Name), read.Messages.Select(m => m.Name));
            Assert.Equal(spec.messages.SelectMany(m => m.Fields.Select(f => (m.Name, f.Name, f.Number, f.Type, f.Label))),
                read.Messages.SelectMany(m => m.Fields.Select(f => (m.Name, f.Name, f.Number, f.Type, f.Label))));
        });
    }

    // Electron ASAR archives.

    private static readonly Gen<string> AsarPath =
        from depth in Gen.Choose(1, 3)
        // "." and ".." segments are unsafe names, which the reader reports instead of reading.
        from parts in Gen.ArrayOf(Word(1, 6, "abcdefghij.-_").Where(p => p.Trim('.').Length > 0), depth)
        select string.Join('/', parts);

    [Fact]
    public void An_asar_archive_reads_back_with_every_file_and_its_bytes()
    {
        var gen = from files in Distinct(Gen.Zip(AsarPath, Bytes(300)), f => f.Item1, 12)
                  from block in Gen.Elements(16, 64, 4096)
                  select (files: files.Where(f => !files.Any(g => g.Item1.StartsWith(f.Item1 + "/", StringComparison.Ordinal))).ToList(), block);
        Holds(gen, spec =>
        {
            var (bytes, _) = AsarWriter.Build(spec.files.Select(f => new AsarWriter.File(f.Item1, f.Item2)), blockSize: spec.block);
            using var stream = new MemoryStream(bytes);
            var archive = AsarArchive.Read(stream);
            Assert.Empty(archive.Issues);
            Assert.Equal(spec.files.Select(f => f.Item1).Order(StringComparer.Ordinal),
                archive.Entries.Where(e => e.Kind == AsarEntryKind.File).Select(e => e.Path).Order(StringComparer.Ordinal));
            var buffer = Array.Empty<byte>();
            foreach (var (path, data) in spec.files)
            {
                var entry = archive.Find(path)!;
                Assert.Equal(data, archive.ReadPacked(stream, entry, data.Length));
                Assert.StartsWith("ok", archive.Verify(stream, null, entry, ref buffer).Status);
            }
        });
    }

    // PE section tables.

    private sealed record PeSectionSpec(string Name, byte[] Data, uint Extra, uint Characteristics);

    [Fact]
    public void A_pe_image_reads_back_with_its_sections_and_their_bytes()
    {
        var gen = from is64 in Gen.Elements(true, false)
                  from machine in is64 ? Gen.Elements((ushort)0x8664, (ushort)0xAA64) : Gen.Elements((ushort)0x14C, (ushort)0x1C4)
                  from sections in Gen.Choose(1, 6).SelectMany(n => Gen.ListOf(
                      from name in Word(1, 7) from data in Bytes(3000) from extra in Gen.Choose(0, 0x2000)
                      from flags in Gen.Elements(0x60000020u, 0x40000040u, 0xC0000040u)
                      select new PeSectionSpec("." + name, data, (uint)extra, flags), n))
                  select (is64, machine, sections);
        Holds(gen, spec =>
        {
            var builder = new PeBuilder { Is64 = spec.is64, Machine = spec.machine, ImageBase = spec.is64 ? 0x140000000UL : 0x400000UL };
            foreach (var s in spec.sections) builder.Add(s.Name, s.Data, s.Characteristics, (uint)Math.Max(s.Data.Length, 1) + s.Extra);
            var pe = PeFile.FromBytes(builder.Build());
            Assert.Equal(spec.is64, pe.Is64Bit);
            Assert.Equal(builder.Sections.Select(s => (s.Name, s.Rva, s.VirtualSize, s.Characteristics)),
                pe.Sections.Select(s => (s.Name, s.Rva, s.VirtualSize, s.Characteristics)));
            foreach (var s in builder.Sections)
            {
                var read = new byte[s.Data.Length];
                Assert.Equal(read.Length, pe.Read(s.Rva, read));
                Assert.Equal(s.Data, read);
            }
        });
    }

    // ELF dynamic sections and symbol tables.

    [Fact]
    public void An_elf_object_reads_back_with_its_dependencies_symbols_and_exports()
    {
        var symbol = from name in Word().Select(w => "s_" + w)
                     from kind in Gen.Choose(0, 2)
                     from slot in Gen.Choose(0, 15)
                     from bind in Gen.Elements((byte)1, (byte)2)
                     select kind switch
                     {
                         0 => new ElfWriter.Symbol(name, Defined: false),
                         1 => new ElfWriter.Symbol(name, ElfWriter.TextRva + (uint)(slot % 2) * 4, 4, Type: 2, Bind: bind),
                         _ => new ElfWriter.Symbol(name, ElfWriter.DataRva + (uint)slot * 8, 8, Type: 1, Bind: bind),
                     };
        var gen = from target in Gen.Elements((true, ElfWriter.EmX64), (true, ElfWriter.EmAarch64), (false, ElfWriter.EmX86), (false, ElfWriter.EmArm))
                  from hash in Gen.Elements(ElfWriter.HashKind.Sysv, ElfWriter.HashKind.Gnu, ElfWriter.HashKind.Both)
                  from symbols in Distinct(symbol, s => s.Name, 10)
                  from needed in Distinct(Word().Select(w => "lib" + w + ".so"), n => n, 4)
                  from soName in Gen.OneOf(Gen.Constant<string?>(null), Word().Select(w => (string?)("lib" + w + ".so")))
                  select (target, hash, symbols, needed, soName);
        Holds(gen, spec =>
        {
            var writer = new ElfWriter
            {
                Is64 = spec.target.Item1, Machine = spec.target.Item2, UseRel = !spec.target.Item1, Hash = spec.hash,
                Symbols = spec.symbols, Needed = spec.needed, SoName = spec.soName,
            };
            var elf = ElfFile.FromBytes(writer.Build(), "property.so");
            Assert.Equal(spec.needed, elf.Dependencies);
            Assert.Equal(spec.soName, elf.SoName);
            Assert.Equal(spec.symbols.Select(s => s.Name).Order(StringComparer.Ordinal),
                elf.DynamicSymbols.Where(s => s.Name.Length > 0).Select(s => s.Name).Order(StringComparer.Ordinal));
            Assert.Equal(spec.symbols.Where(s => s.Defined).Select(s => (s.Name, s.Value)).Order(),
                elf.Exports.Select(e => (e.Name!, e.Rva)).Order());
        });
    }

    // WebAssembly modules.

    private static readonly Gen<WasmType> WasmNumber = Gen.Elements(WasmType.I32, WasmType.I64, WasmType.F32, WasmType.F64);

    [Fact]
    public void A_wasm_module_reads_back_with_its_types_imports_functions_exports_and_names()
    {
        var gen = from types in Gen.Choose(1, 4).SelectMany(n => Gen.ListOf(
                      from p in Gen.Choose(0, 3).SelectMany(k => Gen.ArrayOf(WasmNumber, k))
                      from r in Gen.Choose(0, 1).SelectMany(k => Gen.ArrayOf(WasmNumber, k))
                      select new WasmFuncType(p, r), n))
                  from imports in Gen.Choose(0, 3).SelectMany(n => Gen.ListOf(from module in Word() from name in Word() from type in Gen.Choose(0, types.Count - 1) select (module, name, type), n))
                  from funcs in Gen.Choose(0, 5).SelectMany(n => Gen.ListOf(Gen.Zip(Gen.Choose(0, types.Count - 1),
                      Gen.Choose(0, 2).SelectMany(k => Gen.ArrayOf(Gen.Zip(Gen.Choose(1, 3).Select(c => (uint)c), WasmNumber), k))), n))
                  from memory in Gen.OneOf(Gen.Constant<(uint, uint?)?>(null),
                      from min in Gen.Choose(0, 4) from max in Gen.OneOf(Gen.Constant<uint?>(null), Gen.Choose(4, 64).Select(m => (uint?)m))
                      select ((uint, uint?)?)((uint)min, max))
                  from exports in Distinct(Gen.Zip(Word(), Gen.Choose(0, Math.Max(0, imports.Count + funcs.Count - 1))), e => e.Item1,
                      imports.Count + funcs.Count == 0 ? 0 : 4)
                  from names in Distinct(Gen.Zip(Gen.Choose(0, Math.Max(0, imports.Count + funcs.Count - 1)), Word()), e => e.Item1,
                      imports.Count + funcs.Count == 0 ? 0 : 4)
                  select (types, imports, funcs, memory, exports, names);
        Holds(gen, spec =>
        {
            var b = new WasmModuleBuilder();
            foreach (var t in spec.types) b.Type(t.Params, t.Results);
            foreach (var (module, name, type) in spec.imports) b.ImportFunc(module, name, (uint)type);
            foreach (var (type, locals) in spec.funcs) b.Func((uint)type, [], locals);
            if (spec.memory is var (min, max)) b.Memory(min, max);
            foreach (var (name, index) in spec.exports) b.Export(name, WasmExternal.Func, (uint)index);
            if (spec.names.Count > 0) b.Names(null, new() { [1] = spec.names.ToDictionary(n => (uint)n.Item1, n => n.Item2) });
            var m = WasmBinary.Read(b.Build());
            Assert.Empty(m.Issues);
            Assert.Equal(spec.types.Select(t => (string.Join(',', t.Params), string.Join(',', t.Results))),
                m.Types.Select(t => (string.Join(',', t.Params), string.Join(',', t.Results))));
            Assert.Equal(spec.imports.Select(i => (i.Item1, i.Item2, WasmExternal.Func, (uint)i.Item3)), m.Imports.Select(i => (i.Module, i.Name, i.Kind, i.TypeIndex)));
            Assert.Equal(spec.funcs.Select(f => (uint)f.Item1), m.Functions);
            Assert.Equal(spec.funcs.Select(f => string.Join(',', f.Item2)), m.Bodies.Select(body => string.Join(',', body.Locals)));
            Assert.Equal(spec.memory is var (min2, max2) ? [new WasmLimits(min2, max2, false, false)] : Array.Empty<WasmLimits>(), m.Memories);
            Assert.Equal(spec.exports.Select(e => (e.Item1, WasmExternal.Func, (uint)e.Item2)), m.Exports.Select(e => (e.Name, e.Kind, e.Index)));
            Assert.Equal(spec.names.Select(n => ((uint)n.Item1, n.Item2)).Order(), m.Names.Functions.Select(n => (n.Key, n.Value)).Order());
        });
    }

    // Android binary XML.

    private static Gen<AxmlWriter.Attr> AxmlAttribute(string name) => Gen.OneOf(
        Word(0, 12).Select(v => AxmlWriter.String(name, v)),
        Gen.Choose(int.MinValue, int.MaxValue).Select(v => AxmlWriter.Int(name, v)),
        Gen.Elements(true, false).Select(v => AxmlWriter.Bool(name, v)));

    private static Gen<AxmlWriter.Node> AxmlTree(int size) =>
        from name in Word()
        from attributes in Distinct(Word(), n => n, 4).SelectMany(names => Gen.CollectToArray(names.Select(AxmlAttribute)))
        from children in size <= 1 ? Gen.Constant(new List<AxmlWriter.Node>()) : Gen.Choose(0, 3).SelectMany(n => Gen.ListOf(AxmlTree(size / 3), n))
        select new AxmlWriter.Node(name, attributes).Add([.. children]);

    [Fact]
    public void An_android_binary_xml_document_reads_back_as_the_tree_written()
    {
        Holds(from utf8 in Gen.Elements(false, true) from root in Gen.Sized(s => AxmlTree(Math.Min(s, 27))) select (utf8, root), spec =>
        {
            var doc = AxmlDocument.Read(AxmlWriter.Write(spec.root, spec.utf8));
            Assert.Empty(doc.Issues);
            Same(spec.root, doc.Root!);
        });

        static void Same(AxmlWriter.Node written, AxmlElement read)
        {
            Assert.Equal(written.Name, read.Name);
            // A string value's data word is its string pool index, which the writer assigns.
            Assert.Equal(written.Attributes.Select(a => (a.Ns, a.Name, a.Raw, a.Type, a.Type == 0x03 ? 0 : a.Data)),
                read.Attributes.Select(a => (a.Namespace, a.Name, a.RawValue, a.Value.DataType, a.Value.DataType == 0x03 ? 0 : a.Value.Data)));
            Assert.Equal(written.Children.Count, read.Children.Count);
            for (int i = 0; i < written.Children.Count; i++) Same(written.Children[i], read.Children[i]);
        }
    }

    // Minidumps.

    [Fact]
    public void A_minidump_reads_back_with_its_modules_threads_and_memory()
    {
        var gen = from modules in Gen.Choose(0, 5).SelectMany(n => Gen.ListOf(from name in Word() from pages in Gen.Choose(1, 0x100) from stamp in Gen.Choose(0, int.MaxValue) select (name, size: (uint)pages * 0x1000, stamp), n))
                  from threads in Distinct(Gen.Zip(Gen.Choose(1, 0xFFFF), Gen.OneOf(Gen.Constant<string?>(null), Word().Select(w => (string?)w))), t => t.Item1, 6)
                  from memory in Gen.Choose(0, 5).SelectMany(n => Gen.ListOf(Bytes(0x800).Where(b => b.Length > 0), n))
                  select (modules, threads, memory);
        Holds(gen, spec =>
        {
            var builder = new MinidumpBuilder();
            for (int i = 0; i < spec.modules.Count; i++)
            {
                var (name, size, stamp) = spec.modules[i];
                builder.Modules.Add(new(0x7FF0_0000_0000UL + (ulong)i * 0x100_0000, size, (uint)stamp, $@"C:\app\{name}.dll"));
            }
            for (int i = 0; i < spec.memory.Count; i++) builder.Memory.Add((0x1000_0000UL + (ulong)i * 0x1_0000, spec.memory[i]));
            foreach (var (id, name) in spec.threads)
                builder.Threads.Add(new((uint)id, 0x2000_0000UL + (ulong)id * 0x1_0000, MinidumpBuilder.ContextX64(0x7FF0_0000_1000, 0x2000_0000), name));
            using var dump = MinidumpFile.FromBytes(builder.Build());
            Assert.Equal(builder.Modules.Select(m => (m.Base, m.Size, m.TimeDateStamp, m.Path)), dump.Modules.Select(m => (m.Base, m.Size, m.TimeDateStamp, m.Path)));
            Assert.Equal(builder.Threads.Select(t => (t.Id, t.StackStart, t.Name)), dump.Threads.Select(t => (t.Id, t.StackStart, t.Name)));
            foreach (var (start, data) in builder.Memory)
            {
                var read = new byte[data.Length];
                Assert.Equal(data.Length, dump.ReadMemory(start, read));
                Assert.Equal(data, read);
            }
        });
    }

    // Tar archives, plain and gzip-compressed.

    [Fact]
    public void A_tar_archive_reads_back_with_every_file_and_its_bytes()
    {
        var path = from depth in Gen.Choose(1, 3)
                   from parts in Gen.ArrayOf(Word(1, 30, "abcdefghij-_.").Where(p => p.Trim('.').Length > 0), depth)
                   select string.Join('/', parts);
        var gen = from format in Gen.Elements(TarEntryFormat.Ustar, TarEntryFormat.Pax, TarEntryFormat.Gnu)
                  from gzip in Gen.Elements(false, true)
                  from files in Distinct(Gen.Zip(path, Bytes(2000)), f => f.Item1, 10)
                  select (format, gzip, files: files.Where(f => !files.Any(g => g.Item1.StartsWith(f.Item1 + "/", StringComparison.Ordinal))).ToList());
        Holds(gen.Where(g => g.files.Count > 0), spec =>
        {
            var tar = new MemoryStream();
            using (var w = new TarWriter(tar, spec.format, leaveOpen: true))
                foreach (var (name, data) in spec.files)
                    w.WriteEntry(Entry(spec.format, name, data));
            var bytes = tar.ToArray();
            if (spec.gzip)
            {
                var gz = new MemoryStream();
                using (var z = new GZipStream(gz, CompressionLevel.Fastest, leaveOpen: true)) z.Write(bytes);
                bytes = gz.ToArray();
            }
            var contents = Containers.Open(bytes, spec.gzip ? "property.tar.gz" : "property.tar", AnalysisLimits.Default, default, allFiles: true);
            Assert.Equal(spec.gzip ? "tar.gz" : "tar", contents.Kind);
            Assert.Equal(spec.files.Select(f => (f.Item1, Convert.ToHexString(f.Item2))), contents.Items.Select(i => (i.Name, Convert.ToHexString(i.Bytes))));
        });

        static TarEntry Entry(TarEntryFormat format, string name, byte[] data)
        {
            TarEntry e = format switch
            {
                TarEntryFormat.Ustar => new UstarTarEntry(TarEntryType.RegularFile, name),
                TarEntryFormat.Pax => new PaxTarEntry(TarEntryType.RegularFile, name),
                _ => new GnuTarEntry(TarEntryType.RegularFile, name),
            };
            e.DataStream = new MemoryStream(data);
            return e;
        }
    }

    // Ar archives with GNU and BSD member names.

    [Fact]
    public void An_ar_archive_reads_back_with_every_member_name_and_its_bytes()
    {
        var gen = from bsd in Gen.Elements(false, true)
                  from members in Distinct(Gen.Zip(Word(1, 30).Select(w => "m_" + w + ".o"), Bytes(500)), m => m.Item1, 10)
                  select (bsd, members);
        Holds(gen.Where(g => g.members.Count > 0), spec =>
        {
            var body = new List<byte>("!<arch>\n"u8.ToArray());
            void Member(string header, byte[] data)
            {
                body.AddRange(Encoding.ASCII.GetBytes($"{header,-16}{0,-12}{0,-6}{0,-6}{"100644",-8}{data.Length,-10}`\n"));
                body.AddRange(data);
                if (data.Length % 2 == 1) body.Add((byte)'\n');
            }
            var table = new StringBuilder();
            var offsets = new Dictionary<string, int>();
            foreach (var (name, _) in spec.members.Where(m => !spec.bsd && m.Item1.Length > 15))
            {
                offsets[name] = table.Length;
                table.Append(name).Append("/\n");
            }
            if (table.Length > 0) Member("//", Encoding.ASCII.GetBytes(table.ToString()));
            foreach (var (name, data) in spec.members)
                if (spec.bsd) Member($"#1/{name.Length}", [.. Encoding.ASCII.GetBytes(name), .. data]);
                else if (offsets.TryGetValue(name, out int at)) Member($"/{at}", data);
                else Member(name + "/", data);

            var contents = Containers.Open([.. body], "property.a", AnalysisLimits.Default, default, allFiles: true);
            Assert.Equal(spec.members.Select(m => (m.Item1, Convert.ToHexString(m.Item2))), contents.Items.Select(i => (i.Name, Convert.ToHexString(i.Bytes))));
        });
    }
}
