using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Corvus.Core;
using Corvus.Core.Firmware.Esp32;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>ESP32 flash images, partition tables, NVS partitions and app images, as esptool, gen_esp32part.py and nvs_tool.py read them.</summary>
public sealed class Esp32FlashTests : IDisposable
{
    private const string EspTool = "CORVUS_ESPTOOL";
    private const string EspIdfTools = "CORVUS_ESP_IDF_TOOLS";
    private const string Esp32Files = "CORVUS_ESP32_FILES";

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private Esp32FileView.Facts View(byte[] bytes, string? table = null, long offset = 0, int? limit = null)
    {
        var path = _dir.File("flash-" + Guid.NewGuid().ToString("N") + ".bin");
        File.WriteAllBytes(path, bytes);
        var f = FileInput.Open(path);
        f.Options = new FileViewOptions("esp32", table, Offset: offset, Limit: limit);
        return (Esp32FileView.Facts)new Esp32FileView().Inspect(f, default)!.Detail;
    }

    [Fact]
    public void An_app_image_reads_its_header_segments_and_description()
    {
        var bytes = Esp32Samples.App();
        var image = Esp32Image.Read(bytes);
        Assert.Equal(("ESP32", Esp32Samples.AppEntry, "DIO", "4MB", "40m"), (image.ChipInfo!.Name, image.Entry, image.FlashMode, image.FlashSize, image.FlashFrequency));
        Assert.Equal(("v1.0", "v3.99", 1, true), (image.MinChipRevision, image.MaxChipRevision, image.LegacyMinRevision, image.WpPinDisabled));
        Assert.Equal(["DROM", "IROM", "IRAM"], image.Segments.Select(s => string.Join("+", s.Regions)));
        Assert.Equal((image.ComputedChecksum, true, bytes.Length), (image.Checksum, image.Sha256Valid, image.Length));
        var app = image.App!;
        Assert.Equal(("sensor", "1.4.2", "v5.4", "Jan  2 2025 12:34:56", 3u), (app.ProjectName, app.Version, app.IdfVersion, app.CompileTime, app.SecureVersion));
        Assert.Equal(("0.1", "1.99", "64 KB"), (app.MinEfuseRevision, app.MaxEfuseRevision, app.MmuPageSize));
        Assert.StartsWith("a0a1a2", app.ElfSha256);
        Assert.Null(image.Bootloader);

        var boot = Esp32Image.Read(Esp32Samples.Bootloader());
        Assert.Equal(("v5.4", "Jan  2 2025 12:00:00", 1u), (boot.Bootloader!.IdfVersion, boot.Bootloader.CompileTime, boot.Bootloader.Version));
        Assert.Null(boot.App);
    }

    [Fact]
    public void A_damaged_image_reports_its_checksum_and_digest_invalid()
    {
        var bytes = Esp32Samples.App();
        bytes[40] ^= 0xFF;
        var image = Esp32Image.Read(bytes);
        Assert.NotEqual(image.ComputedChecksum, image.Checksum);
        Assert.False(image.Sha256Valid);
        Assert.Contains("runs past the end", Assert.Throws<InvalidDataException>(() => Esp32Image.Read(Esp32Samples.App().AsSpan(0, 300))).Message);
    }

    [Fact]
    public void A_partition_table_names_types_subtypes_and_flags_as_gen_esp32part_does()
    {
        var table = Esp32PartitionTable.Read(Esp32Samples.Table(Esp32Samples.Layout));
        Assert.True(table.Md5Valid);
        Assert.Equal(["nvs data/nvs", "phy_init data/phy", "factory app/factory", "ota_0 app/ota_0 encrypted", "storage data/fat readonly"],
            table.Partitions.Select(p => $"{p.Label} {p.TypeName}/{p.SubtypeName}" + (p.Encrypted ? " encrypted" : "") + (p.ReadOnly ? " readonly" : "")));
        Assert.Equal("esp32 partition table", Blob.Identify(Esp32Samples.Table(Esp32Samples.Layout)));

        var forged = Esp32Samples.Table(Esp32Samples.Layout);
        forged[4] ^= 1;
        Assert.False(Esp32PartitionTable.Read(forged).Md5Valid);
        Assert.Contains("MD5", Assert.Single(View(forged).Notes));
        Assert.Null(Esp32PartitionTable.Read(Esp32Samples.Table(Esp32Samples.Layout, md5: false)).Md5Valid);
        var unended = Enumerable.Repeat(Esp32Samples.Table([new("x", 1, 2, 0x9000, 0x1000)])[..32], 96).SelectMany(b => b).ToArray();
        Assert.Contains("no end marker", Assert.Throws<InvalidDataException>(() => Esp32PartitionTable.Read(unended)).Message);
    }

    [Fact]
    public void Nvs_values_resolve_to_namespace_key_type_and_joined_blob()
    {
        var (w, blob) = NvsWriter.Sample();
        var bytes = w.Build();
        Assert.Equal("esp32 nvs", Blob.Identify(bytes));
        var nvs = Esp32Nvs.Read(bytes);
        Assert.Empty(nvs.Notes);
        Assert.Equal(["Full", "Active", "Empty"], nvs.Pages.Select(p => p.State));
        Assert.All(nvs.Pages, p => Assert.True(p.CrcValid));
        Assert.Equal((2, 2), (nvs.Pages[0].Version, nvs.Namespaces.Count));
        foreach (var (ns, key, type, value) in Esp32Samples.SampleValues)
            Assert.Contains(nvs.Entries, e => e.Namespace == ns && e.Key == key && e.Type == type && e.Text == value);
        Assert.Equal([1, 2, 3, 4, 5], nvs.Entries.Single(e => e.Key == "legacy").Data);
        var joined = nvs.Entries.Single(e => e.Key == "calib");
        Assert.Equal(("blob", 1, null), (joined.Type, joined.Page, joined.Note));
        Assert.Equal(blob, joined.Data);
        Assert.Equal(12, nvs.Entries.Count);
    }

    [Fact]
    public void Erased_damaged_and_missing_nvs_entries_are_counted_and_noted()
    {
        var w = new NvsWriter();
        w.Namespace("app", 1);
        var erased = w.Position;
        w.Number(1, "old", 0x04, 7);
        w.Number(1, "new", 0x04, 8);
        var damaged = w.Position;
        w.Number(1, "bent", 0x04, 9);
        w.Variable(1, "text", 0x21, Encoding.ASCII.GetBytes("abc\0"), badCrc: true);
        w.Variable(1, "part", 0x42, [1, 2, 3], chunk: 0);
        w.BlobIndex(1, "part", 6, 2, 0);
        w.Erase(erased.Page, erased.Index);
        w.Damage(damaged.Page, damaged.Index);
        var nvs = Esp32Nvs.Read(w.Build(empty: 0));
        Assert.Equal((8, 1), (nvs.Pages[0].Written, nvs.Pages[0].Erased));
        Assert.DoesNotContain(nvs.Entries, e => e.Key == "old");
        Assert.Contains(nvs.Notes, n => n.StartsWith("1 written entry has a CRC mismatch", StringComparison.Ordinal));
        Assert.Equal("entry CRC mismatch", nvs.Entries.Single(e => e.Key == "Bent").Note);
        Assert.Equal("data CRC mismatch", nvs.Entries.Single(e => e.Key == "text").Note);
        Assert.Equal("chunk(s) 1 of 2 not found", nvs.Entries.Single(e => e.Key == "part").Note);
    }

    [Fact]
    public void The_view_pages_and_filters_nvs_values_by_namespace()
    {
        var (w, _) = NvsWriter.Sample();
        var bytes = w.Build();
        var first = View(bytes, limit: 5);
        Assert.Equal(("nvs partition", 12, 5, 5L), (first.Kind, first.Matching, first.Values.Count, first.Next));
        Assert.Contains("offset=5 lists the next values", first.Notes);
        Assert.Equal(["settings", "network"], Assert.Single(first.Nvs).Namespaces);
        var rest = View(bytes, offset: 10);
        Assert.Equal(2, rest.Values.Count);
        Assert.Null(rest.Next);
        var network = Assert.Single(View(bytes, table: "network").Values);
        Assert.Equal(("ssid", "lab-network"), (network.Key, network.Value));
        var calib = View(bytes, table: "settings").Values.Single(v => v.Key == "calib");
        Assert.Equal((5000, "data"), (calib.Size, calib.Kind));
        Assert.EndsWith("...", calib.Value);
    }

    [Fact]
    public void A_flash_image_shows_its_bootloader_table_partitions_and_nvs()
    {
        var (w, _) = NvsWriter.Sample();
        var flash = Esp32Samples.Flash(w.Build(empty: 1));
        Assert.Equal("esp32 flash", Blob.Identify(flash));
        var view = View(flash);
        Assert.Equal(("flash image", "0x1000"), (view.Kind, view.FlashBase));
        Assert.Equal(["bootloader", "factory"], view.Images.Select(i => i.Partition));
        Assert.Equal("sensor", view.Images[1].App!.ProjectName);
        Assert.Equal("0x18", view.Images[1].Segments[0].FileOffset);
        Assert.Equal(["in the file nvs", "in the file erased (0xFF)", "in the file app image", "8,192 bytes in the file ", "outside the file "],
            view.Partitions.Select(p => $"{p.InFile} {p.Content}"));
        Assert.Equal(12, view.Matching);
        Assert.Equal("nvs", view.Values[0].Partition);
    }

    [Fact]
    public void The_container_extracts_each_partition_in_the_file()
    {
        var (w, _) = NvsWriter.Sample();
        var nvs = w.Build(empty: 1);
        var flash = Esp32Samples.Flash(nvs);
        var c = Containers.Open(flash, "flash.bin", new AnalysisLimits(), default, allFiles: true);
        Assert.Equal("esp32 flash", c.Kind);
        Assert.Equal(["bootloader.bin", "partition-table.bin", "nvs.bin", "phy_init.bin", "factory.bin", "ota_0.bin", "storage.bin"], c.Entries!.Select(e => e.Path));
        Assert.Equal(nvs, c.Items.Single(i => i.Name == "nvs.bin").Bytes[..nvs.Length]);
        Assert.Equal(Esp32Samples.Bootloader(), c.Items.Single(i => i.Name == "bootloader.bin").Bytes);
        Assert.Equal(0x2000, c.Items.Single(i => i.Name == "ota_0.bin").Bytes.Length);
        Assert.DoesNotContain(c.Items, i => i.Name == "storage.bin");
        Assert.Contains("ota_0.bin: 8,192 of 65,536 bytes are in the file", c.Notes);
        Assert.Contains("storage.bin: at 0x30000, past the end of the file", c.Notes);

        var limited = Containers.Open(flash, "flash.bin", new AnalysisLimits { MaxItems = 2 }, default, allFiles: true);
        Assert.Equal(2, limited.Items.Count);
        Assert.Contains("Stopped after 2 files", string.Join("\n", limited.Notes));
    }

    [Fact]
    [FuzzEntry(typeof(Esp32Image), typeof(Esp32PartitionTable), typeof(Esp32Nvs), typeof(Esp32FlashReader), typeof(Esp32FileView))]
    public void Fuzzed_flash_images_never_throw()
    {
        var (w, _) = NvsWriter.Sample();
        var sample = Esp32Samples.Flash(w.Build(empty: 0))[..0x12000];
        var failures = FormatFuzz.Run(sample, b =>
        {
            foreach (int at in (int[])[0, 0x7000, 0x8000, 0xF000])
            {
                if (at >= b.Length) continue;
                try { Esp32Image.Read(b.AsSpan(at)); } catch (InvalidDataException) { }
                try { Esp32PartitionTable.Read(b.AsSpan(at)); } catch (InvalidDataException) { }
            }
            if (b.Length > 0x8000) Esp32Nvs.Read(b.AsSpan(0x8000, (b.Length - 0x8000) / 4096 * 4096));
            try { Containers.Open(b, "flash.bin", new AnalysisLimits { MaxItemBytes = 1 << 20 }, default, allFiles: true); }
            catch (ToolError e) when (e.Code == ErrorCode.MalformedInput) { }
            var file = new FileInput("fuzz.bin", b, Blob.Identify(b)) { Options = new FileViewOptions("esp32", "settings") };
            new Esp32FileView().Inspect(file, default);
        }, 200);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    // esptool image-info (CORVUS_ESPTOOL), gen_esp32part.py and nvs_tool.py (CORVUS_ESP_IDF_TOOLS, run with python) read
    // each flash image, partition table, NVS partition and app image under CORVUS_ESP32_FILES; compared: every header,
    // segment, footer and description line, every partition row, and every NVS page and written value.
    [RequiresRealDataFact(EspTool, EspIdfTools, Esp32Files)]
    [Trait("Speed", "Slow")]
    public void Real_files_read_as_esptool_gen_esp32part_and_nvs_tool_read_them()
    {
        var files = Directory.EnumerateFiles(Environment.GetEnvironmentVariable(Esp32Files)!, "*", SearchOption.AllDirectories).ToList();
        int images = 0, tables = 0, partitions = 0;
        foreach (var file in files)
        {
            var bytes = File.ReadAllBytes(file);
            if (Esp32Flash.Find(bytes) is { } flash)
            {
                CompareImage(file, bytes.AsSpan(flash.BootloaderOffset, flash.Bootloader.Length).ToArray());
                CompareTable(file, bytes.AsSpan(flash.TableOffset, 0xC00).ToArray());
                images++; tables++;
                foreach (var p in flash.Table.Partitions)
                {
                    var (start, length) = flash.InFile(p, bytes.Length);
                    if (length == 0 || p.Encrypted) continue;
                    var part = bytes.AsSpan((int)start, (int)length).ToArray();
                    if (p.Type == 0 && Esp32Image.Looks(part)) { CompareImage($"{file}:{p.Label}", part); images++; }
                    if (p.Type == 1 && p.Subtype == 2 && length == p.Size) { CompareNvs($"{file}:{p.Label}", part); partitions++; }
                }
            }
            else if (Esp32PartitionTable.Is(bytes)) { CompareTable(file, bytes); tables++; }
            else if (Esp32Nvs.Looks(bytes)) { CompareNvs(file, bytes); partitions++; }
            else if (Esp32Image.Looks(bytes)) { CompareImage(file, bytes); images++; }
        }
        Assert.True(images > 0 && tables > 0 && partitions > 0, $"{images} images, {tables} tables, {partitions} NVS partitions");
    }

    private void CompareImage(string name, byte[] bytes)
    {
        var path = _dir.File("image-" + Guid.NewGuid().ToString("N") + ".bin");
        File.WriteAllBytes(path, bytes);
        var reference = Run(Environment.GetEnvironmentVariable(EspTool)!, "image-info", path).Split('\n').Select(l => l.TrimEnd())
            .SkipWhile(l => !l.StartsWith("Entry point", StringComparison.Ordinal))
            .Where(l => l.Length > 0 && !l.StartsWith("===", StringComparison.Ordinal) && !l.StartsWith("---", StringComparison.Ordinal) && !l.Contains(" Image ", StringComparison.Ordinal)
                && l is not ("Segments Information" or "Application Information" or "Bootloader Information") && !l.StartsWith("Segment ", StringComparison.Ordinal))
            .ToList();
        var mine = ImageInfo(Esp32Image.Read(bytes));
        Assert.True(reference.SequenceEqual(mine), $"{name}:\n{string.Join("\n", reference)}\n---\n{string.Join("\n", mine)}");
    }

    // image_info's lines after the image type, in its order and wording.
    private static List<string> ImageInfo(Esp32Image i)
    {
        var lines = new List<string>
        {
            $"Entry point: 0x{i.Entry:x8}", $"Segments: {i.Segments.Count}", $"Flash size: {i.FlashSize}", $"Flash freq: {i.FlashFrequency}", $"Flash mode: {i.FlashMode}",
            $"WP pin: 0x{i.WpPin:x}" + (i.WpPinDisabled ? " (disabled)" : ""),
            "Flash pins drive settings: " + string.Join(", ", new[] { "clk_drv", "q_drv", "d_drv", "cs0_drv", "hd_drv", "wp_drv" }.Select((n, k) => $"{n}: 0x{i.DriveSettings[k]:x}")),
            $"Chip ID: {i.ChipId} ({i.ChipInfo!.Name})",
            $"Minimal chip revision: {i.MinChipRevision}, (legacy min_rev = {i.LegacyMinRevision})",
            $"Maximal chip revision: {i.MaxChipRevision}",
        };
        lines.AddRange(i.Segments.Select((s, k) => $"{k,7}  {Hex(s.Length, 7)}  {Hex(s.LoadAddress, 10)}  {Hex(s.FileOffset - 8, 10)}  {string.Join(", ", s.Regions)}"));
        lines.Add($"Checksum: 0x{i.Checksum:x2} " + (i.Checksum == i.ComputedChecksum ? "(valid)" : $"(invalid - calculated 0x{i.ComputedChecksum:x2})"));
        if (i.HashAppended) lines.Add($"Validation hash: {i.Sha256} ({(i.Sha256Valid == true ? "valid" : "invalid")})");
        if (i.App is { } a)
        {
            lines.AddRange([$"Project name: {a.ProjectName}", $"App version: {a.Version}", $"Compile time: {a.CompileTime}", $"ELF file SHA256: {a.ElfSha256}",
                $"ESP-IDF: {a.IdfVersion}", $"Minimal eFuse block revision: {a.MinEfuseRevision}", $"Maximal eFuse block revision: {a.MaxEfuseRevision}"]);
            if (a.MmuPageSize != null) lines.Add($"MMU page size: {a.MmuPageSize}");
            lines.Add($"Secure version: {a.SecureVersion}");
        }
        else if (i.Bootloader is { } b) lines.AddRange([$"Bootloader version: {b.Version}", $"ESP-IDF: {b.IdfVersion}", $"Compile time: {b.CompileTime}"]);
        return [.. lines.Select(l => l.TrimEnd())];
    }

    // Python's "{:#0Nx}": 0x and lower-case digits, zero-padded to N characters in all.
    private static string Hex(long v, int width) => "0x" + v.ToString("x", CultureInfo.InvariantCulture).PadLeft(width - 2, '0');

    private void CompareTable(string name, byte[] bytes)
    {
        var path = _dir.File("table-" + Guid.NewGuid().ToString("N") + ".bin");
        File.WriteAllBytes(path, bytes);
        var reference = Python("gen_esp32part.py", path).Split('\n').Select(l => l.TrimEnd('\r')).Where(l => l.Length > 0 && !l.StartsWith('#')).ToList();
        static string Size(uint v) => v % 0x100000 == 0 ? $"{v / 0x100000}M" : v % 0x400 == 0 ? $"{v / 0x400}K" : $"0x{v:x}";
        static string Name(string n) => n.StartsWith("0x", StringComparison.Ordinal) ? Convert.ToInt32(n, 16).ToString(CultureInfo.InvariantCulture) : n;
        var mine = Esp32PartitionTable.Read(bytes).Partitions.Select(p => string.Join(",", p.Label, Name(p.TypeName), Name(p.SubtypeName), $"0x{p.Offset:x}", Size(p.Size),
            string.Join(":", new[] { p.Encrypted ? "encrypted" : null, p.ReadOnly ? "readonly" : null }.OfType<string>()))).ToList();
        Assert.True(reference.SequenceEqual(mine), $"{name}:\n{string.Join("\n", reference)}\n---\n{string.Join("\n", mine)}");
    }

    private void CompareNvs(string name, byte[] bytes)
    {
        var path = _dir.File("nvs-" + Guid.NewGuid().ToString("N") + ".bin");
        File.WriteAllBytes(path, bytes);
        using var json = JsonDocument.Parse(Python("nvs_tool.py", "-d", "none", "-f", "json", path));
        var nvs = Esp32Nvs.Read(bytes);
        var pages = json.RootElement.GetProperty("pages").EnumerateArray().ToList();
        Assert.Equal(pages.Count, nvs.Pages.Count);
        var ns = new Dictionary<int, string>();
        var expected = new List<string>();
        var chunks = new Dictionary<(int, string), List<(int Chunk, byte[] Data)>>();
        for (int k = 0; k < pages.Count; k++)
        {
            var page = pages[k];
            var mine = nvs.Pages[k];
            var entries = page.GetProperty("entries").EnumerateArray().ToList();
            // nvs_tool lists an item once, with the entries its data spans as children; the bitmap counts each one.
            int Count(string state) => entries.SelectMany(e => e.GetProperty("children").EnumerateArray().Prepend(e)).Count(e => e.GetProperty("state").GetString() == state);
            Assert.Equal((Count("Written"), Count("Erased"), Count("Empty")), (mine.Written, mine.Erased, mine.Empty));
            if (page.GetProperty("is_empty").GetBoolean()) { Assert.Equal("Empty", mine.State); continue; }
            var header = page.GetProperty("header");
            var crc = header.GetProperty("crc");
            Assert.Equal((header.GetProperty("status").GetString(), header.GetProperty("page_index").GetUInt32(), header.GetProperty("version").GetInt32(),
                crc.GetProperty("original").GetUInt32() == crc.GetProperty("computed").GetUInt32()), (mine.State, mine.Sequence, mine.Version, mine.CrcValid));
            foreach (var e in entries.Where(e => e.GetProperty("state").GetString() == "Written"))
            {
                var meta = e.GetProperty("metadata");
                int space = meta.GetProperty("namespace").GetInt32();
                string type = meta.GetProperty("type").GetString()!, key = e.GetProperty("key").GetString() ?? "(key not ASCII)";
                var data = e.GetProperty("data");
                if (space == 0) { ns[data.GetProperty("value").GetInt32()] = key; continue; }
                if (type == "blob_index") continue;
                byte[] Payload() => [.. e.GetProperty("children").EnumerateArray().SelectMany(c => Convert.FromBase64String(c.GetProperty("raw").GetString()!)).Take(data.GetProperty("size").GetInt32())];
                if (type == "blob_data") (chunks.TryGetValue((space, key), out var l) ? l : chunks[(space, key)] = []).Add((meta.GetProperty("chunk_index").GetInt32(), Payload()));
                else if (type == "string") expected.Add($"{space}:{key}:string:{Encoding.UTF8.GetString(Payload()).TrimEnd('\0')}");
                else if (type == "blob") expected.Add($"{space}:{key}:blob:{Convert.ToHexStringLower(Payload())}");
                else expected.Add($"{space}:{key}:{type}:{data.GetProperty("value").GetRawText()}");
            }
        }
        expected.AddRange(chunks.Select(c => $"{c.Key.Item1}:{c.Key.Item2}:blob:{Convert.ToHexStringLower([.. c.Value.OrderBy(x => x.Chunk).SelectMany(x => x.Data)])}"));
        var names = ns.ToDictionary(x => x.Value, x => x.Key);
        Assert.Equal(ns.OrderBy(x => x.Key), nvs.Namespaces.OrderBy(x => x.Key));
        var actual = nvs.Entries.Select(e => $"{names.GetValueOrDefault(e.Namespace)}:{e.Key}:{e.Type}:" + (e.Data is { } d ? Convert.ToHexStringLower(d) : e.Text));
        Assert.True(expected.Order(StringComparer.Ordinal).SequenceEqual(actual.Order(StringComparer.Ordinal)),
            $"{name}:\n{string.Join("\n", expected.Order(StringComparer.Ordinal))}\n---\n{string.Join("\n", actual.Order(StringComparer.Ordinal))}");
    }

    private static string Python(string script, params string[] args) =>
        Run("python", [Path.Combine(Environment.GetEnvironmentVariable(EspIdfTools)!, script), .. args]);

    private static string Run(string tool, params string[] args)
    {
        var start = new ProcessStartInfo(tool) { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in args) start.ArgumentList.Add(a);
        using var p = Process.Start(start)!;
        var output = p.StandardOutput.ReadToEndAsync();
        var error = p.StandardError.ReadToEndAsync();
        p.WaitForExit();
        Assert.True(p.ExitCode == 0, $"{Path.GetFileName(tool)} {string.Join(' ', args)}: exit {p.ExitCode}: {error.Result}");
        return output.Result;
    }
}
