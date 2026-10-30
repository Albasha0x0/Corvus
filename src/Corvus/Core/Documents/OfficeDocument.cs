using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using System.Xml;

namespace Corvus.Core.Documents;

/// <summary>An object embedded in a document: an OLE Package (file name, source path, bytes) or an OLE stream.</summary>
internal sealed record EmbeddedObject(string Path, string Name, string? SourcePath, byte[] Bytes);

/// <summary>A relationship of an OOXML part to an outside target (template, OLE link, frame, hyperlink).</summary>
internal sealed record ExternalLink(string Part, string Type, string Target);

/// <summary>The OLE class of an object in a document, by display name; Active when opening the object runs code.</summary>
internal sealed record OleObjectClass(string Path, string Name, bool Active);

/// <summary>The active content of an OLE or OOXML Office document: macros, OLE objects, external relationships; nothing is run.</summary>
internal sealed class OfficeDocument
{
    public required string Format { get; set; }
    public List<VbaProject> Projects { get; } = [];
    public XlmMacros? Xlm { get; set; }
    public List<EmbeddedObject> Objects { get; } = [];
    public List<ExternalLink> Links { get; } = [];
    public List<OleObjectClass> Classes { get; } = [];
    public List<string> Notes { get; } = [];
    public bool Encrypted { get; set; }
    public List<MacroFinding> Findings { get; private set; } = [];

    /// <summary>OOXML parts and OLE streams read whole are bounded by this many bytes.</summary>
    private const long MaxPart = 256L << 20;

    public static bool IsOoxml(ZipArchive zip) => zip.GetEntry("[Content_Types].xml") != null;

    /// <summary>The document's active content; null when the bytes are neither a compound file nor an OOXML package.</summary>
    public static OfficeDocument? Read(byte[] data, string name, CancellationToken ct)
    {
        if (CompoundFile.Looks(data)) return FromCompound(CompoundFile.Read(data, name), ct);
        if (RtfObjects.Looks(data))
        {
            var rtf = new OfficeDocument { Format = "Rich Text Format document" };
            RtfObjects.Read(data, rtf, ct);
            rtf.Scan();
            return rtf;
        }
        if (OneNoteReader.Looks(data))
        {
            var one = new OfficeDocument { Format = "OneNote section" };
            var files = OneNoteReader.Files(data, MaxPart, one.Notes, ct);
            var names = OneNoteReader.Names(data);
            var fileNames = OneNoteReader.FileNames([.. files.Select(f => f.Data)], names);
            for (int i = 0; i < files.Count; i++)
                one.Objects.Add(new EmbeddedObject($"0x{files[i].Offset:X}", fileNames[i], null, files[i].Data));
            if (names.Count > 0) one.Notes.Add($"file names in the section: {string.Join(", ", names.Take(20))}");
            one.Scan();
            return one;
        }
        if (XlmMacros.IsSylk(data))
        {
            var slk = new OfficeDocument { Format = "SYLK spreadsheet" };
            if (XlmMacros.FromSylk(data) is { HasMacroSheets: true } x) slk.Xlm = x;
            slk.Scan();
            return slk;
        }
        if (Blob.Identify(data) != "zip") return null;
        try
        {
            using var zip = new ZipArchive(new MemoryStream(data, writable: false), ZipArchiveMode.Read);
            return IsOoxml(zip) ? FromOoxml(zip, name, ct) : null;
        }
        catch (InvalidDataException) { return null; }
    }

    public static string Kind(CompoundFile cf)
    {
        bool Has(string path) => cf.Find(path) != null;
        if (Has("WordDocument")) return "Word document";
        if (Has("Workbook") || Has("Book")) return "Excel workbook";
        if (Has("PowerPoint Document")) return "PowerPoint presentation";
        if (Has("EncryptedPackage")) return "encrypted OOXML package";
        if (cf.Entries.Any(e => e.Name.StartsWith("__substg1.0_", StringComparison.Ordinal))) return "Outlook message";
        if (Has("VBA/dir") && Has("PROJECT")) return "VBA project";
        if (Has("\u0001Ole10Native")) return "OLE Package object";
        return "OLE compound file";
    }

    public static OfficeDocument FromCompound(CompoundFile cf, CancellationToken ct)
    {
        var doc = new OfficeDocument { Format = Kind(cf) };
        doc.ReadCompound(cf, "", ct);
        doc.Notes.AddRange(cf.Notes);
        doc.Scan();
        return doc;
    }

    internal void ReadCompound(CompoundFile cf, string prefix, CancellationToken ct, int depth = 0)
    {
        if (cf.Find("EncryptedPackage") is { } encrypted) Decrypt(cf, encrypted, prefix, ct);
        foreach (var root in VbaProject.Roots(cf).ToList())
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var project = VbaProject.Read(cf, root, MaxPart);
                project.Storage = prefix + root;
                Projects.Add(project);
            }
            catch (ToolError ex) when (ex.Code is ErrorCode.MalformedInput or ErrorCode.LimitExceeded) { Notes.Add($"{prefix}{root}VBA: {ex.Message}"); }
        }
        // The File Information Block's fEncrypted bit; a PowerPoint file keeps an EncryptedSummary stream.
        if (cf.Find("WordDocument") is { } word && cf.Read(word, MaxPart) is { Length: >= 12 } fib && (BinaryPrimitives.ReadUInt16LittleEndian(fib.AsSpan(10)) & 0x0100) != 0)
        {
            Encrypted = true;
            Notes.Add($"{prefix}WordDocument: encrypted (RC4); not decrypted");
        }
        if (cf.Find("EncryptedSummary") != null) { Encrypted = true; Notes.Add($"{prefix}PowerPoint Document: encrypted (RC4 CryptoAPI); not decrypted"); }
        if (cf.Find("PowerPoint Document") is { } ppt && depth < 4) ReadPresentation(cf.Read(ppt, MaxPart), prefix + "PowerPoint Document", ct, depth);
        if ((cf.Find("Workbook") ?? cf.Find("Book")) is { } book)
        {
            var x = XlmMacros.FromBiff(cf.Read(book, MaxPart), ct);
            if (x.Encrypted) { Encrypted = true; Notes.AddRange(x.Notes.Select(n => prefix + "Workbook: " + n)); }
            if (x.HasMacroSheets || x.Encrypted) Xlm = x;
        }
        foreach (var e in cf.Entries.Where(e => !e.IsStorage && e.Name == "\u0001Ole10Native"))
        {
            ct.ThrowIfCancellationRequested();
            if (Ole10Native(cf.Read(e, MaxPart)) is { } package) Objects.Add(package with { Path = prefix + e.Path });
            else Notes.Add($"{prefix}{Printable(e.Path)}: not a readable OLE Package");
        }
    }

    /// <summary>The decrypted OOXML package of an encrypted document, when it opens with the default password.</summary>
    public byte[]? DecryptedPackage { get; private set; }

    private void Decrypt(CompoundFile cf, CompoundEntry package, string prefix, CancellationToken ct)
    {
        Encrypted = true;
        if (cf.Find("EncryptionInfo") is not { } info) { Notes.Add($"{prefix}EncryptedPackage: no EncryptionInfo stream; not decrypted"); return; }
        var (plain, how) = OfficeCrypto.Decrypt(cf.Read(info, 1 << 20), cf.Read(package, MaxPart), MaxPart);
        if (plain == null || Blob.Identify(plain) != "zip") { Notes.Add($"{prefix}EncryptedPackage: not decrypted ({(plain == null ? how : "the result is not a zip package")})"); return; }
        try
        {
            using var zip = new ZipArchive(new MemoryStream(plain, writable: false), ZipArchiveMode.Read);
            ReadOoxml(zip, prefix + "EncryptedPackage/", ct);
            if (DecryptedPackage == null && prefix.Length == 0) Format = OoxmlFormat(zip) + ", encrypted";
            DecryptedPackage ??= plain;
            Notes.Add($"{prefix}EncryptedPackage: decrypted ({how})");
        }
        catch (InvalidDataException ex) { Notes.Add($"{prefix}EncryptedPackage: the decrypted package is not readable: {ex.Message}"); }
    }

    /// <summary>The OLE storages a PowerPoint 97-2003 stream embeds (ExOleObjStg, zlib when instance 1), the VBA project among them.</summary>
    private void ReadPresentation(byte[] s, string where, CancellationToken ct, int depth)
    {
        int pos = 0, records = 0;
        while (pos + 8 <= s.Length)
        {
            if ((++records & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            int verInstance = BinaryPrimitives.ReadUInt16LittleEndian(s.AsSpan(pos));
            int type = BinaryPrimitives.ReadUInt16LittleEndian(s.AsSpan(pos + 2));
            long len = BinaryPrimitives.ReadUInt32LittleEndian(s.AsSpan(pos + 4));
            // A container: its records follow.
            if ((verInstance & 0xF) == 0xF) { pos += 8; continue; }
            if (pos + 8 + len > s.Length) break;
            if (type == 0x1011)
            {
                var body = s.AsSpan(pos + 8, (int)len);
                var storage = (verInstance >> 4) == 1 ? body.Length > 4 ? Blob.TryDecompress(body[4..], "zlib", MaxPart) : null : body.ToArray();
                var at = $"{where}/ExOleObjStg@0x{pos:X}/";
                if (storage != null && CompoundFile.Looks(storage))
                {
                    try { ReadCompound(CompoundFile.Read(storage, at), at, ct, depth + 1); }
                    catch (ToolError ex) when (ex.Code is ErrorCode.MalformedInput or ErrorCode.LimitExceeded) { Notes.Add(ex.Message); }
                }
                else if (storage == null) Notes.Add($"{at}: not zlib data");
            }
            pos += 8 + (int)len;
        }
    }

    /// <summary>An OLE Package stream (\x01Ole10Native): the file name, source path and data it carries; null when damaged.</summary>
    public static EmbeddedObject? Ole10Native(byte[] s)
    {
        try
        {
            int at = 4;
            if (s.Length < 8) return null;
            at += 2; // flags
            string ReadZ()
            {
                int end = Array.IndexOf(s, (byte)0, at);
                if (end < 0) throw new InvalidDataException();
                var v = Encoding.Latin1.GetString(s, at, end - at);
                at = end + 1;
                return v;
            }
            var label = ReadZ();
            var source = ReadZ();
            at += 4; // unknown
            int tempLen = BinaryPrimitives.ReadInt32LittleEndian(s.AsSpan(at));
            at += 4;
            if (tempLen < 0 || at + tempLen > s.Length) return null;
            at += tempLen;
            int size = BinaryPrimitives.ReadInt32LittleEndian(s.AsSpan(at));
            at += 4;
            if (size < 0 || at + size > s.Length) return null;
            var name = Path.GetFileName(label.Replace('\\', '/'));
            return new EmbeddedObject("", name.Length > 0 ? name : Path.GetFileName(source.Replace('\\', '/')), source.Length > 0 ? source : null, s.AsSpan(at, size).ToArray());
        }
        catch (Exception ex) when (ex is InvalidDataException or ArgumentOutOfRangeException) { return null; }
    }

    private static OfficeDocument FromOoxml(ZipArchive zip, string name, CancellationToken ct)
    {
        var doc = new OfficeDocument { Format = OoxmlFormat(zip) };
        doc.ReadOoxml(zip, "", ct);
        doc.Scan();
        return doc;
    }

    private static string OoxmlFormat(ZipArchive zip) =>
        zip.Entries.Any(e => e.FullName.StartsWith("word/", StringComparison.Ordinal)) ? "Word document (OOXML)"
        : zip.Entries.Any(e => e.FullName.StartsWith("xl/", StringComparison.Ordinal)) ? "Excel workbook (OOXML)"
        : zip.Entries.Any(e => e.FullName.StartsWith("ppt/", StringComparison.Ordinal)) ? "PowerPoint presentation (OOXML)" : "OOXML package";

    /// <summary>The VBA projects, embedded objects, external links and macro sheets of an OOXML package, paths under <paramref name="prefix"/>.</summary>
    private void ReadOoxml(ZipArchive zip, string prefix, CancellationToken ct)
    {
        foreach (var entry in zip.Entries)
        {
            ct.ThrowIfCancellationRequested();
            var lower = entry.FullName.ToLowerInvariant();
            if (lower.EndsWith("/vbaproject.bin", StringComparison.Ordinal) || lower.Contains("/embeddings/", StringComparison.Ordinal) && lower.EndsWith(".bin", StringComparison.Ordinal)
                || lower.Contains("/activex/", StringComparison.Ordinal) && lower.EndsWith(".bin", StringComparison.Ordinal))
            {
                if (entry.Length > MaxPart) { Notes.Add($"{prefix}{entry.FullName}: over {MaxPart >> 20} MiB, not read"); continue; }
                var bytes = ReadEntry(entry);
                if (!CompoundFile.Looks(bytes))
                {
                    if (lower.Contains("/embeddings/", StringComparison.Ordinal)) Objects.Add(new EmbeddedObject(prefix + entry.FullName, entry.Name, null, bytes));
                    continue;
                }
                try
                {
                    var cf = CompoundFile.Read(bytes, entry.FullName);
                    ReadCompound(cf, prefix + entry.FullName + "/", ct);
                    if (lower.Contains("/embeddings/", StringComparison.Ordinal) && cf.Find("Ole10Native") == null)
                        Objects.Add(new EmbeddedObject(prefix + entry.FullName, entry.Name, null, bytes));
                }
                catch (ToolError ex) when (ex.Code == ErrorCode.MalformedInput) { Notes.Add(ex.Message); }
            }
            else if (lower.Contains("/embeddings/", StringComparison.Ordinal) && entry.Length > 0)
            {
                if (entry.Length <= MaxPart) Objects.Add(new EmbeddedObject(prefix + entry.FullName, entry.Name, null, ReadEntry(entry)));
            }
            else if (lower.EndsWith(".rels", StringComparison.Ordinal))
                ReadLinks(entry, prefix);
        }
        if (zip.Entries.Any(e => e.FullName.StartsWith("xl/", StringComparison.Ordinal)) && XlmMacros.FromOoxml(zip, ct) is { HasMacroSheets: true } x) Xlm = x;
    }

    private void ReadLinks(ZipArchiveEntry rels, string prefix)
    {
        XmlDocument xml;
        try { xml = XlmMacros.Load(rels); }
        catch (ToolError ex) { Notes.Add(ex.Message); return; }
        foreach (XmlElement r in xml.GetElementsByTagName("Relationship"))
        {
            if (!string.Equals(r.GetAttribute("TargetMode"), "External", StringComparison.OrdinalIgnoreCase)) continue;
            var type = r.GetAttribute("Type");
            Links.Add(new ExternalLink(prefix + rels.FullName, type[(type.LastIndexOf('/') + 1)..], r.GetAttribute("Target")));
        }
    }

    private static byte[] ReadEntry(ZipArchiveEntry e)
    {
        using var s = e.Open();
        using var ms = new MemoryStream();
        var buffer = new byte[81920];
        int n;
        while ((n = s.Read(buffer, 0, buffer.Length)) > 0)
        {
            if (ms.Length + n > MaxPart) throw new ToolError(ErrorCode.LimitExceeded, $"{e.FullName} decompresses past {MaxPart >> 20} MiB.");
            ms.Write(buffer, 0, n);
        }
        return ms.ToArray();
    }

    /// <summary>Module file name as written out: the module name with .bas, .cls or .frm.</summary>
    public static string ModuleFile(VbaModule m) => m.Name + m.Type switch { "standard" => ".bas", "form" => ".frm", _ => ".cls" };

    public static string Printable(string path) => string.Concat(path.Select(c => c < 32 ? $"\\x{(int)c:X2}" : c.ToString()));

    /// <summary>Extensions Windows runs or hands to a script host when an embedded file is opened.</summary>
    private static readonly HashSet<string> Runnable =
        [".exe", ".dll", ".scr", ".com", ".pif", ".hta", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".ps1", ".lnk", ".chm", ".cpl", ".msi", ".jar", ".reg", ".url", ".iso", ".img", ".vhd", ".vhdx"];

    private void Scan()
    {
        var texts = Projects.SelectMany(p => p.Modules.Select(m => (m.Name, m.Source))).ToList();
        if (Xlm != null && Xlm.Text.Length > 0) texts.Add(("xlm", Xlm.Text));
        Findings = MacroScan.Scan(texts);
        if (Xlm?.HasMacroSheets == true) Findings.Add(new MacroFinding("Suspicious", "XLM macro", "Excel 4.0 macro sheets, which can run commands"));
        foreach (var c in Classes.Where(c => c.Active))
            Findings.Add(new MacroFinding("OleClass", c.Name, $"an embedded or linked {c.Name} object") { Location = c.Path });
        foreach (var link in Links.Where(l => l.Type is "template" or "objautlink"))
            Findings.Add(new MacroFinding("Template", link.Target, $"a remote {link.Type} target, loaded when the document opens") { Location = link.Part });
        foreach (var link in Links.Where(l => l.Type is "attachedTemplate" or "oleObject" or "frame" or "subDocument"))
            Findings.Add(new MacroFinding("IOC", link.Target, $"external {link.Type} relationship, loaded when the document opens") { Location = link.Part });
        foreach (var o in Objects)
        {
            var ext = Path.GetExtension(o.Name).ToLowerInvariant();
            if (Runnable.Contains(ext))
                Findings.Add(new MacroFinding("Suspicious", o.Name, $"an embedded {ext} file, which opens or runs when double-clicked") { Location = o.Path });
            // A stored name can hide the content: a script or program named as a document.
            else if (Format == "OneNote section" && OneNoteReader.Extension(o.Bytes) is var sniffed && Runnable.Contains(sniffed))
                Findings.Add(new MacroFinding("Suspicious", o.Name, $"an embedded file named {ext} whose content reads as {sniffed}") { Location = o.Path });
        }
        foreach (var m in Projects.SelectMany(p => p.Modules).Where(m => m.SourceMissing))
            Findings.Add(new MacroFinding("Suspicious", "VBA source missing", $"module {m.Name} has no readable source text at its offset (removed or damaged)") { Location = m.Stream });
    }
}
