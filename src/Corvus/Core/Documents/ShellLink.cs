using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Documents;

/// <summary>
/// A Windows shortcut (.lnk, MS-SHLLINK): header flags, times and show command; the target from the ID list (shell items
/// with their long names) and the link info (local path, volume serial and label, network share); the name, relative
/// path, working directory, arguments and icon strings; the extra data blocks (environment target, tracker machine id and
/// MAC address, known and special folders, shim layer, installer descriptor); and any data appended after the last block.
/// </summary>
internal sealed class ShellLink
{
    public uint Flags { get; private set; }
    public uint Attributes { get; private set; }
    public DateTime? Created { get; private set; }
    public DateTime? Accessed { get; private set; }
    public DateTime? Modified { get; private set; }
    public uint TargetSize { get; private set; }
    public string ShowCommand { get; private set; } = "normal";
    public string? HotKey { get; private set; }
    public string? IdListPath { get; private set; }
    public string? LocalPath { get; private set; }
    public string? NetworkPath { get; private set; }
    public string? DriveType { get; private set; }
    public string? VolumeSerial { get; private set; }
    public string? VolumeLabel { get; private set; }
    public string? Name { get; private set; }
    public string? RelativePath { get; private set; }
    public string? WorkingDirectory { get; private set; }
    public string? Arguments { get; private set; }
    public string? IconLocation { get; private set; }
    public int IconIndex { get; private set; }
    public string? EnvironmentTarget { get; private set; }
    public string? IconEnvironment { get; private set; }
    public string? MachineId { get; private set; }
    public string? MacAddress { get; private set; }
    public string? Droid { get; private set; }
    public string? KnownFolder { get; private set; }
    public int? SpecialFolder { get; private set; }
    public string? ShimLayer { get; private set; }
    public string? InstallerDescriptor { get; private set; }
    public List<string> FlagNames { get; } = [];
    public List<string> ExtraBlocks { get; } = [];
    public List<string> Notes { get; } = [];
    /// <summary>Bytes after the terminal extra data block (data appended to the shortcut).</summary>
    public byte[] Overlay { get; private set; } = [];
    public long OverlayOffset { get; private set; }

    private static readonly Guid LinkClsid = new("00021401-0000-0000-C000-000000000046");

    private static readonly string[] FlagList =
    [
        "HasLinkTargetIDList", "HasLinkInfo", "HasName", "HasRelativePath", "HasWorkingDir", "HasArguments", "HasIconLocation", "IsUnicode",
        "ForceNoLinkInfo", "HasExpString", "RunInSeparateProcess", "Unused1", "HasDarwinID", "RunAsUser", "HasExpIcon", "NoPidlAlias", "Unused2",
        "RunWithShimLayer", "ForceNoLinkTrack", "EnableTargetMetadata", "DisableLinkPathTracking", "DisableKnownFolderTracking",
        "DisableKnownFolderAlias", "AllowLinkToLink", "UnaliasOnSave", "PreferEnvironmentPath", "KeepLocalIDListForUNCTarget",
    ];

    public static bool Looks(ReadOnlySpan<byte> b) => b.Length >= 76 && BinaryPrimitives.ReadUInt32LittleEndian(b) == 0x4C && new Guid(b.Slice(4, 16)) == LinkClsid;

    /// <summary>The shortcut's target as the shell resolves it: the environment target when it prefers one, else the local or network path, else the ID list.</summary>
    public string? Target => (Flags & 0x02000000) != 0 && EnvironmentTarget != null ? EnvironmentTarget
        : LocalPath ?? NetworkPath ?? IdListPath ?? EnvironmentTarget;

    public static ShellLink Read(byte[] data, string name)
    {
        if (!Looks(data)) throw new ToolError(ErrorCode.MalformedInput, $"{name} is not a shell link (no 0x4C header with the link class id).");
        var link = new ShellLink();
        try { link.Parse(data); }
        catch (ArgumentOutOfRangeException) { link.Notes.Add("the shortcut ends inside a structure; later fields are missing"); }
        return link;
    }

    private void Parse(byte[] d)
    {
        var s = d.AsSpan();
        Flags = BinaryPrimitives.ReadUInt32LittleEndian(s[20..]);
        Attributes = BinaryPrimitives.ReadUInt32LittleEndian(s[24..]);
        Created = Time(s[28..]);
        Accessed = Time(s[36..]);
        Modified = Time(s[44..]);
        TargetSize = BinaryPrimitives.ReadUInt32LittleEndian(s[52..]);
        IconIndex = BinaryPrimitives.ReadInt32LittleEndian(s[56..]);
        ShowCommand = BinaryPrimitives.ReadUInt32LittleEndian(s[60..]) switch { 3 => "maximized", 7 => "minimized, not activated", 1 => "normal", var v => $"normal ({v})" };
        int hot = BinaryPrimitives.ReadUInt16LittleEndian(s[64..]);
        if (hot != 0) HotKey = $"{((hot >> 8) & 1) switch { 1 => "Shift+", _ => "" }}{((hot >> 8) & 2) switch { 2 => "Ctrl+", _ => "" }}{((hot >> 8) & 4) switch { 4 => "Alt+", _ => "" }}0x{hot & 0xFF:X2}";
        for (int i = 0; i < FlagList.Length; i++) if ((Flags & (1u << i)) != 0 && !FlagList[i].StartsWith("Unused", StringComparison.Ordinal)) FlagNames.Add(FlagList[i]);
        int pos = 76;
        if ((Flags & 0x01) != 0)
        {
            int size = BinaryPrimitives.ReadUInt16LittleEndian(s[pos..]);
            IdListPath = IdList(s.Slice(pos + 2, size));
            pos += 2 + size;
        }
        if ((Flags & 0x02) != 0 && (Flags & 0x100) == 0)
        {
            int size = (int)BinaryPrimitives.ReadUInt32LittleEndian(s[pos..]);
            LinkInfo(s.Slice(pos, Math.Max(size, 0)));
            pos += Math.Max(size, 4);
        }
        bool unicode = (Flags & 0x80) != 0;
        string? Str(uint flag)
        {
            if ((Flags & flag) == 0) return null;
            int count = BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(pos));
            int bytes = unicode ? count * 2 : count;
            var v = unicode ? Encoding.Unicode.GetString(d.AsSpan(pos + 2, bytes)) : Encoding.Latin1.GetString(d.AsSpan(pos + 2, bytes));
            pos += 2 + bytes;
            return v;
        }
        Name = Str(0x04);
        RelativePath = Str(0x08);
        WorkingDirectory = Str(0x10);
        Arguments = Str(0x20);
        IconLocation = Str(0x40);
        // extra data blocks until the terminal block (size under 4)
        while (pos + 4 <= d.Length)
        {
            int size = (int)BinaryPrimitives.ReadUInt32LittleEndian(s[pos..]);
            if (size < 4) { pos += 4; break; }
            if (pos + size > d.Length || size < 8) { Notes.Add($"extra data block at 0x{pos:X} runs past the end"); pos = d.Length; break; }
            Extra(BinaryPrimitives.ReadUInt32LittleEndian(s[(pos + 4)..]), s.Slice(pos + 8, size - 8));
            pos += size;
        }
        if (pos < d.Length)
        {
            OverlayOffset = pos;
            Overlay = d[pos..];
        }
    }

    private static DateTime? Time(ReadOnlySpan<byte> b)
    {
        long ft = BinaryPrimitives.ReadInt64LittleEndian(b);
        return ft > 0 && ft < DateTime.MaxValue.ToFileTimeUtc() ? DateTime.FromFileTimeUtc(ft) : null;
    }

    private static readonly Dictionary<Guid, string> RootFolders = new()
    {
        [new Guid("20D04FE0-3AEA-1069-A2D8-08002B30309D")] = "This PC", [new Guid("450D8FBA-AD25-11D0-98A8-0800361B1103")] = "Documents",
        [new Guid("208D2C60-3AEA-1069-A2D7-08002B30309D")] = "Network", [new Guid("59031A47-3F72-44A7-89C5-5595FE6B30EE")] = "User folder",
        [new Guid("F02C1A0D-BE21-4350-88B0-7367FC96EF3C")] = "Network", [new Guid("21EC2020-3AEA-1069-A2DD-08002B30309D")] = "Control Panel",
        [new Guid("26EE0668-A00A-44D7-9371-BEB064C98683")] = "Control Panel", [new Guid("645FF040-5081-101B-9F08-00AA002F954E")] = "Recycle Bin",
    };

    /// <summary>The path the ID list's shell items spell: root folder, drive, then each file entry by its long name.</summary>
    private string? IdList(ReadOnlySpan<byte> list)
    {
        var parts = new List<string>();
        int pos = 0;
        while (pos + 2 <= list.Length)
        {
            int size = BinaryPrimitives.ReadUInt16LittleEndian(list[pos..]);
            if (size == 0) break;
            if (size < 3 || pos + size > list.Length) { Notes.Add("an ID list item runs past the list"); break; }
            var item = list.Slice(pos, size);
            pos += size;
            byte type = item[2];
            if (type == 0x1F && item.Length >= 20)
                parts.Add(RootFolders.GetValueOrDefault(new Guid(item.Slice(4, 16)), "{" + new Guid(item.Slice(4, 16)) + "}"));
            else if ((type & 0x70) == 0x20 && item.Length > 3)
            {
                var drive = Encoding.Latin1.GetString(item[3..]).Split('\0')[0];
                parts.Add(drive.TrimEnd('\\'));
            }
            else if ((type & 0x70) == 0x30 && item.Length > 14)
            {
                var shortName = Encoding.Latin1.GetString(item[14..]).Split('\0')[0];
                parts.Add(LongName(item) ?? shortName);
            }
            else if ((type & 0x70) == 0x40 && item.Length > 5)
                parts.Add(Encoding.Latin1.GetString(item[5..]).Split('\0')[0]);
            else if (type == 0x61 && item.Length > 6)
            {
                // a URI item: the address is the string in it with a scheme
                var text = (item[3] & 0x80) != 0 ? Encoding.Unicode.GetString(item[6..][..((item.Length - 6) & ~1)]) : Encoding.Latin1.GetString(item[6..]);
                var uri = System.Text.RegularExpressions.Regex.Match(text, @"[A-Za-z][A-Za-z0-9+.\-]*://[^\0\s]+", System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromSeconds(1));
                if (uri.Success) return uri.Value;
                parts.Add("<URI item>");
            }
            else parts.Add($"<item 0x{type:X2}>");
        }
        if (parts.Count == 0) return null;
        var start = parts.FindIndex(p => p.Length == 2 && p[1] == ':' || p.StartsWith(@"\\", StringComparison.Ordinal));
        return start >= 0 ? string.Join(@"\", parts.Skip(start)) : string.Join(@"\", parts);
    }

    /// <summary>The long name of a file entry item, from its 0xBEEF0004 extension block.</summary>
    private static string? LongName(ReadOnlySpan<byte> item)
    {
        for (int i = 14; i + 8 <= item.Length; i++)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(item[(i + 4)..]) != 0xBEEF0004) continue;
            int version = BinaryPrimitives.ReadUInt16LittleEndian(item[(i + 2)..]);
            int at = i + (version >= 9 ? 46 : version >= 7 ? 42 : version >= 3 ? 26 : 22);
            if (at >= item.Length) return null;
            var rest = item[at..];
            int end = 0;
            while (end + 1 < rest.Length && (rest[end] != 0 || rest[end + 1] != 0)) end += 2;
            return end > 0 ? Encoding.Unicode.GetString(rest[..end]) : null;
        }
        return null;
    }

    private void LinkInfo(ReadOnlySpan<byte> li)
    {
        if (li.Length < 28) return;
        int headerSize = (int)BinaryPrimitives.ReadUInt32LittleEndian(li[4..]);
        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(li[8..]);
        int volumeAt = (int)BinaryPrimitives.ReadUInt32LittleEndian(li[12..]);
        int localAt = (int)BinaryPrimitives.ReadUInt32LittleEndian(li[16..]);
        int networkAt = (int)BinaryPrimitives.ReadUInt32LittleEndian(li[20..]);
        int suffixAt = (int)BinaryPrimitives.ReadUInt32LittleEndian(li[24..]);
        int localUnicodeAt = headerSize >= 0x24 && li.Length >= 32 ? (int)BinaryPrimitives.ReadUInt32LittleEndian(li[28..]) : 0;
        int suffixUnicodeAt = headerSize >= 0x24 && li.Length >= 36 ? (int)BinaryPrimitives.ReadUInt32LittleEndian(li[32..]) : 0;
        string suffix = suffixUnicodeAt > 0 ? Wide(li, suffixUnicodeAt) : Ansi(li, suffixAt);
        if ((flags & 1) != 0)
        {
            LocalPath = (localUnicodeAt > 0 ? Wide(li, localUnicodeAt) : Ansi(li, localAt)) + suffix;
            if (volumeAt > 0 && volumeAt + 16 <= li.Length)
            {
                var v = li[volumeAt..];
                DriveType = BinaryPrimitives.ReadUInt32LittleEndian(v[4..]) switch { 2 => "removable", 3 => "fixed", 4 => "network", 5 => "CD-ROM", 6 => "RAM disk", 1 => "no root", _ => "unknown" };
                VolumeSerial = BinaryPrimitives.ReadUInt32LittleEndian(v[8..]).ToString("X8", System.Globalization.CultureInfo.InvariantCulture);
                int labelAt = (int)BinaryPrimitives.ReadUInt32LittleEndian(v[12..]);
                VolumeLabel = labelAt == 0x14 && v.Length >= 20 ? Wide(v, (int)BinaryPrimitives.ReadUInt32LittleEndian(v[16..])) : Ansi(v, labelAt);
                if (VolumeLabel.Length == 0) VolumeLabel = null;
            }
        }
        if ((flags & 2) != 0 && networkAt > 0 && networkAt + 20 <= li.Length)
        {
            var n = li[networkAt..];
            int netNameAt = (int)BinaryPrimitives.ReadUInt32LittleEndian(n[8..]);
            int netUnicodeAt = netNameAt > 0x14 && n.Length >= 24 ? (int)BinaryPrimitives.ReadUInt32LittleEndian(n[20..]) : 0;
            var share = netUnicodeAt > 0 ? Wide(n, netUnicodeAt) : Ansi(n, netNameAt);
            NetworkPath = share + (suffix.Length > 0 ? @"\" + suffix : "");
        }
    }

    private static string Ansi(ReadOnlySpan<byte> b, int at)
    {
        if (at <= 0 || at >= b.Length) return "";
        int end = b[at..].IndexOf((byte)0);
        return Encoding.Latin1.GetString(end < 0 ? b[at..] : b.Slice(at, end));
    }

    private static string Wide(ReadOnlySpan<byte> b, int at)
    {
        if (at <= 0 || at >= b.Length) return "";
        int end = at;
        while (end + 1 < b.Length && (b[end] != 0 || b[end + 1] != 0)) end += 2;
        return Encoding.Unicode.GetString(b[at..end]);
    }

    private void Extra(uint signature, ReadOnlySpan<byte> body)
    {
        switch (signature)
        {
            case 0xA0000001:
                ExtraBlocks.Add("EnvironmentVariables");
                EnvironmentTarget = body.Length >= 260 + 520 ? Wide(body, 260) is { Length: > 0 } w ? w : Ansi(body, 0) : Ansi(body, 0);
                if (EnvironmentTarget.Length == 0 && body.Length > 0 && body[0] != 0) EnvironmentTarget = Encoding.Latin1.GetString(body[..body.IndexOf((byte)0)]);
                break;
            case 0xA0000002: ExtraBlocks.Add("ConsoleData"); break;
            case 0xA0000003 when body.Length >= 88:
                ExtraBlocks.Add("Tracker");
                MachineId = Encoding.Latin1.GetString(body.Slice(8, 16)).TrimEnd('\0');
                var droidFile = new Guid(body.Slice(40, 16));
                Droid = $"{new Guid(body.Slice(24, 16))} {droidFile}";
                // a version 1 GUID ends with the MAC address of the machine that made it
                if ((droidFile.ToByteArray()[7] >> 4) == 1) MacAddress = string.Join(":", droidFile.ToByteArray()[10..].Select(x => x.ToString("x2", System.Globalization.CultureInfo.InvariantCulture)));
                break;
            case 0xA0000004: ExtraBlocks.Add("ConsoleFE"); break;
            case 0xA0000005 when body.Length >= 4:
                ExtraBlocks.Add("SpecialFolder");
                SpecialFolder = (int)BinaryPrimitives.ReadUInt32LittleEndian(body);
                break;
            case 0xA0000006:
                ExtraBlocks.Add("Darwin");
                InstallerDescriptor = body.Length >= 780 ? Wide(body, 260) : Ansi(body, 0);
                break;
            case 0xA0000007:
                ExtraBlocks.Add("IconEnvironment");
                IconEnvironment = body.Length >= 780 ? Wide(body, 260) : Ansi(body, 0);
                break;
            case 0xA0000008:
                ExtraBlocks.Add("Shim");
                ShimLayer = Encoding.Unicode.GetString(body).TrimEnd('\0');
                break;
            case 0xA0000009: ExtraBlocks.Add("PropertyStore"); break;
            case 0xA000000B when body.Length >= 16:
                ExtraBlocks.Add("KnownFolder");
                KnownFolder = new Guid(body[..16]).ToString();
                break;
            case 0xA000000C: ExtraBlocks.Add("VistaAndAboveIDList"); break;
            default: ExtraBlocks.Add($"0x{signature:X8}"); break;
        }
    }
}
