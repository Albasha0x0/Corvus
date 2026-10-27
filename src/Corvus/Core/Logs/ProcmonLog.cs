using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Text;

namespace Corvus.Core.Logs;

/// <summary>A Process Monitor log (.pml format 9, or CSV export); <see cref="Read"/> throws <see cref="InvalidDataException"/> on neither.</summary>
public sealed class ProcmonLog
{
    private const int HeaderSize = 0x3A8, MaxNotes = 200;

    /// <summary>The backing file header: format version, pointer size, computer, system root, event count, Windows version, processors and memory.</summary>
    public sealed record FileHeader(int Version, bool Is64Bit, string Computer, string SystemRoot, long Events, string Windows, int Processors, ulong Memory);

    /// <summary>One process of the backing file's process table; a null time is one the capture did not see.</summary>
    public sealed record Process(int Pid, int ParentPid, int Session, DateTime? Started, DateTime? Ended, bool Is64Bit, string Integrity, string User,
        string Name, string ImagePath, string CommandLine, string Company, string Version, string Description, int Modules);

    /// <summary>One event, numbered from 0; Time is UTC from a .pml, TimeText from CSV; null fields are columns the input lacks.</summary>
    public sealed record Event(long Number, DateTime? Time, string? TimeText, string ProcessName, int? Pid, int? ThreadId, string? Class, string Operation,
        string Path, string Result, TimeSpan? Duration, string? Detail);

    public string Format { get; private set; } = "";
    public FileHeader? Header { get; private set; }
    public IReadOnlyList<Process> Processes { get; private set; } = [];
    public long Events { get; private set; }
    public List<string> Notes { get; } = [];

    /// <summary>True when the bytes start a backing file (PML_) or a CSV export whose header names Process Monitor's columns.</summary>
    public static bool Looks(ReadOnlySpan<byte> head) => head.StartsWith("PML_"u8) || CsvHeader(head) != null;

    /// <summary>Reads <paramref name="stream"/> (seekable for a backing file) and passes each event to <paramref name="sink"/> in file order.</summary>
    public static ProcmonLog Read(Stream stream, Action<Event> sink, CancellationToken ct)
    {
        var head = new byte[Math.Min(4096, stream.Length)];
        stream.Position = 0;
        stream.ReadExactly(head);
        stream.Position = 0;
        var log = new ProcmonLog();
        if (head.AsSpan().StartsWith("PML_"u8)) new PmlReader(log, stream, sink, ct).Run();
        else if (CsvHeader(head) != null) log.ReadCsv(stream, sink, ct);
        else throw new InvalidDataException("not a Process Monitor log (no PML_ signature or CSV header)");
        return log;
    }

    private void Note(string note)
    {
        if (Notes.Count < MaxNotes) Notes.Add(note);
        else if (Notes.Count == MaxNotes) Notes.Add("further notes not kept");
    }

    private sealed class PmlReader(ProcmonLog log, Stream stream, Action<Event> sink, CancellationToken ct)
    {
        private readonly Window _events = new(stream), _tables = new(stream);
        private string[] _strings = [];
        private readonly Dictionary<int, Process> _processes = [];
        private readonly Dictionary<string, string> _hosts = new(StringComparer.Ordinal);
        private readonly Dictionary<(int Port, bool Tcp), string> _ports = [];
        private int _pointer;

        public void Run()
        {
            var h = _tables.At(0, HeaderSize).ToArray();
            int version = BinaryPrimitives.ReadInt32LittleEndian(h.AsSpan(4));
            if (version != 9) throw new InvalidDataException($"backing file format {version}; format 9 is read");
            bool is64 = BinaryPrimitives.ReadInt32LittleEndian(h.AsSpan(8)) != 0;
            _pointer = is64 ? 8 : 4;
            long count = BinaryPrimitives.ReadUInt32LittleEndian(h.AsSpan(0x234));
            long offsets = (long)BinaryPrimitives.ReadUInt64LittleEndian(h.AsSpan(0x248));
            long processes = (long)BinaryPrimitives.ReadUInt64LittleEndian(h.AsSpan(0x250));
            long strings = (long)BinaryPrimitives.ReadUInt64LittleEndian(h.AsSpan(0x258));
            long hosts = (long)BinaryPrimitives.ReadUInt64LittleEndian(h.AsSpan(0x3A0));
            log.Format = "Process Monitor backing file (PML 9)";
            log.Header = new FileHeader(version, is64, Utf16(h.AsSpan(0xC, 0x20)), Utf16(h.AsSpan(0x2C, 0x208)), count,
                string.Join('.', BinaryPrimitives.ReadUInt32LittleEndian(h.AsSpan(0x274)), BinaryPrimitives.ReadUInt32LittleEndian(h.AsSpan(0x278)),
                    BinaryPrimitives.ReadUInt32LittleEndian(h.AsSpan(0x27C))),
                BinaryPrimitives.ReadInt32LittleEndian(h.AsSpan(0x38C)), BinaryPrimitives.ReadUInt64LittleEndian(h.AsSpan(0x390)));
            // A capture that was not closed cleanly has no tables.
            if (offsets == 0 || processes == 0 || strings == 0 || hosts == 0)
                throw new InvalidDataException("the capture was not closed: the backing file has no event, process or string tables");
            Strings(strings);
            Processes(processes);
            HostsAndPorts(hosts);
            log.Processes = [.. _processes.OrderBy(p => p.Key).Select(p => p.Value)];
            for (long i = 0; i < count; i++)
            {
                if ((i & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
                long at = BinaryPrimitives.ReadUInt32LittleEndian(_tables.At(offsets + i * 5, 4));
                try
                {
                    sink(EventAt(i, at));
                    log.Events++;
                }
                catch (Exception ex) when (ex is InvalidDataException or ArgumentOutOfRangeException or EndOfStreamException)
                {
                    log.Note($"event {i} at 0x{at:x}: not read ({ex.Message})");
                }
            }
        }

        private void Strings(long at)
        {
            int count = BinaryPrimitives.ReadInt32LittleEndian(_tables.At(at, 4));
            if (count < 0 || count > 50_000_000) throw new InvalidDataException($"string table: {count} strings");
            _strings = new string[count];
            for (int i = 0; i < count; i++)
            {
                long entry = at + BinaryPrimitives.ReadUInt32LittleEndian(_tables.At(at + 4 + i * 4L, 4));
                int size = BinaryPrimitives.ReadInt32LittleEndian(_tables.At(entry, 4));
                _strings[i] = size is > 0 and < 1 << 20 ? Utf16(_tables.At(entry + 4, size)) : "";
            }
        }

        private string Str(ReadOnlySpan<byte> b, int at)
        {
            uint i = BinaryPrimitives.ReadUInt32LittleEndian(b[at..]);
            return i < _strings.Length ? _strings[i] : "";
        }

        private void Processes(long at)
        {
            int count = BinaryPrimitives.ReadInt32LittleEndian(_tables.At(at, 4));
            if (count < 0 || count > 10_000_000) throw new InvalidDataException($"process table: {count} processes");
            for (int i = 0; i < count; i++)
            {
                long entry = at + BinaryPrimitives.ReadUInt32LittleEndian(_tables.At(at + 4 + count * 4L + i * 4L, 4));
                int fixedSize = 0x60 + _pointer + 4;
                var p = _tables.At(entry, fixedSize).ToArray();
                int index = BinaryPrimitives.ReadInt32LittleEndian(p);
                _processes[index] = new Process(BinaryPrimitives.ReadInt32LittleEndian(p.AsSpan(4)), BinaryPrimitives.ReadInt32LittleEndian(p.AsSpan(8)),
                    BinaryPrimitives.ReadInt32LittleEndian(p.AsSpan(0x18)), Time(BinaryPrimitives.ReadInt64LittleEndian(p.AsSpan(0x20))),
                    Time(BinaryPrimitives.ReadInt64LittleEndian(p.AsSpan(0x28))), BinaryPrimitives.ReadInt32LittleEndian(p.AsSpan(0x34)) != 0,
                    Str(p, 0x38), Str(p, 0x3C), Str(p, 0x40), Str(p, 0x44), Str(p, 0x48), Str(p, 0x4C), Str(p, 0x50), Str(p, 0x54),
                    BinaryPrimitives.ReadInt32LittleEndian(p.AsSpan(0x60 + _pointer)));
            }
        }

        private void HostsAndPorts(long at)
        {
            int hosts = BinaryPrimitives.ReadInt32LittleEndian(_tables.At(at, 4));
            at += 4;
            for (int i = 0; i < hosts && i < 1_000_000; i++)
            {
                string ip = Convert.ToHexString(_tables.At(at, 16));
                int size = BinaryPrimitives.ReadInt32LittleEndian(_tables.At(at + 16, 4));
                _hosts[ip] = Utf16(_tables.At(at + 20, size));
                at += 20 + size;
            }
            int ports = BinaryPrimitives.ReadInt32LittleEndian(_tables.At(at, 4));
            at += 4;
            for (int i = 0; i < ports && i < 1_000_000; i++)
            {
                var b = _tables.At(at, 8);
                int number = BinaryPrimitives.ReadUInt16LittleEndian(b), size = BinaryPrimitives.ReadInt32LittleEndian(b[4..]);
                bool tcp = BinaryPrimitives.ReadUInt16LittleEndian(b[2..]) != 0;
                _ports[(number, tcp)] = Utf16(_tables.At(at + 8, size));
                at += 8 + size;
            }
        }

        private Event EventAt(long number, long at)
        {
            var common = _events.At(at, 0x34);
            int processIndex = BinaryPrimitives.ReadInt32LittleEndian(common);
            int tid = BinaryPrimitives.ReadInt32LittleEndian(common[4..]);
            int cls = BinaryPrimitives.ReadInt32LittleEndian(common[8..]);
            int op = BinaryPrimitives.ReadUInt16LittleEndian(common[0xC..]);
            long duration = BinaryPrimitives.ReadInt64LittleEndian(common[0x14..]);
            long time = BinaryPrimitives.ReadInt64LittleEndian(common[0x1C..]);
            uint result = BinaryPrimitives.ReadUInt32LittleEndian(common[0x24..]);
            int depth = BinaryPrimitives.ReadUInt16LittleEndian(common[0x28..]);
            int detailSize = BinaryPrimitives.ReadInt32LittleEndian(common[0x2C..]);
            if (detailSize < 0 || detailSize > 1 << 20) throw new InvalidDataException($"detail size {detailSize}");
            var detail = _events.At(at + 0x34 + depth * _pointer, detailSize).ToArray();
            _processes.TryGetValue(processIndex, out var process);
            var (operation, path, text) = Details(cls, op, tid, detail);
            return new Event(number, Time(time), null, process?.Name ?? "", process?.Pid, tid, ClassName(cls), operation, path, ResultName(result),
                TimeSpan.FromTicks(duration), text);
        }

        /// <summary>The operation as Process Monitor names it, the path column and the detail read for this class; the path is empty where the event has none.</summary>
        private (string Operation, string Path, string? Detail) Details(int cls, int op, int tid, byte[] d)
        {
            var r = new DetailReader(d);
            switch (cls)
            {
                case 1:
                {
                    string name = Pick(ProcessOperations, op);
                    if (op is 0 or 1)
                    {
                        r.Skip(4);
                        uint pid = r.U32();
                        r.Skip(0x24);
                        int extra = r.U8() + r.U8();
                        var pathInfo = r.U16();
                        var commandInfo = r.U16();
                        r.Skip(2 + extra);
                        var path = r.Text(pathInfo);
                        return (name, path, $"PID: {pid}, Command line: {r.Text(commandInfo)}");
                    }
                    if (op == 5)
                    {
                        ulong imageBase = _pointer == 8 ? r.U64() : r.U32();
                        uint size = r.U32();
                        var info = r.U16();
                        r.Skip(2);
                        return (name, r.Text(info), $"Image Base: 0x{imageBase:x}, Image Size: 0x{size:x}");
                    }
                    if (op == 3) return (name, "", $"Thread ID: {r.U32()}");
                    return (name, "", null);
                }
                case 2:
                {
                    var info = r.U16();
                    r.Skip(op switch { 12 or 14 => 2, 0 or 1 => 6, 3 or 5 => 10, 4 or 6 or 7 or 8 => 14, _ => 0 });
                    return (Pick(RegistryOperations, op), r.Text(info), null);
                }
                case 3 or 6:
                {
                    int sub = r.U8();
                    r.Skip(3 + _pointer * 5 + 0x14);
                    var info = r.U16();
                    r.Skip(2);
                    var path = r.Text(info);
                    string name = Pick(FileSystemOperations, op);
                    if (sub != 0 && SubOperations.TryGetValue(op, out var subs))
                        name = subs.TryGetValue(sub, out var subName) ? subName : Unknown;
                    // QueryDirectory names its filter after the path, and the path column joins them.
                    if (op == 32 && sub == 1 && r.Left >= 2 && r.Text(r.U16()) is { Length: > 0 } filter)
                        path = path.EndsWith('\\') ? path + filter : path + "\\" + filter;
                    return (name, path, null);
                }
                case 4:
                    return (Pick(ProfilingOperations, op), op == 0 ? $"Thread {tid}" : "", null);
                case 5:
                {
                    int flags = r.U16();
                    r.Skip(2);
                    uint length = r.U32();
                    var source = r.Bytes(16);
                    var target = r.Bytes(16);
                    int sourcePort = r.U16(), targetPort = r.U16();
                    bool tcp = (flags & 4) != 0;
                    string path = $"{Host(source, (flags & 1) != 0)}:{Port(sourcePort, tcp)} -> {Host(target, (flags & 2) != 0)}:{Port(targetPort, tcp)}";
                    var detail = new StringBuilder($"Length: {length}");
                    var pairs = r.MultiString();
                    for (int i = 0; i + 1 < pairs.Count; i += 2) detail.Append(", ").Append(pairs[i]).Append(": ").Append(pairs[i + 1]);
                    return ((tcp ? "TCP " : "UDP ") + Pick(NetworkOperations, op), path, detail.ToString());
                }
                default:
                    return (Unknown, "", null);
            }
        }

        private string Host(byte[] ip, bool v4)
        {
            if (_hosts.TryGetValue(Convert.ToHexString(ip), out var name) && name.Length > 0) return name;
            if (v4) return new IPAddress(ip.AsSpan(0, 4)).ToString();
            // Process Monitor writes all eight groups without zero compression.
            var groups = new string[8];
            for (int i = 0; i < 8; i++) groups[i] = BinaryPrimitives.ReadUInt16BigEndian(ip.AsSpan(i * 2)).ToString("x", CultureInfo.InvariantCulture);
            return string.Join(':', groups);
        }

        private string Port(int port, bool tcp) => _ports.TryGetValue((port, tcp), out var name) ? name : port.ToString(CultureInfo.InvariantCulture);
    }

    /// <summary>Reads a detail structure; a read past its end throws <see cref="InvalidDataException"/>.</summary>
    private ref struct DetailReader(byte[] d)
    {
        private int _at;
        public readonly int Left => d.Length - _at;

        private ReadOnlySpan<byte> Take(int n)
        {
            if (n < 0 || _at + n > d.Length) throw new InvalidDataException($"detail ends at {d.Length} bytes; {n} more needed at {_at}");
            var s = d.AsSpan(_at, n);
            _at += n;
            return s;
        }

        public void Skip(int n) => Take(n);
        public int U8() => Take(1)[0];
        public int U16() => BinaryPrimitives.ReadUInt16LittleEndian(Take(2));
        public uint U32() => BinaryPrimitives.ReadUInt32LittleEndian(Take(4));
        public ulong U64() => BinaryPrimitives.ReadUInt64LittleEndian(Take(8));
        public byte[] Bytes(int n) => Take(n).ToArray();

        /// <summary>A string whose info word (bit 15: ASCII; bits 0 to 14: characters) came earlier; it ends at its first null.</summary>
        public string Text(int info)
        {
            bool ascii = (info & 0x8000) != 0;
            int chars = info & 0x7FFF;
            return ascii ? Cut(Encoding.ASCII.GetString(Take(chars))) : Utf16(Take(chars * 2));
        }

        /// <summary>The null-separated strings up to a double null or the end of the detail.</summary>
        public List<string> MultiString()
        {
            var list = new List<string>();
            var sb = new StringBuilder();
            while (Left >= 2)
            {
                char c = (char)U16();
                if (c != '\0') { sb.Append(c); continue; }
                if (sb.Length == 0) break;
                list.Add(sb.ToString());
                sb.Clear();
            }
            if (sb.Length > 0) list.Add(sb.ToString());
            return list;
        }
    }

    /// <summary>A buffered window over a seekable stream, refilled at the requested offset when a read falls outside it.</summary>
    private sealed class Window(Stream stream)
    {
        private byte[] _buffer = new byte[1 << 20];
        private long _start = -1;
        private int _length;

        public ReadOnlySpan<byte> At(long offset, int count)
        {
            if (offset < 0 || count < 0) throw new InvalidDataException($"read of {count} bytes at {offset}");
            if (offset < _start || offset + count > _start + _length)
            {
                if (count > _buffer.Length) _buffer = new byte[Math.Max(count, _buffer.Length * 2)];
                stream.Position = offset;
                _start = offset;
                _length = stream.ReadAtLeast(_buffer, Math.Min(count, _buffer.Length), throwOnEndOfStream: false);
                if (count > _length) throw new EndOfStreamException($"{count} bytes at 0x{offset:x} run past the end of the file");
            }
            return _buffer.AsSpan((int)(offset - _start), count);
        }
    }

    private static string Utf16(ReadOnlySpan<byte> b) => Cut(Encoding.Unicode.GetString(b[..(b.Length & ~1)]));

    private static string Cut(string s) => s.IndexOf('\0') is var i and >= 0 ? s[..i] : s;

    private static DateTime? Time(long filetime) =>
        filetime > 0 && filetime <= DateTime.MaxValue.ToFileTimeUtc() ? DateTime.FromFileTimeUtc(filetime) : null;

    private const string Unknown = "<Unknown>";

    private static string Pick(string[] names, int i) => i >= 0 && i < names.Length ? names[i] : Unknown;

    private static string ClassName(int cls) => cls switch
    {
        1 => "Process", 2 => "Registry", 3 => "File System", 4 => "Profiling", 5 => "Network", 6 => "IPC", _ => Unknown,
    };

    // Operation names as Process Monitor shows them, by the operation number each class records.
    private static readonly string[] ProcessOperations =
        ["Process Defined", "Process Create", "Process Exit", "Thread Create", "Thread Exit", "Load Image", "Thread Profile", "Process Start",
         "Process Statistics", "System Statistics"];

    private static readonly string[] RegistryOperations =
        ["RegOpenKey", "RegCreateKey", "RegCloseKey", "RegQueryKey", "RegSetValue", "RegQueryValue", "RegEnumValue", "RegEnumKey", "RegSetInfoKey",
         "RegDeleteKey", "RegDeleteValue", "RegFlushKey", "RegLoadKey", "RegUnloadKey", "RegRenameKey", "RegQueryMultipleValueKey", "RegSetKeySecurity",
         "RegQueryKeySecurity"];

    private static readonly string[] NetworkOperations =
        ["Unknown", "Other", "Send", "Receive", "Accept", "Connect", "Disconnect", "Reconnect", "Retransmit", "TCPCopy"];

    private static readonly string[] ProfilingOperations = ["Thread Profiling", "Process Profiling", "Debug Output Profiling"];

    private static readonly string[] FileSystemOperations =
        ["VolumeDismount", "VolumeMount", "FASTIO_MDL_WRITE_COMPLETE", "WriteFile2", "FASTIO_MDL_READ_COMPLETE", "ReadFile2", "QueryOpen",
         "FASTIO_CHECK_IF_POSSIBLE", "IRP_MJ_12", "IRP_MJ_11", "IRP_MJ_10", "IRP_MJ_9", "IRP_MJ_8", "FASTIO_NOTIFY_STREAM_FO_CREATION",
         "FASTIO_RELEASE_FOR_CC_FLUSH", "FASTIO_ACQUIRE_FOR_CC_FLUSH", "FASTIO_RELEASE_FOR_MOD_WRITE", "FASTIO_ACQUIRE_FOR_MOD_WRITE",
         "FASTIO_RELEASE_FOR_SECTION_SYNCHRONIZATION", "CreateFileMapping", "CreateFile", "CreatePipe", "IRP_MJ_CLOSE", "ReadFile", "WriteFile",
         "QueryInformationFile", "SetInformationFile", "QueryEAFile", "SetEAFile", "FlushBuffersFile", "QueryVolumeInformation",
         "SetVolumeInformation", "DirectoryControl", "FileSystemControl", "DeviceIoControl", "InternalDeviceIoControl", "Shutdown", "LockUnlockFile",
         "CloseFile", "CreateMailSlot", "QuerySecurityFile", "SetSecurityFile", "Power", "SystemControl", "DeviceChange", "QueryFileQuota",
         "SetFileQuota", "PlugAndPlay"];

    // Sub-operations by file system operation number.
    private static readonly Dictionary<int, Dictionary<int, string>> SubOperations = new()
    {
        [30] = new()
        {
            [1] = "QueryInformationVolume", [2] = "QueryLabelInformationVolume", [3] = "QuerySizeInformationVolume", [4] = "QueryDeviceInformationVolume",
            [5] = "QueryAttributeInformationVolume", [6] = "QueryControlInformationVolume", [7] = "QueryFullSizeInformationVolume",
            [8] = "QueryObjectIdInformationVolume",
        },
        [31] = new() { [1] = "SetControlInformationVolume", [2] = "SetLabelInformationVolume", [8] = "SetObjectIdInformationVolume" },
        [25] = new()
        {
            [0x04] = "QueryBasicInformationFile", [0x05] = "QueryStandardInformationFile", [0x06] = "QueryFileInternalInformationFile",
            [0x07] = "QueryEaInformationFile", [0x09] = "QueryNameInformationFile", [0x0E] = "QueryPositionInformationFile",
            [0x12] = "QueryAllInformationFile", [0x14] = "QueryEndOfFile", [0x16] = "QueryStreamInformationFile",
            [0x1C] = "QueryCompressionInformationFile", [0x1D] = "QueryId", [0x1F] = "QueryMoveClusterInformationFile",
            [0x22] = "QueryNetworkOpenInformationFile", [0x23] = "QueryAttributeTagFile", [0x25] = "QueryIdBothDirectory",
            [0x27] = "QueryValidDataLength", [0x28] = "QueryShortNameInformationFile", [0x2B] = "QueryIoPiorityHint", [0x2E] = "QueryLinks",
            [0x30] = "QueryNormalizedNameInformationFile", [0x31] = "QueryNetworkPhysicalNameInformationFile",
            [0x32] = "QueryIdGlobalTxDirectoryInformation", [0x33] = "QueryIsRemoteDeviceInformation", [0x34] = "QueryAttributeCacheInformation",
            [0x35] = "QueryNumaNodeInformation", [0x36] = "QueryStandardLinkInformation", [0x37] = "QueryRemoteProtocolInformation",
            [0x38] = "QueryRenameInformationBypassAccessCheck", [0x39] = "QueryLinkInformationBypassAccessCheck",
            [0x3A] = "QueryVolumeNameInformation", [0x3B] = "QueryIdInformation", [0x3C] = "QueryIdExtdDirectoryInformation",
            [0x3E] = "QueryHardLinkFullIdInformation", [0x3F] = "QueryIdExtdBothDirectoryInformation",
            [0x43] = "QueryDesiredStorageClassInformation", [0x44] = "QueryStatInformation", [0x45] = "QueryMemoryPartitionInformation",
            [0x46] = "QuerySatLxInformation", [0x47] = "QueryCaseSensitiveInformation", [0x48] = "QueryLinkInformationEx",
            [0x49] = "QueryLinkInfomraitonBypassAccessCheck", [0x4A] = "QueryStorageReservedIdInformation",
            [0x4B] = "QueryCaseSensitiveInformationForceAccessCheck",
        },
        [26] = new()
        {
            [0x04] = "SetBasicInformationFile", [0x0A] = "SetRenameInformationFile", [0x0B] = "SetLinkInformationFile",
            [0x0D] = "SetDispositionInformationFile", [0x0E] = "SetPositionInformationFile", [0x13] = "SetAllocationInformationFile",
            [0x14] = "SetEndOfFileInformationFile", [0x16] = "SetFileStreamInformation", [0x17] = "SetPipeInformation",
            [0x27] = "SetValidDataLengthInformationFile", [0x28] = "SetShortNameInformation", [0x3D] = "SetReplaceCompletionInformation",
            [0x40] = "SetDispositionInformationEx", [0x41] = "SetRenameInformationEx", [0x42] = "SetRenameInformationExBypassAccessCheck",
            [0x4A] = "SetStorageReservedIdInformation",
        },
        [32] = new() { [1] = "QueryDirectory", [2] = "NotifyChangeDirectory" },
        [47] = new()
        {
            [0x00] = "StartDevice", [0x01] = "QueryRemoveDevice", [0x02] = "RemoveDevice", [0x03] = "CancelRemoveDevice", [0x04] = "StopDevice",
            [0x05] = "QueryStopDevice", [0x06] = "CancelStopDevice", [0x07] = "QueryDeviceRelations", [0x08] = "QueryInterface",
            [0x09] = "QueryCapabilities", [0x0A] = "QueryResources", [0x0B] = "QueryResourceRequirements", [0x0C] = "QueryDeviceText",
            [0x0D] = "FilterResourceRequirements", [0x0F] = "ReadConfig", [0x10] = "WriteConfig", [0x11] = "Eject", [0x12] = "SetLock",
            [0x13] = "QueryId2", [0x14] = "QueryPnpDeviceState", [0x15] = "QueryBusInformation", [0x16] = "DeviceUsageNotification",
            [0x17] = "SurpriseRemoval", [0x18] = "QueryLegacyBusInformation",
        },
        [37] = new() { [1] = "LockFile", [2] = "UnlockFileSingle", [3] = "UnlockFileAll", [4] = "UnlockFileByKey" },
    };

    /// <summary>The result as Process Monitor shows it: a status name, empty for a pending status, else the status in hex.</summary>
    public static string ResultName(uint status) => Results.TryGetValue(status, out var name) ? name : $"0x{status:X}";

    private static readonly Dictionary<uint, string> Results = new()
    {
        [0x0] = "SUCCESS", [0x103] = "", [0x104] = "REPARSE", [0x105] = "MORE ENTRIES",
        [0x108] = "OPLOCK BREAK IN PROGRESS", [0x10B] = "NOTIFY CLEANUP", [0x10C] = "NOTIFY ENUM DIR",
        [0x12A] = "FILE LOCKED WITH ONLY READERS", [0x12B] = "FILE LOCKED WITH WRITERS",
        [0x215] = "OPLOCK SWITCHED TO NEW HANDLE", [0x216] = "OPLOCK HANDLE CLOSED", [0x367] = "WAIT FOR OPLOCK",
        [0x368] = "REPARSE GLOBAL", [0x40000016] = "PREDEFINED HANDLE", [0xC0000001] = "UNSUCCESSFUL",
        [0x80000015] = "INVALID EA FLAG", [0x80000002] = "DATATYPE MISALIGNMENT", [0x80000005] = "BUFFER OVERFLOW",
        [0x80000006] = "NO MORE FILES", [0x8000001A] = "NO MORE ENTRIES", [0x80090322] = "E_WRONG_PRINCIPAL",
        [0xC0000101] = "NOT EMPTY", [0xC0000002] = "NOT IMPLEMENTED", [0xC0000003] = "INVALID INFO CLASS",
        [0xC0000004] = "INFO LENGTH MISMATCH", [0xC0000005] = "ACCESS VIOLATION", [0xC0000006] = "IN PAGE ERROR",
        [0xC0000008] = "INVALID HANDLE", [0xC000000D] = "INVALID PARAMETER", [0xC000000E] = "NO SUCH DEVICE",
        [0xC000000F] = "NO SUCH FILE", [0xC0000010] = "INVALID DEVICE REQUEST", [0xC0000011] = "END OF FILE",
        [0xC0000012] = "WRONG VOLUME", [0xC0000013] = "NO MEDIA", [0xC0000015] = "NONEXISTENT SECTOR",
        [0xC0000017] = "NO MEMORY", [0xC0000021] = "ALREADY COMMITTED", [0xC0000022] = "ACCESS DENIED",
        [0xC0000023] = "BUFFER TOO SMALL", [0xC0000024] = "OBJECT TYPE MISMATCH", [0xC0000032] = "DISK CORRUPT",
        [0xC0000033] = "NAME INVALID", [0xC0000034] = "NAME NOT FOUND", [0xC0000035] = "NAME COLLISION",
        [0xC0000039] = "OBJECT PATH INVALID", [0xC000003A] = "PATH NOT FOUND", [0xC000003B] = "PATH SYNTAX BAD",
        [0xC000003C] = "DATA OVERRUN", [0xC000003F] = "CRC ERROR", [0xC0000043] = "SHARING VIOLATION",
        [0xC0000044] = "QUOTA EXCEEDED", [0xC000004F] = "EAS NOT SUPPORTED", [0xC0000050] = "EA TOO LARGE",
        [0xC0000051] = "NONEXISTENT EA ENTRY", [0xC0000052] = "NO EAS ON FILE", [0xC0000053] = "EA CORRUPT ERROR",
        [0xC0000054] = "FILE LOCK CONFLICT", [0xC0000055] = "NOT GRANTED", [0xC0000056] = "DELETE PENDING",
        [0xC000005A] = "INVALID OWNER", [0xC0000061] = "PRIVILEGE NOT HELD", [0xC000006D] = "LOGON FAILURE",
        [0xC000007E] = "RANGE NOT LOCKED", [0xC000007F] = "DISK FULL", [0xC0000098] = "FILE INVALID",
        [0xC000009A] = "INSUFFICIENT RESOURCES", [0xC000009C] = "DEVICE DATA ERROR", [0xC000009D] = "DEVICE NOT CONNECTED",
        [0xC00000A2] = "MEDIA WRITE PROTECTED", [0xC00000A5] = "BAD IMPERSONATION",
        [0xC00000AB] = "INSTANCE NOT AVAILABLE", [0xC00000AC] = "PIPE NOT AVAILABLE", [0xC00000AD] = "INVALID PIPE STATE",
        [0xC00000AE] = "PIPE BUSY", [0xC00000B0] = "PIPE DISCONNECTED", [0xC00000B1] = "PIPE CLOSING",
        [0xC00000B2] = "PIPE CONNECTED", [0xC00000B3] = "PIPE LISTENING", [0xC00000B4] = "INVALID READ MODE",
        [0xC00000B5] = "IO TIMEOUT", [0xC00000BA] = "IS DIRECTORY", [0xC00000BB] = "NOT SUPPORTED",
        [0xC00000BD] = "DUPLICATE NAME", [0xC00000BE] = "BAD NETWORK PATH", [0xC00000C1] = "TOO MANY COMMANDS",
        [0xC00000C3] = "INVALID NETWORK RESPONSE", [0xC00000C4] = "NETWORK ERROR", [0xC00000CC] = "BAD NETWORK NAME",
        [0xC00000D4] = "NOT SAME DEVICE", [0xC00000D8] = "CANT WAIT", [0xC00000D9] = "PIPE EMPTY",
        [0xC00000DB] = "CSC OBJECT PATH NOT FOUND", [0xC00000E2] = "OPLOCK NOT GRANTED",
        [0xC00000EF] = "INVALID PARAMETER 1", [0xC00000F0] = "INVALID PARAMETER 2", [0xC00000F1] = "INVALID PARAMETER 3",
        [0xC00000F2] = "INVALID PARAMETER 4", [0xC00000FB] = "REDIRECTOR NOT STARTED", [0xC0000102] = "FILE CORRUPT",
        [0xC0000103] = "NOT A DIRECTORY", [0xC0000107] = "FILES OPEN", [0xC000010D] = "CANNOT IMPERSONATE",
        [0xC0000120] = "CANCELLED", [0xC0000121] = "CANNOT DELETE", [0xC0000123] = "FILE DELETED",
        [0xC0000128] = "FILE CLOSED", [0xC000012A] = "THREAD NOT IN PROCESS", [0xC0000148] = "INVALID LEVEL",
        [0xC000014B] = "PIPE BROKEN", [0xC000014C] = "REGISTRY CORRUPT", [0xC000014D] = "IO FAILED",
        [0xC000017C] = "KEY DELETED", [0xC0000181] = "CHILD MUST BE VOLATILE", [0xC0000184] = "INVALID DEVICE STATE",
        [0xC0000185] = "IO DEVICE ERROR", [0xC0000188] = "LOG FILE FULL", [0xC000019C] = "FS DRIVER REQUIRED",
        [0xC0000203] = "USER SESSION DELETED", [0xC0000205] = "INSUFFICIENT SERVER RESOURCES",
        [0xC0000207] = "INVALID ADDRESS COMPONENT", [0xC000020C] = "DISCONNECTED", [0xC0000225] = "NOT FOUND",
        [0xC0000243] = "USER MAPPED FILE", [0xC0000248] = "LOGIN WKSTA RESTRICTION", [0xC0000257] = "PATH NOT COVERED",
        [0xC000026D] = "DFS UNAVAILABLE", [0xC0000273] = "NO MORE MATCHES", [0xC0000275] = "NOT REPARSE POINT",
        [0xC00002EA] = "CANNOT MAKE", [0xC00002F0] = "OBJECTID NOT FOUND", [0xC0000388] = "DOWNGRADE DETECTED",
        [0xC0000425] = "HIVE UNLOADED", [0xC0000427] = "FILE SYSTEM LIMITATION",
        [0xC0000463] = "DEVICE FEATURE NOT SUPPORTED", [0xC000046D] = "OBJECT NOT EXTERNALLY BACKED",
        [0xC00004AD] = "STORAGE RESERVE ID INVALID", [0xC00004AE] = "STORAGE RESERVE DOES NOT EXIST",
        [0xC00004AF] = "STORAGE RESERVE ALREADY EXISTS", [0xC00004B0] = "STORAGE RESERVE NOT EMPTY",
        [0xC00004B1] = "NOT A DAX VOLUME", [0xC0000909] = "CANNOT BREAK OPLOCK",
        [0xC000A2A1] = "STATUS_OFFLOAD_READ_FLT_NOT_SUPPORTED", [0xC000A2A2] = "STATUS_OFFLOAD_WRITE_FLT_NOT_SUPPORTED",
        [0xC000A2A3] = "OFFLOAD READ FILE NOT SUPPORTED", [0xC000A2A4] = "OFFLOAD READ FILE NOT SUPPORTED",
        [0xC0190001] = "TRANSACTIONAL CONFLICT", [0xC0190002] = "INVALID TRANSACTION",
        [0xC0190003] = "TRANSACTION_NOT_ACTIVE", [0xC019003E] = "EFS NOT ALLOWED IN TRANSACTION",
        [0xC019003F] = "TRANSACTIONAL OPEN NOT ALLOWED", [0xC0190040] = "TRANSACTED MAPPING UNSUPPORTED REMOTE",
        [0xC0190044] = "CANNOT EXECUTE FILE IN TRANSACTION", [0xC0190049] = "SPARSE NOT ALLOWED IN TRANSACTION",
        [0xC01C0004] = "FAST IO DISALLOWED",
    };

    // CSV export.

    private static readonly string[] CsvColumns =
        ["Time of Day", "Date & Time", "Process Name", "PID", "TID", "Operation", "Path", "Result", "Detail", "Event Class", "Duration", "Sequence"];

    /// <summary>The header's columns when the first line is a CSV header naming Process Name and Operation among Process Monitor's columns; else null.</summary>
    private static List<string>? CsvHeader(ReadOnlySpan<byte> head)
    {
        if (head.StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF])) head = head[3..];
        int end = head.IndexOfAny((byte)'\r', (byte)'\n');
        if (end < 0 || head.IsEmpty || head[0] != (byte)'"') return null;
        var columns = CsvFields(Encoding.UTF8.GetString(head[..end]));
        return columns.Contains("Process Name") && columns.Contains("Operation") && columns.Count(CsvColumns.Contains) >= 3 ? columns : null;
    }

    private void ReadCsv(Stream stream, Action<Event> sink, CancellationToken ct)
    {
        Format = "Process Monitor CSV export";
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1 << 16, leaveOpen: true);
        var columns = CsvFields(reader.ReadLine() ?? "");
        int Col(string name) => columns.IndexOf(name);
        int time = Col("Time of Day") is var t and >= 0 ? t : Col("Date & Time"), process = Col("Process Name"), pid = Col("PID"), tid = Col("TID"),
            op = Col("Operation"), path = Col("Path"), result = Col("Result"), detail = Col("Detail"), cls = Col("Event Class"), duration = Col("Duration");
        long line = 1;
        while (reader.ReadLine() is { } text)
        {
            line++;
            if ((line & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            // A quoted field may hold line breaks.
            while (text.Count(c => c == '"') % 2 != 0 && reader.ReadLine() is { } more) text += "\n" + more;
            if (text.Length == 0) continue;
            var f = CsvFields(text);
            if (f.Count != columns.Count) { Note($"line {line}: {f.Count} fields, the header has {columns.Count}"); continue; }
            string Field(int i) => i >= 0 ? f[i] : "";
            int? Int(int i) => i >= 0 && int.TryParse(f[i], NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null;
            TimeSpan? Seconds(int i) => i >= 0 && double.TryParse(f[i], NumberStyles.Float, CultureInfo.InvariantCulture, out var s) ? TimeSpan.FromSeconds(s) : null;
            sink(new Event(Events, null, time >= 0 ? f[time] : null, Field(process), Int(pid), Int(tid), cls >= 0 ? f[cls] : null, Field(op), Field(path),
                Field(result), Seconds(duration), detail >= 0 ? f[detail] : null));
            Events++;
        }
    }

    /// <summary>The fields of one CSV record: comma-separated, a quoted field keeps commas, and a doubled quote stands for one.</summary>
    private static List<string> CsvFields(string line)
    {
        var fields = new List<string>();
        var sb = new StringBuilder();
        bool quoted = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (quoted)
            {
                if (c != '"') sb.Append(c);
                else if (i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; }
                else quoted = false;
            }
            else if (c == '"') quoted = true;
            else if (c == ',') { fields.Add(sb.ToString()); sb.Clear(); }
            else sb.Append(c);
        }
        fields.Add(sb.ToString());
        return fields;
    }
}
