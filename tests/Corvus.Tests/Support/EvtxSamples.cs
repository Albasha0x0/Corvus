using System.Buffers.Binary;
using System.IO.Hashing;
using System.Text;

namespace Corvus.Tests;

/// <summary>
/// Builds Windows event log files (format 3.2, one chunk): templated events written as the event log service writes
/// them (templates and names defined in place on first use, referenced by chunk offset after), an EventData passed as
/// a nested binary XML value, and events placed in the chunk's free space after its last record.
/// </summary>
internal static class EvtxSamples
{
    public const string Namespace = "http://schemas.microsoft.com/win/2004/08/events/event";

    /// <summary>One templated event; a null Activity or Sid leaves that optional value empty.</summary>
    public sealed record Sample(ulong RecordId, string Provider, Guid ProviderGuid, ushort EventId, byte Level, DateTime Created, int ProcessId,
        int ThreadId, string Channel, string Computer, string Path, string[] Items, Guid? Activity = null, byte[]? Sid = null);

    /// <summary>An event of a second template: the System values of Event, then an EventData holding one unnamed Data value, passed as a nested binary XML value.</summary>
    public sealed record NestedData(Sample Event, string Data);

    public static readonly byte[] LocalSystem = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];

    /// <summary>The file bytes: header, then one chunk holding <paramref name="events"/> and, past its free space offset, <paramref name="free"/>.</summary>
    public static byte[] Log(IEnumerable<object> events, IEnumerable<object>? free = null, bool dirty = false)
    {
        var chunk = new Chunk();
        ulong first = 0, last = 0;
        int lastOffset = 0x200;
        foreach (var e in events)
        {
            lastOffset = chunk.Pos;
            ulong id = chunk.Record(e);
            if (first == 0) first = id;
            last = id;
        }
        int freeOffset = chunk.Pos;
        foreach (var e in free ?? []) chunk.Record(e);
        var c = chunk.B;
        "ElfChnk\0"u8.CopyTo(c);
        BinaryPrimitives.WriteUInt64LittleEndian(c.AsSpan(8), first);
        BinaryPrimitives.WriteUInt64LittleEndian(c.AsSpan(16), last);
        BinaryPrimitives.WriteUInt64LittleEndian(c.AsSpan(24), first);
        BinaryPrimitives.WriteUInt64LittleEndian(c.AsSpan(32), last);
        BinaryPrimitives.WriteUInt32LittleEndian(c.AsSpan(40), 128);
        BinaryPrimitives.WriteUInt32LittleEndian(c.AsSpan(44), (uint)lastOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(c.AsSpan(48), (uint)freeOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(c.AsSpan(52), Crc32.HashToUInt32(c.AsSpan(0x200, freeOffset - 0x200)));
        var crc = new Crc32();
        crc.Append(c.AsSpan(0, 120));
        crc.Append(c.AsSpan(128, 384));
        BinaryPrimitives.WriteUInt32LittleEndian(c.AsSpan(124), crc.GetCurrentHashAsUInt32());

        var file = new byte[0x1000 + c.Length];
        "ElfFile\0"u8.CopyTo(file);
        BinaryPrimitives.WriteUInt64LittleEndian(file.AsSpan(24), last + 1);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(32), 128);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(36), 2);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(38), 3);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(40), 0x1000);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(42), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(120), dirty ? 1u : 0u);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(124), Crc32.HashToUInt32(file.AsSpan(0, 120)));
        c.CopyTo(file, 0x1000);
        return file;
    }

    private sealed class Chunk
    {
        public readonly byte[] B = new byte[0x10000];
        public int Pos = 0x200;
        private readonly Dictionary<string, int> _names = [];
        private readonly Dictionary<Guid, int> _templates = [];

        public ulong Record(object e)
        {
            int start = Pos;
            Bytes("**\0\0"u8);
            U32(0);
            var system = e switch { Sample s => s, NestedData n => n.Event, _ => throw new ArgumentException(e.GetType().Name) };
            ulong id = system.RecordId;
            U64(id);
            U64((ulong)system.Created.ToFileTimeUtc());
            FragmentHeader();
            if (e is Sample sample) Instance(SampleTemplate, SampleBody, SampleValues(sample));
            else Instance(NestedTemplate, NestedBody, NestedValues((NestedData)e));
            // Records are padded to 8 bytes; the padding reads as the end of the fragment.
            while ((Pos - start + 4) % 8 != 0) U8(0);
            U32((uint)(Pos - start + 4));
            BinaryPrimitives.WriteUInt32LittleEndian(B.AsSpan(start + 4), (uint)(Pos - start));
            return id;
        }

        private static readonly Guid SampleTemplate = Guid.Parse("6d1b1fa0-2bd2-4c5e-9b8e-0a3c5f4e7d21");
        private static readonly Guid NestedTemplate = Guid.Parse("3e8a5c71-94b2-4f0d-8c6e-1d7b2a9f5e30");
        private static readonly Guid DataTemplate = Guid.Parse("b47d0e29-5a63-4c18-9f2e-6a0c3d8b1f75");

        /// <summary>A template instance: the template defined in place on first use, then the values (bytes, or written in place).</summary>
        private void Instance(Guid template, Action body, List<(byte Type, byte[]? Bytes, Action? Write)> values)
        {
            // The template id is the first four bytes of the template GUID.
            var guid = template.ToByteArray();
            uint templateId = BinaryPrimitives.ReadUInt32LittleEndian(guid);
            U8(0x0C);
            U8(1);
            U32(templateId);
            if (!_templates.TryGetValue(template, out var at))
            {
                at = Pos + 4;
                _templates[template] = at;
                U32((uint)at);
                // Each of the 32 buckets chains its templates through their next-template field.
                int bucket = 384 + (int)(templateId % 32) * 4;
                U32(BinaryPrimitives.ReadUInt32LittleEndian(B.AsSpan(bucket)));
                BinaryPrimitives.WriteUInt32LittleEndian(B.AsSpan(bucket), (uint)at);
                Bytes(guid);
                int lengthAt = Pos;
                U32(0);
                body();
                BinaryPrimitives.WriteUInt32LittleEndian(B.AsSpan(lengthAt), (uint)(Pos - lengthAt - 4));
            }
            else U32((uint)at);
            U32((uint)values.Count);
            int descriptors = Pos;
            foreach (var (type, bytes, _) in values)
            {
                U16(bytes?.Length ?? 0);
                U8(type);
                U8(0);
            }
            for (int i = 0; i < values.Count; i++)
            {
                if (values[i].Bytes is { } bytes) { Bytes(bytes); continue; }
                int start = Pos;
                values[i].Write!();
                BinaryPrimitives.WriteUInt16LittleEndian(B.AsSpan(descriptors + i * 4), (ushort)(Pos - start));
            }
        }

        private static List<(byte, byte[]?, Action?)> SampleValues(Sample s) =>
        [
            .. SystemValues(s),
            (0x01, Encoding.Unicode.GetBytes(s.Path), null),
            (0x81, Encoding.Unicode.GetBytes(string.Concat(s.Items.Select(i => i + "\0"))), null),
            (0x00, [], null),
        ];

        private static List<(byte, byte[]?, Action?)> SystemValues(Sample s) =>
        [
            (0x01, Encoding.Unicode.GetBytes(s.Provider), null),
            (0x0F, s.ProviderGuid.ToByteArray(), null),
            (0x06, BitConverter.GetBytes(s.EventId), null),
            (0x04, [s.Level], null),
            (0x11, BitConverter.GetBytes(s.Created.ToFileTimeUtc()), null),
            (0x0A, BitConverter.GetBytes(s.RecordId), null),
            s.Activity is { } a ? ((byte)0x0F, a.ToByteArray(), null) : ((byte)0x00, [], null),
            (0x08, BitConverter.GetBytes((uint)s.ProcessId), null),
            (0x08, BitConverter.GetBytes((uint)s.ThreadId), null),
            (0x01, Encoding.Unicode.GetBytes(s.Channel), null),
            (0x01, Encoding.Unicode.GetBytes(s.Computer), null),
            s.Sid is { } sid ? ((byte)0x13, sid, null) : ((byte)0x00, [], null),
        ];

        // Substitutions: 0 provider, 1 provider GUID, 2 event id, 3 level, 4 time, 5 record id, 6 activity (optional),
        // 7 process, 8 thread, 9 channel, 10 computer, 11 user SID (optional), 12 path, 13 items (string array), 14 size (optional).
        private void SampleBody()
        {
            FragmentHeader();
            Open("Event", attributes: true); Attr("xmlns", more: false); Text(Namespace); Content();
            SystemBody();
            Open("EventData", false); Content();
            Open("Data", true); Attr("Name", false); Text("Path"); Content(); Sub(12, 0x01); End();
            Open("Data", true); Attr("Name", false); Text("Items"); Content(); Sub(13, 0x81); End();
            Open("Data", true); Attr("Name", false); Text("Size"); Content(); Sub(14, 0x15, optional: true); End();
            End();
            End();
            U8(0x00);
        }

        private void SystemBody()
        {
            Open("System", false); Content();
            Open("Provider", true); Attr("Name", true); Sub(0, 0x01); Attr("Guid", false); Sub(1, 0x0F); EmptyEnd();
            Open("EventID", false); Content(); Sub(2, 0x06); End();
            Open("Level", false); Content(); Sub(3, 0x04); End();
            Open("TimeCreated", true); Attr("SystemTime", false); Sub(4, 0x11); EmptyEnd();
            Open("EventRecordID", false); Content(); Sub(5, 0x0A); End();
            Open("Correlation", true); Attr("ActivityID", false); Sub(6, 0x0F, optional: true); EmptyEnd();
            Open("Execution", true); Attr("ProcessID", true); Sub(7, 0x08); Attr("ThreadID", false); Sub(8, 0x08); EmptyEnd();
            Open("Channel", false); Content(); Sub(9, 0x01); End();
            Open("Computer", false); Content(); Sub(10, 0x01); End();
            Open("Security", true); Attr("UserID", false); Sub(11, 0x13, optional: true); EmptyEnd();
            End();
        }

        private List<(byte, byte[]?, Action?)> NestedValues(NestedData n) =>
        [
            .. SystemValues(n.Event),
            // A binary XML value is itself a template instance, as every fragment the service writes.
            (0x21, null, () =>
            {
                FragmentHeader();
                Instance(DataTemplate, DataBody, [(0x01, Encoding.Unicode.GetBytes(n.Data), null)]);
            }),
        ];

        private void DataBody()
        {
            FragmentHeader();
            Open("EventData", false); Content();
            Open("Data", false); Content(); Sub(0, 0x01); End();
            End();
            U8(0x00);
        }

        // Substitutions: 0 to 11 as the sample template, 12 the EventData element as binary XML.
        private void NestedBody()
        {
            FragmentHeader();
            Open("Event", true); Attr("xmlns", false); Text(Namespace); Content();
            SystemBody();
            Sub(12, 0x21, optional: true);
            End();
            U8(0x00);
        }

        private void FragmentHeader() => Bytes([0x0F, 1, 1, 0]);

        // Open elements: where each one's data size and attribute list size go, filled when it ends.
        private readonly Stack<(int Size, int Attributes)> _open = [];

        private void Open(string name, bool attributes)
        {
            U8(attributes ? (byte)0x41 : (byte)0x01);
            U16(0xFFFF);
            int size = Pos;
            U32(0);
            Name(name);
            int attributeSize = attributes ? Pos : -1;
            if (attributes) U32(0);
            _open.Push((size, attributeSize));
        }

        private void EndAttributes()
        {
            int at = _open.Peek().Attributes;
            if (at >= 0) BinaryPrimitives.WriteUInt32LittleEndian(B.AsSpan(at), (uint)(Pos - at - 4));
        }

        private void Content()
        {
            EndAttributes();
            U8(0x02);
        }

        private void EmptyEnd()
        {
            EndAttributes();
            U8(0x03);
            Closed();
        }

        private void End()
        {
            U8(0x04);
            Closed();
        }

        private void Closed()
        {
            int at = _open.Pop().Size;
            BinaryPrimitives.WriteUInt32LittleEndian(B.AsSpan(at), (uint)(Pos - at - 4));
        }

        private void Attr(string name, bool more)
        {
            U8(more ? (byte)0x46 : (byte)0x06);
            Name(name);
        }

        private void Text(string text)
        {
            U8(0x05);
            U8(0x01);
            U16(text.Length);
            Bytes(Encoding.Unicode.GetBytes(text));
        }

        private void Sub(int index, byte type, bool optional = false)
        {
            U8(optional ? (byte)0x0E : (byte)0x0D);
            U16(index);
            U8(type);
        }

        /// <summary>A name's chunk offset; the first use defines the name in place, right after the offset, and enters it in the chunk's name table.</summary>
        private void Name(string name)
        {
            if (_names.TryGetValue(name, out var at)) { U32((uint)at); return; }
            int self = Pos + 4;
            _names[name] = self;
            U32((uint)self);
            ushort hash = 0;
            foreach (var ch in name) hash = (ushort)(hash * 65599 + ch);
            // Each of the 64 buckets chains its names through their next-name field.
            int bucket = 128 + hash % 64 * 4;
            U32(BinaryPrimitives.ReadUInt32LittleEndian(B.AsSpan(bucket)));
            BinaryPrimitives.WriteUInt32LittleEndian(B.AsSpan(bucket), (uint)self);
            U16(hash);
            U16(name.Length);
            Bytes(Encoding.Unicode.GetBytes(name));
            U16(0);
        }

        private void U8(byte v) => B[Pos++] = v;
        private void U16(int v) { BinaryPrimitives.WriteUInt16LittleEndian(B.AsSpan(Pos), (ushort)v); Pos += 2; }
        private void U32(uint v) { BinaryPrimitives.WriteUInt32LittleEndian(B.AsSpan(Pos), v); Pos += 4; }
        private void U64(ulong v) { BinaryPrimitives.WriteUInt64LittleEndian(B.AsSpan(Pos), v); Pos += 8; }
        private void Bytes(ReadOnlySpan<byte> b) { b.CopyTo(B.AsSpan(Pos)); Pos += b.Length; }
    }
}
