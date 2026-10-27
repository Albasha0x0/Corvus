using System.Buffers.Binary;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Corvus.Services.Simplify;

/// <summary>A read-only stream over an embedded resource or a byte array; a <see cref="ModuleType"/> stream gets its bytes from its base constructor call.</summary>
internal sealed class StreamObject : HeapObject
{
    public StreamObject(byte[] data) => Data = data;
    public StreamObject(ArrayObject backing, int start, int length) => Over(backing, start, length);
    public StreamObject(TypeDef moduleType) => ModuleType = moduleType;

    public void Over(ArrayObject backing, int start, int length)
    {
        Backing = backing;
        Data = (byte[])backing.Data;
        Start = start;
        Length = length;
    }

    public TypeDef? ModuleType { get; }
    public byte[]? Data { get; private set; }
    public ArrayObject? Backing { get; private set; }
    public int Start { get; private set; }
    public int Length { get; private set; } = -1;
    public int Size => Length < 0 ? Data!.Length : Length;
    public long Position { get; set; }
    public bool Disposed { get; set; }
    /// <summary>A FileStream over the module's own file (deterministic environment), not a MemoryStream.</summary>
    public bool FromFile { get; init; }
    /// <summary>A StreamReader read from it; the reader buffers, so the stream position is unknown.</summary>
    public bool Buffered { get; set; }
}

internal sealed class BinaryReaderObject(StreamObject stream, Encoding encoding) : HeapObject
{
    public StreamObject Stream { get; } = stream;
    public Encoding Encoding { get; } = encoding;
}

internal sealed class StreamReaderObject(StreamObject stream, Encoding encoding, bool detect) : HeapObject
{
    public StreamObject Stream { get; } = stream;
    public Encoding Encoding { get; } = encoding;
    public bool Detect { get; } = detect;
    /// <summary>The rest of the stream, decoded on the first read.</summary>
    public string? Text { get; set; }
    public int Position { get; set; }
}

/// <summary>An assembly other than the one analyzed; its resources are not read.</summary>
internal sealed class ForeignAssemblyObject : ReflectionObject
{
    protected override string[] Types => ["System.Reflection.Assembly", "System.Reflection.RuntimeAssembly"];
}

internal sealed partial class IlEvaluator
{
    private readonly Dictionary<string, byte[]?> _resources = new(StringComparer.Ordinal);

    /// <summary>The bytes of an embedded resource of the module, or null when absent, as the CLR returns.</summary>
    private byte[]? ResourceBytes(string name)
    {
        if (!_resources.TryGetValue(name, out var bytes))
        {
            bytes = module.Resources.OfType<EmbeddedResource>().FirstOrDefault(r => r.Name == name)?.CreateReader().ToArray();
            _resources[name] = bytes;
        }
        return bytes;
    }

    private static bool IsAssembly(object? v) => v is AssemblyObject or ForeignAssemblyObject;

    /// <summary>Resource, stream and reader calls; <paramref name="handled"/> false otherwise; files and network bail external-io.</summary>
    private object? ResourceCall(IMethod method, Code op, object?[] args, out bool handled)
    {
        handled = false;
        string type = method.DeclaringType?.FullName ?? "";
        string name = method.Name;
        int count = method.MethodSig?.Params.Count ?? 0;
        object? Receiver() => args.Length > 0 ? args[0] is Pointer p ? p.Get() : args[0] : null;

        if (type.StartsWith("System.Net.", StringComparison.Ordinal) ||
            type is "System.IO.File" or "System.IO.FileStream" or "System.IO.FileInfo" or "System.IO.Directory" or "System.IO.DirectoryInfo"
                or "System.IO.FileSystemInfo" || (type == "System.IO.StreamReader" && op == Code.Newobj && method.MethodSig!.Params[0].ElementType == ElementType.String))
            throw Bail(FallbackReason.ExternalIo, $"calls {Describe(method)}: files and the network differ between runs");

        handled = true;
        var receiver = Receiver();
        switch (type, name)
        {
            case ("System.Type", "get_Assembly"):
                return TypeOf(args[0]).Sig.ToTypeDefOrRef()?.ResolveTypeDef()?.Module == module ? _assemblyObject : new ForeignAssemblyObject();
            case ("System.Reflection.Assembly", "GetCallingAssembly"):
                // Evaluated code and its callers are the module's own.
                return _assemblyObject;
            case ("System.Reflection.Assembly", "GetEntryAssembly"):
                throw Bail(FallbackReason.ExternalIo, "the entry assembly is the host's, which differs between runs");
            case ("System.Reflection.Assembly", "GetManifestResourceNames") when IsAssembly(receiver):
                RequireOwn(receiver);
                return NewArray(module.Resources.OfType<EmbeddedResource>().Select(r => (object?)r.Name.String).ToArray());
            case ("System.Reflection.Assembly", "GetManifestResourceStream") when IsAssembly(receiver):
            {
                RequireOwn(receiver);
                string resource = count == 2 ? QualifiedResourceName(args[1], Str(args[2])) : Str(args[1]);
                if (ResourceBytes(resource) is not { } bytes) return null;
                Allocate(bytes.Length + 64);
                return new StreamObject(bytes) { Shared = _cctorDepth > 0 };
            }

            case ("System.IO.MemoryStream", ".ctor") when op == Code.Newobj || receiver is StreamObject { ModuleType: not null, Data: null }:
            {
                // Either newobj or a derived class's base constructor call, 'this' first.
                var ctorArgs = op == Code.Newobj ? args : args[1..];
                if (count == 0 || (count == 1 && method.MethodSig!.Params[0].ElementType == ElementType.I4))
                    throw Bail(FallbackReason.WritableStream, "creates an empty MemoryStream, which is only written to");
                var array = ArrayOf(ctorArgs[0]);
                if (array.Data is not byte[] data) throw Bail(FallbackReason.InvalidCode, "MemoryStream over an array that is not byte[]");
                int start = count >= 3 ? I4(ctorArgs[1]) : 0, length = count >= 3 ? I4(ctorArgs[2]) : data.Length;
                if (start < 0 || length < 0 || start + length > data.Length) throw Bail(FallbackReason.RuntimeError, "MemoryStream range outside the array");
                Allocate(64);
                if (op != Code.Newobj)
                {
                    ((StreamObject)receiver!).Over(array, start, length);
                    return Void;
                }
                return new StreamObject(array, start, length) { Shared = _cctorDepth > 0 };
            }
            case ("System.IO.MemoryStream", "ToArray") when receiver is StreamObject s:
                Open(s);
                return NewArray(s.Data.AsSpan(s.Start, s.Size).ToArray());

            case ("System.IO.BinaryReader", ".ctor") when op == Code.Newobj:
                return new BinaryReaderObject(StreamOf(args[0]), count >= 2 ? Enc(args[1]) : new UTF8Encoding(false, false)) { Shared = _cctorDepth > 0 };
            case ("System.IO.StreamReader", ".ctor") when op == Code.Newobj:
            {
                // Byte-order marks are detected unless a bool argument says otherwise; buffer size and leaveOpen are ignored.
                var stream = StreamOf(args[0]);
                var parameters = method.MethodSig!.Params;
                bool hasEncoding = count >= 2 && parameters[1].FullName == "System.Text.Encoding";
                var encoding = hasEncoding ? Enc(args[1]) : new UTF8Encoding(false);
                bool detect = count switch
                {
                    1 => true,
                    2 => !hasEncoding ? Numeric.IsTrue(args[1]) : true,
                    _ => Numeric.IsTrue(args[2]),
                };
                return new StreamReaderObject(stream, encoding, detect) { Shared = _cctorDepth > 0 };
            }
        }

        if (receiver is StreamObject { ModuleType: { } derived } && Chain(derived).Any(t => t.FullName == type)) type = "System.IO.MemoryStream";
        switch (receiver)
        {
            case StreamObject s when type is "System.IO.Stream" or "System.IO.MemoryStream" or "System.IO.UnmanagedMemoryStream" or "System.IDisposable":
                return StreamCall(s, method, name, count, args);
            case BinaryReaderObject r when type is "System.IO.BinaryReader" or "System.IDisposable":
                return BinaryReaderCall(r, method, name, args);
            case StreamReaderObject r when type is "System.IO.StreamReader" or "System.IO.TextReader" or "System.IDisposable":
                return StreamReaderCall(r, method, name);
        }
        handled = false;
        return null;
    }

    /// <summary>Whether a module class is modelled as a MemoryStream: a direct, non-generic subclass with no instance fields, overrides or events.</summary>
    private static bool IsStreamClass(TypeDef type) =>
        type.BaseType?.FullName == "System.IO.MemoryStream" && !type.HasGenericParameters && type.DeclaringType?.HasGenericParameters != true &&
        !type.Fields.Any(f => !f.IsStatic) && !type.Methods.Any(m => m.IsVirtual) && !type.HasEvents && !type.IsAbstract;

    private StreamObject NewStream(MethodDef ctor, object?[] args)
    {
        Allocate(64);
        var obj = new StreamObject(ctor.DeclaringType) { Shared = _cctorDepth > 0 };
        TriggerTypeInitializer(ctor);
        Execute(ctor, [obj, .. args]);
        if (obj.Data == null) throw Bail(FallbackReason.UnsupportedCall, $"{ctor.DeclaringType.FullName}: its constructor does not set up the stream from an array");
        return obj;
    }

    private void RequireOwn(object? assembly)
    {
        if (assembly is not AssemblyObject)
            throw Bail(FallbackReason.ExternalIo, "reads the resources of another assembly");
    }

    /// <summary>GetManifestResourceStream(Type, name): the name in the type's namespace.</summary>
    private string QualifiedResourceName(object? type, string name)
    {
        var t = TypeOf(type);
        var td = t.Sig.ToTypeDefOrRef()?.ResolveTypeDef();
        if (td?.Module != module) throw Bail(FallbackReason.ExternalIo, "reads the resources of another assembly");
        var ns = td.DeclaringType == null ? td.Namespace.String : td.DeclaringType.Namespace.String;
        return ns.Length > 0 ? ns + "." + name : name;
    }

    private StreamObject StreamOf(object? value) => (value is Pointer p ? p.Get() : value) switch
    {
        StreamObject s => s,
        null => throw Bail(FallbackReason.RuntimeError, "null stream"),
        _ => throw Bail(FallbackReason.UnsupportedValue, "a stream the evaluation did not open"),
    };

    private static void Open(StreamObject s)
    {
        if (s.Data == null) throw Bail(FallbackReason.InvalidCode, "the stream is used before its constructor set it up");
        if (s.Disposed) throw Bail(FallbackReason.RuntimeError, "the stream is closed");
    }

    /// <summary>Reads up to <paramref name="count"/> bytes at the stream's position.</summary>
    private static ReadOnlySpan<byte> Take(StreamObject s, int count)
    {
        Open(s);
        if (s.Buffered) throw Bail(FallbackReason.PlatformDependent, "the stream after a StreamReader read from it (the reader buffers)");
        long available = Math.Max(0, s.Size - s.Position);
        int n = (int)Math.Min(count, available);
        var span = s.Data.AsSpan((int)(s.Start + s.Position), n);
        s.Position += n;
        return span;
    }

    private object? StreamCall(StreamObject s, IMethod method, string name, int count, object?[] args)
    {
        switch (name, count)
        {
            case ("get_Length", 0): Open(s); return (long)s.Size;
            case ("get_Position", 0): Open(s); return s.Position;
            case ("set_Position", 1):
            {
                Open(s);
                RequireMutable(s);
                long position = Numeric.Bits(args[1]);
                if (position < 0) throw Bail(FallbackReason.RuntimeError, "negative stream position");
                s.Position = position;
                return Void;
            }
            case ("Seek", 2):
            {
                Open(s);
                RequireMutable(s);
                long target = I4(args[2]) switch
                {
                    0 => Numeric.Bits(args[1]),
                    1 => s.Position + Numeric.Bits(args[1]),
                    2 => s.Size + Numeric.Bits(args[1]),
                    _ => throw Bail(FallbackReason.RuntimeError, "invalid SeekOrigin"),
                };
                if (target < 0) throw Bail(FallbackReason.RuntimeError, "seek before the start of the stream");
                s.Position = target;
                return target;
            }
            case ("get_CanRead", 0): case ("get_CanSeek", 0): return s.Disposed ? 0 : 1;
            case ("get_CanWrite", 0): return 0;
            case ("ReadByte", 0):
            {
                RequireMutable(s);
                var b = Take(s, 1);
                return b.Length == 0 ? -1 : (int)b[0];
            }
            case ("Read", 3):
            {
                RequireMutable(s);
                var target = MutableArray(args[1]);
                if (target.Data is not byte[] buffer) throw Bail(FallbackReason.InvalidCode, "Stream.Read into an array that is not byte[]");
                int offset = I4(args[2]), length = I4(args[3]);
                if (offset < 0 || length < 0 || offset + length > buffer.Length) throw Bail(FallbackReason.RuntimeError, "Stream.Read outside the buffer");
                var before = Before(target, offset, length);
                var bytes = Take(s, length);
                bytes.CopyTo(buffer.AsSpan(offset));
                Committed(target, offset, before);
                return bytes.Length;
            }
            case ("Dispose", 0): case ("Close", 0):
                s.Disposed = true;
                return Void;
            case ("Write", _): case ("WriteByte", _): case ("SetLength", _): case ("Flush", _): case ("CopyTo", _): case ("WriteTo", _):
                throw Bail(FallbackReason.WritableStream, $"calls {Describe(method)}: the evaluator only reads streams");
            default:
                throw Bail(FallbackReason.UnsupportedCall, $"calls {Describe(method)}, which is not evaluable");
        }
    }

    private object? BinaryReaderCall(BinaryReaderObject r, IMethod method, string name, object?[] args)
    {
        var s = r.Stream;
        ReadOnlySpan<byte> Exactly(int n)
        {
            RequireMutable(s);
            var bytes = Take(s, n);
            return bytes.Length == n ? bytes : throw Bail(FallbackReason.RuntimeError, "end of stream (EndOfStreamException)");
        }
        switch (name)
        {
            case "ReadByte": return (int)Exactly(1)[0];
            case "ReadSByte": return (int)(sbyte)Exactly(1)[0];
            case "ReadBoolean": return Exactly(1)[0] != 0 ? 1 : 0;
            case "ReadInt16": return (int)BinaryPrimitives.ReadInt16LittleEndian(Exactly(2));
            case "ReadUInt16": return (int)BinaryPrimitives.ReadUInt16LittleEndian(Exactly(2));
            case "ReadInt32": case "ReadUInt32": return BinaryPrimitives.ReadInt32LittleEndian(Exactly(4));
            case "ReadInt64": case "ReadUInt64": return BinaryPrimitives.ReadInt64LittleEndian(Exactly(8));
            case "ReadSingle": return BinaryPrimitives.ReadSingleLittleEndian(Exactly(4));
            case "ReadDouble": return BinaryPrimitives.ReadDoubleLittleEndian(Exactly(8));
            case "Read7BitEncodedInt": return SevenBitInt(r);
            case "ReadBytes":
            {
                int n = I4(args[1]);
                if (n < 0) throw Bail(FallbackReason.RuntimeError, "negative count");
                RequireMutable(s);
                var bytes = Take(s, n).ToArray();
                return NewArray(bytes);
            }
            case "ReadString":
            {
                int length = SevenBitInt(r);
                if (length < 0) throw Bail(FallbackReason.RuntimeError, "invalid string length");
                return NewString(r.Encoding.GetString(Exactly(length)));
            }
            case "get_BaseStream": return s;
            case "Dispose": case "Close":
                s.Disposed = true;
                return Void;
            default:
                throw Bail(FallbackReason.UnsupportedCall, $"calls {Describe(method)}, which is not evaluable");
        }
    }

    /// <summary>BinaryReader's 7-bit encoded length: up to five bytes, low bits first.</summary>
    private int SevenBitInt(BinaryReaderObject r)
    {
        RequireMutable(r.Stream);
        int value = 0;
        for (int shift = 0; shift < 35; shift += 7)
        {
            var b = Take(r.Stream, 1);
            if (b.Length == 0) throw Bail(FallbackReason.RuntimeError, "end of stream (EndOfStreamException)");
            value |= (b[0] & 0x7F) << shift;
            if ((b[0] & 0x80) == 0) return value;
        }
        throw Bail(FallbackReason.RuntimeError, "bad 7-bit encoded int");
    }

    private object? StreamReaderCall(StreamReaderObject r, IMethod method, string name)
    {
        string Text()
        {
            if (r.Text == null)
            {
                RequireMutable(r.Stream);
                var bytes = Take(r.Stream, int.MaxValue);
                r.Stream.Buffered = true;
                var encoding = r.Encoding;
                int skip = 0;
                if (r.Detect)
                {
                    if (bytes.StartsWith((byte[])[0xEF, 0xBB, 0xBF])) (encoding, skip) = (new UTF8Encoding(false), 3);
                    else if (bytes.StartsWith((byte[])[0xFF, 0xFE, 0, 0])) (encoding, skip) = (new UTF32Encoding(false, false), 4);
                    else if (bytes.StartsWith((byte[])[0xFF, 0xFE])) (encoding, skip) = (new UnicodeEncoding(false, false), 2);
                    else if (bytes.StartsWith((byte[])[0xFE, 0xFF])) (encoding, skip) = (new UnicodeEncoding(true, false), 2);
                }
                else if (bytes.StartsWith(encoding.Preamble)) skip = encoding.Preamble.Length;
                r.Text = NewString(encoding.GetString(bytes[skip..]));
            }
            return r.Text;
        }
        switch (name)
        {
            case "ReadToEnd":
            {
                var text = Text();
                var rest = text[r.Position..];
                r.Position = text.Length;
                return rest;
            }
            case "ReadLine":
            {
                var text = Text();
                if (r.Position >= text.Length) return null;
                int end = text.IndexOfAny(['\r', '\n'], r.Position);
                if (end < 0) end = text.Length;
                var line = text[r.Position..end];
                r.Position = end < text.Length && text[end] == '\r' && end + 1 < text.Length && text[end + 1] == '\n' ? end + 2 : Math.Min(text.Length, end + 1);
                return line;
            }
            case "Peek":
            {
                var text = Text();
                return r.Position < text.Length ? (int)text[r.Position] : -1;
            }
            case "Read" when method.MethodSig?.Params.Count == 0:
            {
                var text = Text();
                return r.Position < text.Length ? (int)text[r.Position++] : -1;
            }
            case "get_EndOfStream": return r.Position >= Text().Length ? 1 : 0;
            case "Dispose": case "Close":
                r.Stream.Disposed = true;
                return Void;
            default:
                throw Bail(FallbackReason.UnsupportedCall, $"calls {Describe(method)}, which is not evaluable");
        }
    }
}
