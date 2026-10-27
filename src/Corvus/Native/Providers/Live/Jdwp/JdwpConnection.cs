using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Text;
using Corvus.Core;

namespace Corvus.Native.Providers.Live.Jdwp;

/// <summary>A JDWP connection over one TCP socket; a packet over <see cref="MaxPacket"/> ends it.</summary>
internal sealed class JdwpConnection : IAsyncDisposable
{
    private const int MaxPacket = 64 << 20;
    private static readonly byte[] Handshake = "JDWP-Handshake"u8.ToArray();
    private readonly TcpClient _tcp = new() { NoDelay = true };
    private readonly ConcurrentDictionary<int, TaskCompletionSource<byte[]>> _pending = new();
    private readonly SemaphoreSlim _send = new(1, 1);
    private readonly TaskCompletionSource<string> _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private NetworkStream? _stream;
    private Action<JdwpConnection, byte[]>? _composite;
    private int _next;

    /// <summary>Byte sizes of object, reference type, method, field and frame ids.</summary>
    public int ObjectId { get; private set; } = 8;
    public int ReferenceTypeId { get; private set; } = 8;
    public int MethodId { get; private set; } = 8;
    public int FieldId { get; private set; } = 8;
    public int FrameId { get; private set; } = 8;


    /// <summary>Completes with the reason once the connection ends.</summary>
    public Task<string> Closed => _closed.Task;

    /// <summary>Connects and reads the id sizes; <paramref name="composite"/> gets every event on the receive thread from the handshake on, so the VM start event is not lost (8-byte ids until sizes are read).</summary>
    public static async Task<JdwpConnection> ConnectAsync(string host, int port, TimeSpan timeout, Action<JdwpConnection, byte[]> composite, CancellationToken ct)
    {
        var c = new JdwpConnection { _composite = composite };
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(timeout);
        try
        {
            await c._tcp.ConnectAsync(host, port, limit.Token).ConfigureAwait(false);
            c._stream = c._tcp.GetStream();
            await c._stream.WriteAsync(Handshake, limit.Token).ConfigureAwait(false);
            var answer = new byte[Handshake.Length];
            await c._stream.ReadExactlyAsync(answer, limit.Token).ConfigureAwait(false);
            if (!answer.AsSpan().SequenceEqual(Handshake)) throw new IOException("the peer did not answer the JDWP handshake");
        }
        catch (Exception ex) when (ex is SocketException or IOException or OperationCanceledException && !ct.IsCancellationRequested)
        {
            c._tcp.Dispose();
            throw new ToolError(ErrorCode.NotFound, $"No JDWP agent answers at {host}:{port}: {ex.Message}",
                "start the program with -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=127.0.0.1:PORT; a JVM takes one debugger at a time");
        }
        _ = Task.Run(c.ReceiveAsync, CancellationToken.None);
        var sizes = new JdwpReader(await c.SendAsync(1, 7, [], timeout, ct).ConfigureAwait(false), c);
        (c.FieldId, c.MethodId, c.ObjectId, c.ReferenceTypeId, c.FrameId) = (sizes.Int(), sizes.Int(), sizes.Int(), sizes.Int(), sizes.Int());
        return c;
    }

    /// <summary>Sends command <paramref name="set"/>/<paramref name="command"/> and returns the reply data; a JDWP error is a <see cref="ToolError"/> naming it.</summary>
    public async Task<byte[]> SendAsync(byte set, byte command, byte[] data, TimeSpan timeout, CancellationToken ct)
    {
        var id = Interlocked.Increment(ref _next);
        var answer = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[id] = answer;
        var packet = new byte[11 + data.Length];
        BinaryPrimitives.WriteInt32BigEndian(packet, packet.Length);
        BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(4), id);
        (packet[9], packet[10]) = (set, command);
        data.CopyTo(packet, 11);
        try
        {
            await _send.WaitAsync(ct).ConfigureAwait(false);
            try { await _stream!.WriteAsync(packet, ct).ConfigureAwait(false); }
            finally { _send.Release(); }
            var done = await Task.WhenAny(answer.Task, _closed.Task, Task.Delay(timeout, ct)).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            if (done == answer.Task) return await answer.Task.ConfigureAwait(false);
            if (done == _closed.Task) throw new ToolError(ErrorCode.Failed, $"The JDWP connection ended during command {set}/{command}: {_closed.Task.Result}.");
            throw new ToolError(ErrorCode.Timeout, $"The JVM did not answer command {set}/{command} within {timeout.TotalSeconds:0} s.");
        }
        catch (IOException ex) { throw new ToolError(ErrorCode.Failed, $"The JDWP connection failed during command {set}/{command}: {ex.Message}"); }
        finally { _pending.TryRemove(id, out _); }
    }

    private async Task ReceiveAsync()
    {
        var header = new byte[11];
        string reason = "closed by the JVM";
        try
        {
            while (true)
            {
                await _stream!.ReadExactlyAsync(header).ConfigureAwait(false);
                int length = BinaryPrimitives.ReadInt32BigEndian(header);
                if (length is < 11 or > MaxPacket) { reason = $"a packet of {length} bytes"; break; }
                var data = new byte[length - 11];
                await _stream.ReadExactlyAsync(data).ConfigureAwait(false);
                int id = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(4));
                if ((header[8] & 0x80) != 0)
                {
                    if (!_pending.TryGetValue(id, out var answer)) continue;
                    var error = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(9));
                    if (error == 0) answer.TrySetResult(data);
                    else answer.TrySetException(new ToolError(ErrorCode.Failed, $"The JVM refused the command: {ErrorName(error)} ({error})."));
                }
                // Event.Composite is the only command a JVM sends.
                else if (header[9] == 64 && header[10] == 100) _composite?.Invoke(this, data);
            }
        }
        catch (EndOfStreamException) { }
        catch (IOException ex) { reason = ex.Message; }
        catch (ObjectDisposedException) { reason = "closed"; }
        foreach (var p in _pending.Values) p.TrySetException(new ToolError(ErrorCode.Failed, $"The JDWP connection ended: {reason}."));
        _closed.TrySetResult(reason);
    }

    // The JDWP specification's error constants met in practice; others are named by number.
    public static string ErrorName(int error) => error switch
    {
        10 => "INVALID_THREAD",
        13 => "THREAD_NOT_SUSPENDED",
        20 => "INVALID_OBJECT",
        21 => "INVALID_CLASS",
        22 => "CLASS_NOT_PREPARED",
        23 => "INVALID_METHODID",
        24 => "INVALID_LOCATION",
        30 => "INVALID_FRAMEID",
        35 => "OPAQUE_FRAME",
        99 => "NOT_IMPLEMENTED",
        101 => "ABSENT_INFORMATION",
        102 => "INVALID_EVENT_TYPE",
        112 => "VM_DEAD",
        113 => "INTERNAL",
        _ => "error",
    };

    public async ValueTask DisposeAsync()
    {
        _tcp.Dispose();
        _closed.TrySetResult("closed");
        await Task.CompletedTask.ConfigureAwait(false);
    }
}

/// <summary>Big-endian JDWP data with the connection's id sizes; a read past the end throws <see cref="EndOfStreamException"/>.</summary>
internal sealed class JdwpReader(byte[] data, JdwpConnection sizes)
{
    private int _at;

    public byte Byte() => _at < data.Length ? data[_at++] : throw new EndOfStreamException("JDWP data ended early");
    public int Int() => BinaryPrimitives.ReadInt32BigEndian(Take(4));
    public long Long() => BinaryPrimitives.ReadInt64BigEndian(Take(8));
    public long Id(int size) => size switch
    {
        8 => BinaryPrimitives.ReadInt64BigEndian(Take(8)),
        4 => BinaryPrimitives.ReadUInt32BigEndian(Take(4)),
        _ => Sized(Take(size)),
    };
    public long Object() => Id(sizes.ObjectId);
    public long Type() => Id(sizes.ReferenceTypeId);
    public long Method() => Id(sizes.MethodId);
    public long Frame() => Id(sizes.FrameId);
    public string String() => Encoding.UTF8.GetString(Take(Int()));
    public JdwpLocation Location() => new(Byte(), Type(), Method(), Long());

    private static long Sized(ReadOnlySpan<byte> b)
    {
        long v = 0;
        foreach (var x in b) v = (v << 8) | x;
        return v;
    }

    private ReadOnlySpan<byte> Take(int n)
    {
        if (n < 0 || _at + n > data.Length) throw new EndOfStreamException("JDWP data ended early");
        _at += n;
        return data.AsSpan(_at - n, n);
    }
}

/// <summary>Big-endian JDWP command data with the connection's id sizes.</summary>
internal sealed class JdwpWriter(JdwpConnection sizes)
{
    private readonly List<byte> _bytes = [];

    public JdwpWriter Byte(byte v) { _bytes.Add(v); return this; }
    public JdwpWriter Int(int v) { Span<byte> b = stackalloc byte[4]; BinaryPrimitives.WriteInt32BigEndian(b, v); _bytes.AddRange(b); return this; }
    public JdwpWriter Long(long v) { Span<byte> b = stackalloc byte[8]; BinaryPrimitives.WriteInt64BigEndian(b, v); _bytes.AddRange(b); return this; }
    public JdwpWriter Id(long v, int size) { for (int i = size - 1; i >= 0; i--) _bytes.Add((byte)(v >> (8 * i))); return this; }
    public JdwpWriter Object(long v) => Id(v, sizes.ObjectId);
    public JdwpWriter Type(long v) => Id(v, sizes.ReferenceTypeId);
    public JdwpWriter Method(long v) => Id(v, sizes.MethodId);
    public JdwpWriter String(string v) { var b = Encoding.UTF8.GetBytes(v); Int(b.Length); _bytes.AddRange(b); return this; }
    public JdwpWriter Location(JdwpLocation l) => Byte(l.Tag).Type(l.Class).Method(l.Method).Long(l.Index);
    public byte[] ToArray() => [.. _bytes];
}

/// <summary>A code location: type tag (1 class, 2 interface), class id, method id and bytecode index.</summary>
internal readonly record struct JdwpLocation(byte Tag, long Class, long Method, long Index);
