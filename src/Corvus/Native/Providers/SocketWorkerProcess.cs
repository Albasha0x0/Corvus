using System.Net.Sockets;
using Corvus.Core;

namespace Corvus.Native.Providers;

/// <summary>
/// A worker served over a socket by a process the server did not start (a database open in IDA): its standard input
/// and output are the connection, it has no standard error, and killing or disposing it closes the connection, never
/// the process.
/// </summary>
internal sealed class SocketWorkerProcess : ChildProcess
{
    private readonly TcpClient _client;
    private readonly int _pid;
    private readonly NetworkStream _stream;
    private readonly ClosingStream _output;
    private readonly TaskCompletionSource _exited = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public SocketWorkerProcess(TcpClient client, int pid)
    {
        _client = client;
        _pid = pid;
        _stream = client.GetStream();
        _output = new ClosingStream(_stream, () => _exited.TrySetResult());
    }

    public override int Id => _pid;
    public override Stream StandardInput => _stream;
    public override Stream StandardOutput => _output;
    public override Stream StandardError => Stream.Null;
    public override bool HasExited => _exited.Task.IsCompleted;
    public override int? ExitCode => HasExited ? 0 : null;
    public override Task Exited => _exited.Task;

    // The serving process is the analyst's: no stall report samples it and no kill reaches it.
    public override IReadOnlyList<int> TreeProcessIds() => [];
    public override TimeSpan? TreeCpuTime() => null;

    public override void Kill() => Dispose();

    public override void Dispose()
    {
        _client.Dispose();
        _exited.TrySetResult();
    }

    // Reads the connection; the end of it (or a reset) is the worker's exit.
    private sealed class ClosingStream(Stream inner, Action closed) : ForwardReadStream
    {
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            try
            {
                int n = inner.Read(buffer);
                if (n == 0) closed();
                return n;
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException)
            {
                closed();
                return 0;
            }
        }
    }
}
