namespace Corvus.Mcp;

/// <summary>The server's standard input and output as the MCP stream transport reads and writes them.</summary>
internal static class StdioStreams
{
    /// <summary>Standard input; a read waits for its token, as the SDK's stdio transport reads it.</summary>
    public static Stream Input() => new CancellableInput(Console.OpenStandardInput());

    // How long a flush holds its caller's thread before it completes on the
    // writer thread: past it, the client is not reading.
    private static readonly TimeSpan QuickFlush = TimeSpan.FromMilliseconds(100);

    /// <summary>
    /// <paramref name="inner"/> written by a thread of its own: a write queues its bytes and a flush completes once
    /// everything queued before it is written. The console stream's own asynchronous write takes a thread-pool thread,
    /// and a write on the caller's thread blocks it while the client is not reading.
    /// </summary>
    public static Stream Output(Stream inner) => Output(inner, QuickFlush);

    /// <summary><see cref="Output(Stream)"/> with a flush held on its caller's thread for up to <paramref name="quickFlush"/>.</summary>
    internal static Stream Output(Stream inner, TimeSpan quickFlush) => new QueuedOutput(inner, quickFlush);

    private sealed class CancellableInput(Stream inner) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            inner.ReadAsync(buffer, offset, count, cancellationToken).WaitAsync(cancellationToken);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var read = inner.ReadAsync(buffer, cancellationToken);
            return read.IsCompletedSuccessfully ? read : new ValueTask<int>(read.AsTask().WaitAsync(cancellationToken));
        }

        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing) inner.Dispose();
            base.Dispose(disposing);
        }
    }

    private sealed class QueuedOutput : Stream
    {
        private readonly Stream _inner;
        private readonly TimeSpan _quickFlush;
        private readonly Thread _writer;
        // Byte chunks, flush markers (a TaskCompletionSource) and null for
        // the end.
        private readonly Queue<object?> _queue = new();
        private Exception? _failed;
        private bool _ended;

        public QueuedOutput(Stream inner, TimeSpan quickFlush)
        {
            _inner = inner;
            _quickFlush = quickFlush;
            _writer = new Thread(Drain) { IsBackground = true, Name = "Corvus standard output" };
            _writer.Start();
        }

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (buffer.Length > 0) Enqueue(buffer.ToArray());
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            Write(buffer.AsSpan(offset, count));
            return Task.CompletedTask;
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Write(buffer.Span);
            return ValueTask.CompletedTask;
        }

        // The writer thread runs a flush's continuation: a flush it waited for
        // itself would never complete.
        public override void Flush()
        {
            if (Thread.CurrentThread == _writer) _inner.Flush();
            else FlushAsync(CancellationToken.None).GetAwaiter().GetResult();
        }

        // A flush the writer completes while the caller's await is subscribing
        // to it resumes the caller on a thread-pool thread: the runtime queues
        // a continuation added too late to a task completed meanwhile. A quick
        // flush is waited for here and returned complete, so the caller
        // resumes on its own thread. The writer thread, running a slow flush's
        // continuation, never waits: only it can drain the flush.
        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            var flushed = new TaskCompletionSource();
            Enqueue(flushed);
            if (Thread.CurrentThread != _writer)
            {
                try { flushed.Task.Wait(_quickFlush, cancellationToken); }
                catch (Exception ex) when (ex is AggregateException or OperationCanceledException) { }
            }
            return flushed.Task.WaitAsync(cancellationToken);
        }

        private void Enqueue(object item)
        {
            lock (_queue)
            {
                if (_failed != null) throw new IOException("standard output failed", _failed);
                ObjectDisposedException.ThrowIf(_ended, this);
                _queue.Enqueue(item);
                Monitor.Pulse(_queue);
            }
        }

        private void Drain()
        {
            while (true)
            {
                object? item;
                lock (_queue)
                {
                    while (_queue.Count == 0) Monitor.Wait(_queue);
                    item = _queue.Dequeue();
                }
                if (item == null) break;
                try
                {
                    if (item is byte[] bytes) _inner.Write(bytes);
                    else
                    {
                        _inner.Flush();
                        ((TaskCompletionSource)item).TrySetResult();
                    }
                }
                catch (Exception ex)
                {
                    Fail(ex, item as TaskCompletionSource);
                    return;
                }
            }
            _inner.Dispose();
        }

        // Every flush still queued fails with the write's exception.
        private void Fail(Exception ex, TaskCompletionSource? current)
        {
            List<TaskCompletionSource> waiting;
            lock (_queue)
            {
                _failed = ex;
                waiting = [.. _queue.OfType<TaskCompletionSource>()];
                _queue.Clear();
            }
            current?.TrySetException(ex);
            foreach (var flush in waiting) flush.TrySetException(ex);
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                lock (_queue)
                {
                    if (!_ended)
                    {
                        _ended = true;
                        _queue.Enqueue(null);
                        Monitor.Pulse(_queue);
                    }
                }
            base.Dispose(disposing);
        }
    }
}
