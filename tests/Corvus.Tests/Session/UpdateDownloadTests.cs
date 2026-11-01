using System.Net;
using Microsoft.Extensions.Time.Testing;
using Corvus.Core;
using Corvus.Setup;

namespace Corvus.Tests;

/// <summary>The update download ends on a stall, not on a total time.</summary>
public sealed class UpdateDownloadTests
{
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(10);

    // Yields each chunk after the test releases a gate; after the last it
    // waits for cancellation when hang is set.
    private sealed class GatedStream(byte[][] chunks, bool hang) : Stream
    {
        private int _next;
        public readonly SemaphoreSlim Gate = new(0);
        public readonly TaskCompletionSource Waiting = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            if (_next == chunks.Length)
            {
                if (!hang) return 0;
                Waiting.TrySetResult();
                await Task.Delay(Timeout.Infinite, ct);
            }
            await Gate.WaitAsync(ct);
            var chunk = chunks[_next++];
            chunk.CopyTo(buffer);
            return chunk.Length;
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class Handler(Stream body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(body) });
    }

    [Fact]
    public async Task A_slow_download_that_keeps_receiving_data_completes()
    {
        var clock = new FakeTimeProvider();
        var body = new GatedStream([[1, 2], [3], [4, 5]], hang: false);
        using var http = new HttpClient(new Handler(body));
        var rule = new StallRule(Window, clock);
        var download = GitHubHttp.DownloadAsync(http, "https://api.github.com/a", rule, clock, default);
        foreach (var unit in new[] { "2 of unknown bytes", "3 of unknown bytes", "5 of unknown bytes" })
        {
            clock.Advance(TimeSpan.FromMinutes(8));
            body.Gate.Release();
            while (rule.LastUnit != unit && !download.IsCompleted) await Task.Yield();
        }
        Assert.Equal([1, 2, 3, 4, 5], await download);
    }

    [Fact]
    public async Task A_download_without_data_for_the_window_names_its_last_progress()
    {
        var clock = new FakeTimeProvider();
        var body = new GatedStream([[1, 2]], hang: true);
        using var http = new HttpClient(new Handler(body));
        var download = GitHubHttp.DownloadAsync(http, "https://api.github.com/a", new StallRule(Window, clock), clock, default);
        body.Gate.Release();
        await body.Waiting.Task;
        clock.Advance(Window);
        var stalled = await Assert.ThrowsAsync<TimeoutException>(() => download);
        Assert.Contains("last progress: 2 of unknown bytes", stalled.Message);
    }

    private sealed class HangingHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            await Task.Delay(Timeout.Infinite, ct);
            return null!;
        }
    }

    [Fact]
    public async Task A_download_without_response_headers_names_the_wait()
    {
        var clock = new FakeTimeProvider();
        using var http = new HttpClient(new HangingHandler());
        var download = GitHubHttp.DownloadAsync(http, "https://api.github.com/a", new StallRule(Window, clock), clock, default);
        clock.Advance(Window);
        var stalled = await Assert.ThrowsAsync<TimeoutException>(() => download);
        Assert.Contains("last progress: waiting for the response", stalled.Message);
    }

    [Fact]
    public void A_status_failure_is_separated_from_the_update_command()
    {
        var line = Installation.DownloadFailure(new HttpRequestException("Response status code does not indicate success: 404 (Not Found)"), "2.8.0");
        Assert.Contains("(Not Found). Run: corvus update --version 2.8.0", line);
    }

    [Fact]
    public void A_failed_download_names_the_update_command_for_its_release()
    {
        var line = Installation.DownloadFailure(new TimeoutException("no data for 600 s."), "2.8.0");
        Assert.Contains("corvus update --version 2.8.0", line);
    }
}
