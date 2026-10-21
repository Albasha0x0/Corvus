using System.IO.Pipes;
using System.Text;
using Corvus.Native.Dump.Managed;
using Corvus.Native.Providers;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>The session's reads of a 32-bit program's runtime through a scripted 32-bit decoder process.</summary>
public sealed class LiveClrDecoderTests
{
    [Fact]
    public void An_error_answer_fails_that_read_only()
    {
        using var temp = new TempDir();
        int calls = 0;
        // Regression: one error answer marked the decoder stopped for the session (LiveClr.Read).
        // The first method_at answers an error, as when ClrMD throws on a module mid-load.
        using var process = new ScriptedDecoderProcess(request => request.StartsWith("method_at\t", StringComparison.Ordinal)
            ? ++calls == 1 ? """{"ok":false,"error":"module not ready"}""" : """{"ok":true,"value":{"assembly":"app.exe","signature":"App.Main()","start":4096}}"""
            : """{"ok":true,"value":null}""");
        // The client deletes its folder and that folder's parent.
        var folder = Directory.CreateDirectory(temp.File(Path.Combine("decoders", "1"))).FullName;
        using var clr = new LiveClr(ClrDecoder.Of(".NET Framework 4.8 (x86)", ClrHelperClient.Attach(process, folder)));
        string? stopped = null;
        var failed = new List<string>();
        clr.Stopped = why => stopped = why;
        clr.Failed = failed.Add;

        Assert.Null(clr.MethodAt(0x1010));
        Assert.Equal(("app.exe", "App.Main()", 4096UL), clr.MethodAt(0x1010));
        Assert.Null(clr.Unavailable);
        Assert.Null(stopped);
        Assert.Equal(["the 32-bit .NET decoder: module not ready"], failed);
    }

    /// <summary>A decoder process behind anonymous pipes: answers its start, then each request line with <c>answer(line)</c>.</summary>
    private sealed class ScriptedDecoderProcess : ChildProcess
    {
        private readonly AnonymousPipeServerStream _input = new(PipeDirection.Out), _output = new(PipeDirection.In), _errors = new(PipeDirection.In);
        private readonly AnonymousPipeClientStream _requests, _answers, _errorsOut;
        private readonly TaskCompletionSource _exited = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public ScriptedDecoderProcess(Func<string, string> answer)
        {
            _requests = new(PipeDirection.In, _input.ClientSafePipeHandle);
            _answers = new(PipeDirection.Out, _output.ClientSafePipeHandle);
            _errorsOut = new(PipeDirection.Out, _errors.ClientSafePipeHandle);
            new Thread(() =>
            {
                try
                {
                    using var reader = new StreamReader(_requests, Encoding.UTF8);
                    using var writer = new StreamWriter(_answers, new UTF8Encoding(false)) { AutoFlush = true, NewLine = "\n" };
                    writer.WriteLine("""{"ok":true,"value":null}""");
                    while (reader.ReadLine() is { } line && line != "exit") writer.WriteLine(answer(line));
                }
                catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
                _errorsOut.Dispose();
                _exited.TrySetResult();
            }) { IsBackground = true }.Start();
        }

        public override int Id => Environment.ProcessId;
        public override Stream StandardInput => _input;
        public override Stream StandardOutput => _output;
        public override Stream StandardError => _errors;
        public override bool HasExited => _exited.Task.IsCompleted;
        public override int? ExitCode => HasExited ? 0 : null;
        public override Task Exited => _exited.Task;
        public override IReadOnlyList<int> TreeProcessIds() => HasExited ? [] : [Id];
        public override void Kill() => _input.Dispose();

        public override void Dispose()
        {
            _input.Dispose();
            _exited.Task.Wait(TimeSpan.FromSeconds(5));
            _output.Dispose();
            _errors.Dispose();
        }
    }
}
