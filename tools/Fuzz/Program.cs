using Corvus.Fuzz;
using SharpFuzz;

return Execute(args);

static int Execute(string[] args)
{
    if (args is not [var command, ..]) return Usage();
    var flags = new Dictionary<string, string>();
    var positional = new List<string>();
    for (int i = 1; i < args.Length; i++)
    {
        if (args[i] is "--timeout" or "--max-runs" or "--out" or "--date")
        {
            if (i + 1 >= args.Length) return Fail($"{args[i]} needs a value. Next: Corvus.Fuzz {command} ... {args[i]} <value>");
            flags[args[i]] = args[++i];
        }
        else positional.Add(args[i]);
    }
    if (!int.TryParse(flags.GetValueOrDefault("--timeout", "10"), out var seconds) || seconds < 1)
        return Fail("--timeout is a whole number of seconds, 1 or more.");
    if (!int.TryParse(flags.GetValueOrDefault("--max-runs", "5000"), out var maxRuns) || maxRuns < 1)
        return Fail("--max-runs is a whole number, 1 or more.");
    var timeout = TimeSpan.FromSeconds(seconds);
    switch (command)
    {
        case "list":
            foreach (var t in FuzzTargets.All) Console.WriteLine(t.Name);
            return 0;
        case "run" when positional is [var name]:
            return Target(name) is { } run ? Run(run, timeout) : 2;
        case "check" when positional is [var name, var file]:
            return Target(name) is { } check ? Check(check, file, timeout) : 2;
        case "fixture" when positional is [var name, var file]:
            return Target(name) is { } fix ? Fixture(fix, file, flags.GetValueOrDefault("--out", "."), maxRuns, timeout) : 2;
        case "queue" when positional is [var mode]:
            return Queue(mode, flags.GetValueOrDefault("--date"));
        case "replay" when positional is [var folder]:
            return Replay(folder, timeout);
        default:
            return Usage();
    }
}

static int Usage()
{
    Console.Error.WriteLine("""
        Usage: Corvus.Fuzz <command> [--timeout seconds] [--max-runs n]
          list                                  the targets
          run <target>                          one input from stdin, under afl-fuzz (instrument corvus.dll with sharpfuzz first)
          check <target> <file>                 exit 0 when the read passes, 1 when it fails
          fixture <target> <file> [--out dir]   reduce a failing file to <target>-<hash>.bin
                                                exit 0 written, 3 the file does not fail
          queue nightly|sweep [--date yyyy-MM-dd]
                                                the targets of that night's rotation, or every target; starts no run
          replay <folder>                       read every <target>-<hash>.bin; exit 1 when one fails
        Exit 2: bad arguments or a missing target, file or folder.
        """);
    return 2;
}

static int Queue(string mode, string? date)
{
    var day = DateOnly.FromDateTime(DateTime.UtcNow);
    if (date != null && !DateOnly.TryParseExact(date, "yyyy-MM-dd", out day))
        return Fail($"--date is yyyy-MM-dd, not '{date}'. Next: Corvus.Fuzz queue {mode} --date {DateTime.UtcNow:yyyy-MM-dd}");
    if (FuzzRotation.Queue(mode, day) is not { } queue)
        return Fail($"No queue '{mode}'. Next: Corvus.Fuzz queue {string.Join("|", FuzzRotation.Modes)}");
    foreach (var t in queue) Console.WriteLine(t.Name);
    return 0;
}

static int Fail(string message)
{
    Console.Error.WriteLine(message);
    return 2;
}

static FuzzTarget? Target(string name)
{
    var target = FuzzTargets.Find(name);
    if (target == null) Console.Error.WriteLine($"No target '{name}'. Next: Corvus.Fuzz list");
    return target;
}

static int Run(FuzzTarget target, TimeSpan timeout)
{
    // An exception other than a tool error ends the process, which afl-fuzz records as a crash.
    Fuzzer.OutOfProcess.Run(stream =>
    {
        var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        using var cts = new CancellationTokenSource(timeout);
        target.Invoke(buffer.ToArray(), cts.Token);
    });
    return 0;
}

static int Check(FuzzTarget target, string file, TimeSpan timeout)
{
    if (!File.Exists(file)) return Fail($"No file '{file}'. Next: Corvus.Fuzz check {target.Name} <existing file>");
    if (FuzzTargets.Probe(target, File.ReadAllBytes(file), timeout) is not { } failure)
    {
        Console.WriteLine("pass");
        return 0;
    }
    Console.WriteLine($"fail {failure.Signature}: {failure.Message}. Next: Corvus.Fuzz fixture {target.Name} {file}");
    return 1;
}

static int Fixture(FuzzTarget target, string file, string outDir, int maxRuns, TimeSpan timeout)
{
    if (!File.Exists(file)) return Fail($"No file '{file}'. Next: Corvus.Fuzz fixture {target.Name} <existing file>");
    var input = File.ReadAllBytes(file);
    if (FuzzTargets.Probe(target, input, timeout) is not { } failure)
    {
        Console.Error.WriteLine($"The file does not fail on {target.Name}. Next: Corvus.Fuzz fixture <target afl-fuzz ran> {file}; Corvus.Fuzz list names the targets.");
        return 3;
    }
    var reduced = Minimizer.Reduce(target, input, failure.Signature, maxRuns, timeout);
    Directory.CreateDirectory(outDir);
    var path = Path.Combine(outDir, FuzzTargets.FixtureName(target, reduced.Bytes));
    File.WriteAllBytes(path, reduced.Bytes);
    Console.WriteLine($"{path} {failure.Signature} {input.Length} -> {reduced.Bytes.Length} bytes in {reduced.Runs} reads" +
        (reduced.Capped ? $"; stopped at --max-runs {maxRuns}, run fixture on the written file with a higher --max-runs to reduce further" : ""));
    return 0;
}

static int Replay(string folder, TimeSpan timeout)
{
    if (!Directory.Exists(folder)) return Fail($"No folder '{folder}'. Next: Corvus.Fuzz replay <folder of fixtures>");
    int failed = 0, read = 0, unnamed = 0;
    foreach (var file in Directory.EnumerateFiles(folder, "*.bin").Order(StringComparer.Ordinal))
    {
        if (FuzzTargets.OfFixture(file) is not { } target)
        {
            unnamed++;
            continue;
        }
        read++;
        if (FuzzTargets.Probe(target, File.ReadAllBytes(file), timeout) is not { } failure) continue;
        failed++;
        Console.WriteLine($"fail {Path.GetFileName(file)} {failure.Signature}: {failure.Message}. Next: Corvus.Fuzz check {target.Name} {file}");
    }
    Console.WriteLine($"read {read} fixtures, {failed} failed" +
        (unnamed > 0 ? $", {unnamed} named for no target (unknown, not read). Next: Corvus.Fuzz list, then rename them <target>-<hash>.bin" : ""));
    return failed > 0 ? 1 : 0;
}
