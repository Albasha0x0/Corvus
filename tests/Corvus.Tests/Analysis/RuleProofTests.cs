using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Services;
using Corvus.Services.Analysis;
using Corvus.Services.Analysis.Hunts;

namespace Corvus.Tests;

/// <summary>Hunting queries checked against folders of clean files and prior builds; every program is built from source with named pipes.</summary>
public sealed class RuleProofTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _ws = new();
    public void Dispose() { _ws.Dispose(); _dir.Dispose(); }

    private string Folder(string name) => Directory.CreateDirectory(_dir.File(name)).FullName;

    // A library with one method per pipe, so its pipes are its facts.
    private static string Build(string folder, string name, params string[] pipes)
    {
        var methods = string.Concat(pipes.Select((p, i) => "public static string P" + i + "() => @\"\\\\.\\pipe\\" + p + "\";"));
        var path = Path.Combine(folder, name + ".dll");
        File.WriteAllBytes(path, InspectionTests.Compile(name, "public static class " + name + " { " + methods + " }"));
        return path;
    }

    private HuntSet Prove(string file, ProofOptions options)
    {
        var summary = new InspectionService(_ws).Summarize(null, file, default, new FileViewOptions("hunts") { Proof = options });
        return (HuntSet)summary.Views["hunts"].Detail;
    }

    private static Hunt Pipe(HuntSet set, string name) => Assert.Single(set.Hunts, h => h.Facts.Any(f => f.Contains(name, StringComparison.Ordinal)));

    [Fact]
    public void A_fact_the_clean_files_carry_is_dropped_and_a_fact_of_the_program_alone_is_kept()
    {
        var clean = Folder("clean");
        for (int i = 0; i < 3; i++) Build(clean, "Clean" + i, "shared-pipe-beta", "clean-own-" + i);
        var file = Build(Folder("input"), "Subject", "shared-pipe-beta", "unique-pipe-alpha");
        var set = Prove(file, new ProofOptions(clean, MinFiles: 1));
        var shared = Pipe(set, "shared-pipe-beta").Proof!;
        Assert.Equal("drop", shared.Verdict);
        Assert.Equal(3, shared.CleanHits);
        Assert.Equal(3, shared.Samples.Count);
        var unique = Pipe(set, "unique-pipe-alpha").Proof!;
        Assert.Equal("keep", unique.Verdict);
        Assert.Equal(0, unique.CleanHits);
    }

    [Fact]
    public void Queries_are_ranked_keep_first_then_fewest_clean_hits()
    {
        var clean = Folder("clean");
        Build(clean, "Clean0", "one-hit-pipe");
        for (int i = 1; i < 4; i++) Build(clean, "Clean" + i, "many-hit-pipe");
        var file = Build(Folder("input"), "Subject", "many-hit-pipe", "one-hit-pipe", "no-hit-pipe");
        var verdicts = Prove(file, new ProofOptions(clean, MinFiles: 1)).Hunts.Select(h => h.Proof!.Verdict).ToList();
        Assert.Equal(verdicts.OrderBy(v => v == "keep" ? 0 : v == "review" ? 1 : 2), verdicts);
        Assert.Contains("review", verdicts);
        Assert.Equal("drop", verdicts[^1]);
    }

    [Fact]
    public void A_clean_copy_of_the_same_bytes_is_named_and_is_no_hit_on_a_fact()
    {
        var clean = Folder("clean");
        var file = Build(Folder("input"), "Subject", "copied-pipe");
        var copy = Path.Combine(clean, "Copy.dll");
        File.Copy(file, copy);
        var set = Prove(file, new ProofOptions(clean, MinFiles: 1));
        Assert.Equal([copy], set.Proof!.Clean.Copies);
        Assert.Equal(0, set.Proof.Clean.Read);
        var hash = Assert.Single(set.Hunts, h => h.Table == "DeviceFileEvents" && h.Facts[0].StartsWith("sha1:", StringComparison.Ordinal));
        Assert.Equal("review", hash.Proof!.Verdict);
        Assert.Contains(copy, hash.Proof.Reason, StringComparison.Ordinal);
        Assert.Equal(0, Pipe(set, "copied-pipe").Proof!.CleanHits);
    }

    [Fact]
    public void A_fact_added_in_build_3_of_5_is_reported_as_missing_from_the_builds_before_it()
    {
        var prior = Folder("prior");
        Build(prior, "Build1", "durable-pipe");
        Build(prior, "Build2", "durable-pipe");
        Build(prior, "Build3", "durable-pipe", "added-in-three");
        Build(prior, "Build4", "durable-pipe", "added-in-three");
        var file = Build(Folder("input"), "Build5", "durable-pipe", "added-in-three", "added-in-five");
        var set = Prove(file, new ProofOptions(Folder("clean"), prior, MinFiles: 1));
        var durable = Pipe(set, "durable-pipe").Proof!;
        Assert.Equal(("durable", 4), (durable.Status, durable.PriorHits));
        var added = Pipe(set, "added-in-three").Proof!;
        Assert.Equal(("changed", 2), (added.Status, added.PriorHits));
        Assert.Equal(["Build1.dll", "Build2.dll"], added.Facts[0].MissingFrom);
        Assert.Contains("missing from Build1.dll, Build2.dll", added.Reason, StringComparison.Ordinal);
        var only = Pipe(set, "added-in-five").Proof!;
        Assert.Equal(("new", 0), (only.Status, only.PriorHits));
    }

    [Fact]
    public void An_unreadable_clean_file_makes_the_scan_partial_and_a_query_with_no_hit_a_review()
    {
        var clean = Folder("clean");
        Build(clean, "Readable", "other-pipe");
        var locked = Build(clean, "Locked", "other-pipe");
        var file = Build(Folder("input"), "Subject", "lonely-pipe");
        using var hold = new FileStream(locked, FileMode.Open, FileAccess.Read, FileShare.None);
        var set = Prove(file, new ProofOptions(clean, MinFiles: 1));
        Assert.Equal((1, 1, false), (set.Proof!.Clean.Read, set.Proof.Clean.NotRead, set.Proof.Clean.Complete));
        Assert.Contains(set.Proof.Clean.Unread, u => u.StartsWith(locked, StringComparison.OrdinalIgnoreCase));
        var proof = Pipe(set, "lonely-pipe").Proof!;
        Assert.Equal("review", proof.Verdict);
        Assert.Contains("1 not read", proof.Reason, StringComparison.Ordinal);
        Assert.Contains(set.Notes, n => n.StartsWith("The clean scan is partial", StringComparison.Ordinal));
    }

    [Fact]
    public void An_unread_share_under_the_threshold_keeps_a_query_and_the_reason_names_it()
    {
        var clean = Folder("clean");
        for (int i = 0; i < 20; i++) Build(clean, "Clean" + i, "own-" + i);
        var locked = Build(clean, "Locked", "own-locked");
        var file = Build(Folder("input"), "Subject", "lonely-pipe");
        using var hold = new FileStream(locked, FileMode.Open, FileAccess.Read, FileShare.None);
        var proof = Pipe(Prove(file, new ProofOptions(clean, MinFiles: 1)), "lonely-pipe").Proof!;
        Assert.Equal("keep", proof.Verdict);
        Assert.Contains("1 not read", proof.Reason, StringComparison.Ordinal);
        var strict = Pipe(Prove(file, new ProofOptions(clean, UnreadPercent: 4, MinFiles: 1)), "lonely-pipe").Proof!;
        Assert.Equal("review", strict.Verdict);
    }

    [Fact]
    public void A_folder_over_max_files_is_read_to_the_bound_and_reported_partial()
    {
        var clean = Folder("clean");
        for (int i = 0; i < 3; i++) Build(clean, "Clean" + i, "own-" + i);
        var file = Build(Folder("input"), "Subject", "lonely-pipe");
        var set = Prove(file, new ProofOptions(clean, MaxFiles: 2, MinFiles: 1));
        Assert.Equal((2, 1), (set.Proof!.Clean.Read, set.Proof.Clean.Skipped));
        Assert.Equal("review", Pipe(set, "lonely-pipe").Proof!.Verdict);
    }

    [Fact]
    public async Task A_dropped_query_stays_in_the_saved_file_with_its_verdict_and_gets_no_rule()
    {
        var clean = Folder("clean");
        for (int i = 0; i < 3; i++) Build(clean, "Clean" + i, "shared-pipe-beta");
        var file = Build(Folder("input"), "Subject", "shared-pipe-beta", "unique-pipe-alpha");
        var tools = new Corvus.Tools.InspectionTools(new InspectionService(_ws), _ws);
        var saved = _dir.File("hunts.json");
        var text = await tools.SummarizeFile(path: file, view: "hunts", huntsPath: saved, cleanFolder: clean);
        Assert.Contains("dropped by the proof", text, StringComparison.Ordinal);
        var root = JsonNode.Parse(File.ReadAllBytes(saved))!;
        var dropped = root["hunts"]!.AsArray().Single(h => h!["proof"]!["verdict"]!.GetValue<string>() == "drop")!;
        Assert.DoesNotContain(root["detectionRules"]!.AsArray(), r => r!["id"]!.GetValue<string>() == dropped["id"]!.GetValue<string>());
        Assert.Contains(root["detectionRules"]!.AsArray(), r => r!["queryCondition"]!["queryText"]!.GetValue<string>().Contains("unique-pipe-alpha", StringComparison.Ordinal));
        Assert.Equal(3, root["proof"]!["clean"]!["read"]!.GetValue<int>());
    }

    [Fact]
    public async Task The_proof_parameters_are_refused_without_a_clean_folder_or_outside_the_hunts_view()
    {
        var file = Build(Folder("input"), "Subject", "lonely-pipe");
        var tools = new Corvus.Tools.InspectionTools(new InspectionService(_ws), _ws);
        var alone = await Assert.ThrowsAsync<ToolError>(() => tools.SummarizeFile(path: file, view: "hunts", dropAt: 2));
        Assert.Equal(ErrorCode.InvalidArgument, alone.Code);
        var other = await Assert.ThrowsAsync<ToolError>(() => tools.SummarizeFile(path: file, view: "overview", cleanFolder: Folder("clean")));
        Assert.Equal(ErrorCode.InvalidArgument, other.Code);
        var missing = await Assert.ThrowsAsync<ToolError>(() => tools.SummarizeFile(path: file, view: "hunts", cleanFolder: _dir.File("absent")));
        Assert.Equal(ErrorCode.NotFound, missing.Code);
    }

    private static HuntSet Plain(string kind, string value, string table = "DeviceRegistryEvents") =>
        new([new Hunt("h", "title", table, "DeviceEvents", [kind + ":" + value], IndicatorEvidence.String)], []);

    private string Readable(int count)
    {
        var clean = Folder("clean");
        for (int i = 0; i < count; i++) Build(clean, "Clean" + i, "own-" + i);
        return clean;
    }

    private string FolderOf(int count, string name = "clean")
    {
        var clean = Folder(name);
        for (int i = 0; i < count; i++) File.WriteAllText(Path.Combine(clean, "f" + i + ".bin"), "x");
        return clean;
    }

    [Fact]
    public void Text_files_cannot_show_a_registry_key_so_no_hit_is_unknown()
    {
        var clean = Folder("clean");
        for (int i = 0; i < 30; i++) File.WriteAllText(Path.Combine(clean, "note" + i + ".txt"), "plain text " + i);
        var keys = InspectionTests.Compile("Keys", """
            public static class Keys
            {
                public static object Open() => Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\Vendor\App");
            }
            """);
        var file = Path.Combine(Folder("input"), "Keys.dll");
        File.WriteAllBytes(file, keys);
        var registry = Assert.Single(Prove(file, new ProofOptions(clean)).Hunts, h => h.Table == "DeviceRegistryEvents").Proof!;
        Assert.Equal("review", registry.Verdict);
        Assert.Contains("could not show registry_key", registry.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void A_reason_names_only_the_unknown_kinds_the_query_depends_on()
    {
        var clean = Folder("clean");
        for (int i = 0; i < 30; i++) File.WriteAllText(Path.Combine(clean, "note" + i + ".txt"), "plain text " + i);
        var keys = InspectionTests.Compile("Keys", """
            public static class Keys
            {
                public static object Open() => Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\Vendor\App");
            }
            """);
        var file = Path.Combine(Folder("input"), "Keys.dll");
        File.WriteAllBytes(file, keys);
        var registry = Assert.Single(Prove(file, new ProofOptions(clean)).Hunts, h => h.Table == "DeviceRegistryEvents").Proof!;
        Assert.DoesNotContain("dll_name", registry.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void A_signer_a_clean_file_could_not_show_is_unknown_and_one_it_could_show_is_a_miss()
    {
        var set = Plain("signer", "CN=Example Publisher", "DeviceFileCertificateInfo");
        var clean = FolderOf(25);
        var blind = RuleProof.Apply(set, new ProofOptions(clean), (_, _) => new RuleProof.FileRead(false, [], new HashSet<string> { HuntKind.Signer }), default);
        Assert.Equal("review", blind.Hunts[0].Proof!.Verdict);
        var sighted = RuleProof.Apply(set, new ProofOptions(clean), (_, _) => new RuleProof.FileRead(false, [], new HashSet<string>()), default);
        Assert.Equal("keep", sighted.Hunts[0].Proof!.Verdict);
    }

    [Fact]
    public void A_query_over_several_facts_counts_the_files_that_carry_any_of_them()
    {
        var hunt = new Hunt("h", "libraries", "DeviceImageLoadEvents", "DeviceImageLoadEvents", ["dll_name:lib-a.dll", "dll_name:lib-b.dll"], IndicatorEvidence.Reference);
        var clean = FolderOf(4);
        var set = RuleProof.Apply(new HuntSet([hunt], []), new ProofOptions(clean, MinFiles: 1), (path, _) =>
            new RuleProof.FileRead(false, [new HuntFact(HuntKind.DllName, Path.GetFileName(path) is "f0.bin" or "f1.bin" ? "lib-a.dll" : "lib-b.dll", IndicatorEvidence.Reference)], new HashSet<string>()), default);
        var proof = set.Hunts[0].Proof!;
        Assert.Equal(("drop", 4), (proof.Verdict, proof.CleanHits));
    }

    [Fact]
    public void A_clean_folder_under_the_minimum_gives_a_review_that_states_the_count()
    {
        var keys = Prove(Build(Folder("input"), "Subject", "lonely-pipe"), new ProofOptions(Readable(3)));
        var proof = Pipe(keys, "lonely-pipe").Proof!;
        Assert.Equal("review", proof.Verdict);
        Assert.Contains("Only 3 clean files", proof.Reason, StringComparison.Ordinal);
        Assert.Contains("minimum is 20", proof.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void A_link_in_the_clean_folder_is_named_and_the_scan_is_partial()
    {
        var clean = FolderOf(2);
        var target = Folder("elsewhere");
        var link = Path.Combine(clean, "link");
        if (OperatingSystem.IsWindows())
        {
            using var mk = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd.exe", $"/c mklink /J \"{link}\" \"{target}\"") { CreateNoWindow = true, UseShellExecute = false })!;
            mk.WaitForExit();
        }
        else Directory.CreateSymbolicLink(link, target);
        var set = RuleProof.Apply(Plain("registry_key", "Software_X"), new ProofOptions(clean, MinFiles: 1), (_, _) => new RuleProof.FileRead(false, [], new HashSet<string>()), default);
        Assert.Equal(1, set.Proof!.Clean.Inaccessible);
        Assert.Contains(set.Proof.Clean.Unread, u => u.StartsWith(link, StringComparison.OrdinalIgnoreCase));
        Assert.False(set.Proof.Clean.Complete);
    }

    [Fact]
    public void A_file_that_times_out_is_not_read_and_the_scan_goes_on()
    {
        var clean = FolderOf(3);
        var set = RuleProof.Apply(Plain("registry_key", "Software_X"), new ProofOptions(clean, MinFiles: 1), (path, _) =>
            Path.GetFileName(path) == "f1.bin" ? throw new OperationCanceledException(new CancellationTokenSource().Token) : new RuleProof.FileRead(false, [], new HashSet<string>()), default);
        Assert.Equal((2, 1), (set.Proof!.Clean.Read, set.Proof.Clean.NotRead));
        Assert.Contains(set.Proof.Clean.Unread, u => u.EndsWith("timed out", StringComparison.Ordinal));
    }

    [Fact]
    public void A_caller_cancellation_still_ends_the_scan()
    {
        using var cts = new CancellationTokenSource();
        var clean = FolderOf(3);
        Assert.ThrowsAny<OperationCanceledException>(() => RuleProof.Apply(Plain("registry_key", "Software_X"), new ProofOptions(clean), (_, _) => { cts.Cancel(); cts.Token.ThrowIfCancellationRequested(); return null!; }, cts.Token));
    }

    [Fact]
    public void A_percent_outside_0_to_100_is_refused()
    {
        var error = Assert.Throws<ToolError>(() => RuleProof.Apply(Plain("registry_key", "Software_X"), new ProofOptions(FolderOf(1), UnreadPercent: 101), (_, _) => null!, default));
        Assert.Equal(ErrorCode.InvalidArgument, error.Code);
    }

    [Fact]
    public async Task The_text_output_shows_the_files_cut_by_max_files_and_the_folders_not_entered()
    {
        var clean = Folder("clean");
        for (int i = 0; i < 3; i++) Build(clean, "Clean" + i, "own-" + i);
        var file = Build(Folder("input"), "Subject", "lonely-pipe");
        var tools = new Corvus.Tools.InspectionTools(new InspectionService(_ws), _ws);
        var text = await tools.SummarizeFile(path: file, view: "hunts", cleanFolder: clean, maxFiles: 2);
        Assert.Contains("2 of 3 files read", text, StringComparison.Ordinal);
        Assert.Contains("1 past maxFiles", text, StringComparison.Ordinal);
    }

    [Fact]
    public void A_query_limited_to_the_file_says_the_clean_files_cannot_alert()
    {
        var clean = Folder("clean");
        for (int i = 0; i < 3; i++) Build(clean, "Clean" + i, "shared-pipe-beta");
        var file = Build(Folder("input"), "Subject", "shared-pipe-beta");
        var set = Prove(file, new ProofOptions(clean, MinFiles: 1));
        var pipe = Pipe(set, "shared-pipe-beta").Proof!;
        Assert.Equal(("drop", "file"), (pipe.Verdict, pipe.Scope));
        Assert.Contains("is common: 3 clean files carry it", pipe.Reason, StringComparison.Ordinal);
        Assert.Contains("cannot alert", pipe.Reason, StringComparison.Ordinal);
        Assert.DoesNotContain("false", pipe.Reason, StringComparison.OrdinalIgnoreCase);
        var hash = Assert.Single(set.Hunts, h => h.Table == "DeviceFileEvents" && h.Facts[0].StartsWith("sha1:", StringComparison.Ordinal)).Proof!;
        Assert.Equal("any", hash.Scope);
    }

    [Fact]
    public void Folders_that_contain_each_other_are_refused()
    {
        var clean = Folder("clean");
        var nested = Directory.CreateDirectory(Path.Combine(clean, "builds")).FullName;
        foreach (var (c, p) in new[] { (clean, nested), (nested, clean), (clean, clean) })
        {
            var error = Assert.Throws<ToolError>(() => RuleProof.Apply(Plain("registry_key", @"Software\X"), new ProofOptions(c, p), (_, _) => null!, default));
            Assert.Equal(ErrorCode.InvalidArgument, error.Code);
        }
    }

    [Fact]
    public void Prior_files_that_are_not_images_of_the_same_kind_are_not_builds()
    {
        var prior = Folder("prior");
        Build(prior, "Build1", "durable-pipe");
        Build(prior, "Build2", "durable-pipe");
        for (int i = 0; i < 3; i++) File.WriteAllText(Path.Combine(prior, "notes" + i + ".txt"), "text");
        var file = Build(Folder("input"), "Build3", "durable-pipe");
        var set = Prove(file, new ProofOptions(Folder("clean"), prior, MinFiles: 1));
        Assert.Equal((2, 3), (set.Proof!.Prior!.Read, set.Proof.Prior.Ignored));
        var proof = Pipe(set, "durable-pipe").Proof!;
        Assert.Equal(("durable", 2), (proof.Status, proof.PriorHits));
    }

    [Fact]
    public void A_prior_build_that_could_not_show_a_kind_is_unknown_for_a_fact_of_it()
    {
        var prior = FolderOf(3, "prior");
        var set = RuleProof.Apply(Plain("named_pipe", "svc"), new ProofOptions(Folder("clean"), prior, MinFiles: 1), (path, _) => Path.GetFileName(path) switch
        {
            "f0.bin" => new RuleProof.FileRead(false, [new HuntFact(HuntKind.NamedPipe, "svc", IndicatorEvidence.String)], new HashSet<string>()),
            "f1.bin" => new RuleProof.FileRead(false, [], new HashSet<string> { HuntKind.NamedPipe }),
            _ => new RuleProof.FileRead(false, [], new HashSet<string>()),
        }, default);
        var proof = set.Hunts[0].Proof!;
        Assert.Equal("unknown", proof.Status);
        Assert.Equal(1, proof.Facts[0].PriorUnknown);
        Assert.Equal(["f2.bin"], proof.Facts[0].MissingFrom);
        Assert.Contains("1 of 3 prior builds could not show it", proof.Reason, StringComparison.Ordinal);
    }

    private static string BuildLibraries(string folder, string name, params string[] libraries)
    {
        var loads = string.Concat(libraries.Select((l, i) => "public static object L" + i + "() => System.Runtime.InteropServices.NativeLibrary.Load(\"" + l + "\");"));
        var path = Path.Combine(folder, name + ".dll");
        File.WriteAllBytes(path, InspectionTests.Compile(name, "public static class " + name + " { " + loads + " }"));
        return path;
    }

    [Fact]
    public void A_library_query_with_one_common_name_is_written_again_without_it()
    {
        var clean = Folder("clean");
        for (int i = 0; i < 3; i++) BuildLibraries(clean, "Clean" + i, "common-lib.dll");
        var file = BuildLibraries(Folder("input"), "Subject", "common-lib.dll", "own-lib.dll");
        var query = Assert.Single(Prove(file, new ProofOptions(clean, MinFiles: 1)).Hunts, h => h.Facts[0].StartsWith("dll_name:", StringComparison.Ordinal));
        Assert.DoesNotContain("common-lib.dll", query.Kql, StringComparison.Ordinal);
        Assert.Contains("own-lib.dll", query.Kql, StringComparison.Ordinal);
        Assert.Contains("dll_name:own-lib.dll", query.Facts);
        Assert.DoesNotContain("dll_name:common-lib.dll", query.Facts);
        Assert.Equal(["dll_name:common-lib.dll (3 clean files)"], query.Proof!.Removed);
        Assert.Equal("keep", query.Proof.Verdict);
        Assert.Contains("written again without dll_name:common-lib.dll", query.Proof.Reason, StringComparison.Ordinal);
        Assert.Empty(KqlCheck.Diagnostics(query.Kql));
    }

    [Fact]
    public void A_library_query_whose_names_are_all_common_is_dropped_whole()
    {
        var hunt = KqlHunts.LibraryHunt(["common-a.dll", "common-b.dll"], IndicatorEvidence.Reference, "0123456789abcdef0123456789abcdef01234567", false);
        var facts = hunt.Facts.Select(f => new HuntFact(HuntKind.DllName, f["dll_name:".Length..], IndicatorEvidence.Reference)).ToList();
        var set = RuleProof.Apply(new HuntSet([hunt], []), new ProofOptions(FolderOf(3), MinFiles: 1), (_, _) => new RuleProof.FileRead(false, facts, new HashSet<string>()), default);
        var proof = set.Hunts[0].Proof!;
        Assert.Equal(("drop", null), (proof.Verdict, proof.Removed));
        Assert.Equal(hunt.Id, set.Hunts[0].Id);
    }

    [Fact]
    [FuzzEntry(typeof(HuntRules))]
    public void Fuzzed_saved_hunts_files_never_throw_unexpectedly()
    {
        var seed = HuntRules.Write(Plain("registry_key", "Software_X"));
        var failures = FormatFuzz.Run(seed, b => HuntRules.Read(b), 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    [Fact]
    public void A_saved_hunts_file_is_checked_as_the_queries_it_holds()
    {
        var clean = Folder("clean");
        for (int i = 0; i < 3; i++) Build(clean, "Clean" + i, "shared-pipe-beta");
        var file = Build(Folder("input"), "Subject", "shared-pipe-beta", "unique-pipe-alpha");
        var direct = Prove(file, new ProofOptions(clean, MinFiles: 1));
        var saved = _dir.File("hunts.json");
        File.WriteAllBytes(saved, HuntRules.Write(new HuntSet(direct.Hunts.Select(h => h with { Proof = null }).ToList(), [])));
        var fromJson = Prove(saved, new ProofOptions(clean, MinFiles: 1));
        Assert.Equal(direct.Hunts.Select(h => (h.Id, h.Proof!.Verdict)).Order(), fromJson.Hunts.Select(h => (h.Id, h.Proof!.Verdict)).Order());
        Assert.DoesNotContain(fromJson.Notes, n => n.Contains("PE images only", StringComparison.Ordinal));
        Assert.Equal(direct.Hunts.Count(h => h.HuntingOnly), fromJson.Hunts.Count(h => h.HuntingOnly));
    }

    [Fact]
    public async Task The_tool_reads_a_saved_hunts_file_with_the_view_hunts()
    {
        var clean = Folder("clean");
        for (int i = 0; i < 3; i++) Build(clean, "Clean" + i, "shared-pipe-beta");
        var file = Build(Folder("input"), "Subject", "shared-pipe-beta");
        var tools = new Corvus.Tools.InspectionTools(new InspectionService(_ws), _ws);
        var saved = _dir.File("hunts.json");
        await tools.SummarizeFile(path: file, view: "hunts", huntsPath: saved);
        var text = await tools.SummarizeFile(path: saved, view: "hunts", cleanFolder: clean, minFiles: 1);
        Assert.Contains("drop", text, StringComparison.Ordinal);
        Assert.Contains("is common: 3 clean files carry it", text, StringComparison.Ordinal);
    }

    [Fact]
    public void The_facts_only_read_gives_the_same_hunt_facts_without_the_digest()
    {
        var file = Build(Folder("input"), "Subject", "shared-pipe-beta");
        var inspection = new InspectionService(_ws);
        var full = inspection.Summarize(null, file, default, new FileViewOptions("hunts"));
        var lean = inspection.Summarize(null, file, default, new FileViewOptions("hunts") { FactsOnly = true });
        Assert.NotNull(full.File.Tlsh ?? full.File.TlshAbsent);
        Assert.Null(lean.File.Tlsh);
        Assert.Equal("not computed", lean.File.TlshAbsent);
        Assert.Equal(((HuntSet)full.Views["hunts"].Detail).Facts.Select(f => f.Kind + ":" + f.Value).Order(),
            ((HuntSet)lean.Views["hunts"].Detail).Facts.Select(f => f.Kind + ":" + f.Value).Order());
        Assert.Equal(full.File.Sha1, lean.File.Sha1);
    }

    [Fact]
    public void Extensions_limit_the_files_a_proof_folder_counts()
    {
        var clean = Folder("clean");
        for (int i = 0; i < 3; i++) Build(clean, "Clean" + i, "own-" + i);
        for (int i = 0; i < 4; i++) File.WriteAllText(Path.Combine(clean, "note" + i + ".txt"), "text");
        var file = Build(Folder("input"), "Subject", "lonely-pipe");
        var set = Prove(file, new ProofOptions(clean, MinFiles: 1, Extensions: [".DLL"]));
        Assert.Equal((3, 3), (set.Proof!.Clean.Found, set.Proof.Clean.Read));
    }
}
