using System.Diagnostics;
using System.Runtime.InteropServices;
using Corvus.Core;
using Corvus.Core.Protobuf;
using Corvus.Native.Providers;
using Corvus.Services.Analysis;
using Corvus.Services.Analysis.Endpoints;
using Microsoft.CodeAnalysis;

namespace Corvus.Tests;

/// <summary>
/// Real descriptors and clients: Google.Protobuf's base64 descriptors and protoc's own raw ones round-trip through protoc
/// (CORVUS_PROTO_COMPILER, else the Grpc.Tools package's protoc); a generated gRPC client and a Refit interface by member.
/// </summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
public sealed class ProtobufRealTests : IDisposable
{
    private const string GrpcTools = "2.84.0";
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _ws = new();
    public void Dispose() { _ws.Dispose(); _dir.Dispose(); }

    private static string Protoc()
    {
        if (ExternalTools.Locate(ExternalTools.ProtoCompiler) is { } configured) return configured.Path;
        var (folder, name) = (OperatingSystem.IsWindows(), OperatingSystem.IsMacOS(), RuntimeInformation.OSArchitecture) switch
        {
            (true, _, _) => ("windows_x64", "protoc.exe"),
            (_, true, _) => ("macosx_universal", "protoc"),
            (_, _, Architecture.Arm64) => ("linux_arm64", "protoc"),
            _ => ("linux_x64", "protoc"),
        };
        var path = RealPackages.File("Grpc.Tools", GrpcTools, "tools", folder, name);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, File.GetUnixFileMode(path) | UnixFileMode.UserExecute);
        return path;
    }

    private static List<FoundDescriptor> Descriptors(string file) =>
        [.. ApiSurface.Read([new ContainerItem(Path.GetFileName(file), Blob.Identify(File.ReadAllBytes(file)), "file", File.ReadAllBytes(file))], default).Descriptors];

    /// <summary>Each descriptor's .proto text, compiled by protoc and read back, gives the same text; returns the files checked.</summary>
    private int RoundTrip(IReadOnlyList<FoundDescriptor> found)
    {
        var protoc = Protoc();
        var root = Path.Combine(_dir.Path, Guid.NewGuid().ToString("N"));
        var texts = found.DistinctBy(d => d.File.Name).ToDictionary(d => d.File.Name, d => ProtoText.Write(d.File));
        foreach (var (name, text) in texts)
        {
            var path = Path.Combine(root, name);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, text);
        }
        foreach (var (name, text) in texts)
        {
            var output = Path.Combine(root, Guid.NewGuid().ToString("N") + ".pb");
            var psi = new ProcessStartInfo(protoc);
            foreach (var a in ExternalTools.Arguments(ExternalTools.ProtoCompiler, "descriptor-set", ("root", root), ("out", output), ("file", name))) psi.ArgumentList.Add(a);
            var (code, log) = Tools.Run(psi, 60_000);
            Assert.True(code == 0, $"protoc rejected {name}:\n{log}\n{text}");
            var set = File.ReadAllBytes(output);
            // FileDescriptorSet: field 1, length-delimited, once (no --include_imports)
            Assert.Equal(0x0A, set[0]);
            int at = 1, length = 0, shift = 0;
            byte b;
            do { b = set[at++]; length |= (b & 0x7F) << shift; shift += 7; } while ((b & 0x80) != 0);
            var again = ProtoFile.Read(set.AsSpan(at, length));
            Assert.NotNull(again);
            // the header comment counts custom options, which protoc drops without their extension definitions
            static string Body(string t) => string.Join("\n", t.Split('\n').Where(l => !l.StartsWith("// ", StringComparison.Ordinal)));
            Assert.Equal(Body(text), Body(ProtoText.Write(again)));
        }
        return texts.Count;
    }

    [Fact]
    public void Csharp_descriptors_of_google_protobuf_round_trip_through_protoc()
    {
        var found = Descriptors(RealPackages.Lib("Google.Protobuf", "3.36.2", "net8.0", "Google.Protobuf.dll"));
        Assert.Contains(found, d => d.File.Name == "google/protobuf/descriptor.proto" && d.Encoding == "base64 string");
        Assert.Contains(found, d => d.File.Name == "google/protobuf/struct.proto");
        Assert.Equal(15, RoundTrip(found));
    }

    [Fact]
    public void Native_descriptors_in_protoc_itself_round_trip_through_protoc()
    {
        var found = Descriptors(Protoc());
        Assert.Contains(found, d => d.File.Name == "google/protobuf/descriptor.proto" && d.Encoding == "raw bytes");
        Assert.Contains(found, d => d.File.Name == "google/protobuf/compiler/plugin.proto");
        Assert.True(RoundTrip(found) >= 4); // descriptor, plugin, cpp and java features
    }

    [Fact]
    public void Generated_grpc_client_methods_and_their_descriptor_service_are_endpoints()
    {
        var path = RealPackages.Lib("Grpc.HealthCheck", "2.84.0", "net8.0", "Grpc.HealthCheck.dll");
        var rows = new UnpackService(_ws).Search(path, "Health", "endpoint", 100, AnalysisLimits.Default, default).Items
            .Select(m => $"{m.Name} | {m.Detail} | {m.Member}").ToList();
        Assert.True(rows.Contains("POST /grpc.health.v1.Health/Check | grpc | Grpc.Health.V1.Health::.cctor()"), string.Join("\n", rows));
        Assert.True(rows.Contains("POST /grpc.health.v1.Health/Watch | proto | health.proto service Health"), string.Join("\n", rows));
    }

    [Fact]
    public void Refit_interfaces_compiled_against_the_real_package_are_endpoints()
    {
        var refit = RealPackages.Lib("Refit", "10.0.1", "net10.0", "Refit.dll");
        var bytes = Roslyn.Compile("RefitApp", """
            using System.Threading.Tasks;
            using Refit;
            namespace App
            {
                public interface IRepos
                {
                    [Get("/repos/{owner}/{repo}")] Task<string> Repo(string owner, string repo);
                    [Get("/search/repositories")] Task<string> Search([AliasAs("q")] string query, int page);
                    [Delete("/repos/{owner}/{repo}")] Task Remove(string owner, string repo, [Header("Authorization")] string token);
                }
                public static class Client { public static IRepos Create() => RestService.For<IRepos>("https://api.github.com"); }
            }
            """, new(OutputKind.DynamicallyLinkedLibrary), [MetadataReference.CreateFromFile(refit)]);
        var path = _dir.File("RefitApp.dll");
        File.WriteAllBytes(path, bytes);
        var rows = new UnpackService(_ws).Search(path, "*", "endpoint", 100, AnalysisLimits.Default, default).Items.Select(m => $"{m.Name} | {m.Member}").ToList();
        Assert.Contains("GET https://api.github.com/repos/{owner}/{repo} | App.IRepos::Repo(string, string)", rows);
        Assert.Contains("GET https://api.github.com/search/repositories?page=…&q=… | App.IRepos::Search(string, int)", rows);
        Assert.Contains("DELETE https://api.github.com/repos/{owner}/{repo} | App.IRepos::Remove(string, string, string)", rows);
    }
}
