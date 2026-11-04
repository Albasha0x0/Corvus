using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Text.Json;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Live;

namespace Corvus.Tests;

/// <summary>The agent finds a module's exports from its export directory, without a loader call.</summary>
public sealed class LiveAgentExportTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static string AgentSource()
    {
        var text = System.Text.Encoding.UTF8.GetString(EmbeddedScript.Read("Corvus.Native.Providers.Live.live_agent.js"));
        var start = text.IndexOf("function exportAddress(", StringComparison.Ordinal);
        Assert.True(start >= 0, "exportAddress is not in the agent");
        var end = text.IndexOf("\n}\n", start, StringComparison.Ordinal);
        return text[start..(end + 3)];
    }

    /// <summary>Exported names of <paramref name="path"/> with their RVAs; a forwarder's RVA is null.</summary>
    private static Dictionary<string, uint?> FileExports(string path)
    {
        using var stream = File.OpenRead(path);
        using var pe = new PEReader(stream);
        var directory = pe.PEHeaders.PEHeader!.ExportTableDirectory;
        var image = pe.GetEntireImage().GetContent().ToArray();
        uint Rva(uint rva)
        {
            var section = pe.PEHeaders.SectionHeaders.First(h => rva >= h.VirtualAddress && rva < h.VirtualAddress + Math.Max(h.VirtualSize, h.SizeOfRawData));
            return rva - (uint)section.VirtualAddress + (uint)section.PointerToRawData;
        }
        uint U32(uint offset) => BitConverter.ToUInt32(image.AsSpan((int)offset, 4));
        ushort U16(uint offset) => BitConverter.ToUInt16(image.AsSpan((int)offset, 2));
        var table = Rva((uint)directory.RelativeVirtualAddress);
        uint count = U32(table + 24);
        var functions = Rva(U32(table + 28));
        var names = Rva(U32(table + 32));
        var ordinals = Rva(U32(table + 36));
        var result = new Dictionary<string, uint?>();
        for (uint i = 0; i < count; i++)
        {
            var name = System.Text.Encoding.ASCII.GetString(image.AsSpan((int)Rva(U32(names + i * 4)), 256)).Split('\0')[0];
            var target = U32(functions + U16(ordinals + i * 2) * 4u);
            var inside = target >= directory.RelativeVirtualAddress && target < directory.RelativeVirtualAddress + directory.Size;
            result[name] = inside ? null : target;
        }
        return result;
    }

    private const string Driver = """
        import frida, json, sys, os
        dev = frida.get_local_device()
        pid = dev.spawn([os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe"), "/c", "exit"])
        try:
            session = dev.attach(pid)
            source = open(sys.argv[1], encoding="utf-8").read() + "\nrpc.exports = { run(names) { const m = Process.getModuleByName(names.shift()); return { base: m.base.toString(), found: names.map(n => { const a = exportAddress(m, n); return a === null ? null : a.toString(); }) }; } };"
            script = session.create_script(source)
            script.load()
            names = [sys.argv[3]] + json.load(open(sys.argv[2]))
            print(json.dumps(script.exports_sync.run(names)))
        finally:
            dev.kill(pid)
        """;

    // Regression for e874ead66: the JIT export lookup entered the loader.
    [LiveTargetFact("win-x64", attaches: true)]
    public void A_loaded_modules_exports_match_its_file_and_a_forwarded_or_absent_name_is_null()
    {
        var module = Path.Combine(Environment.SystemDirectory, "kernel32.dll");
        var expected = FileExports(module);
        var plain = expected.Where(e => e.Value is not null).Select(e => e.Key).Order(StringComparer.Ordinal).Take(300);
        var forwarded = expected.Where(e => e.Value is null).Select(e => e.Key).Order(StringComparer.Ordinal).Take(20).ToArray();
        Assert.NotEmpty(forwarded);
        var sample = plain.Concat(forwarded).Append("NoSuchExport").ToArray();
        File.WriteAllText(_dir.File("agent_export.js"), AgentSource());
        File.WriteAllText(_dir.File("names.json"), JsonSerializer.Serialize(sample));
        File.WriteAllText(_dir.File("driver.py"), Driver);
        var python = new FridaBackend().Python!.Executable;
        var psi = new ProcessStartInfo(python) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        // Frida unpacks into TEMP: a folder of the test's own is deleted with it.
        psi.Environment["TEMP"] = psi.Environment["TMP"] = Directory.CreateDirectory(_dir.File("frida-temp")).FullName;
        foreach (var a in new[] { "-I", _dir.File("driver.py"), _dir.File("agent_export.js"), _dir.File("names.json"), "kernel32.dll" }) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var error = p.StandardError.ReadToEndAsync();
        var output = p.StandardOutput.ReadToEnd();
        Assert.True(p.WaitForExit(60_000), "the driver did not end");
        Assert.True(p.ExitCode == 0, error.Result);
        using var reply = JsonDocument.Parse(output);
        var baseAddress = Convert.ToUInt64(reply.RootElement.GetProperty("base").GetString(), 16);
        var found = reply.RootElement.GetProperty("found").EnumerateArray().Select(e => e.GetString()).ToArray();
        Assert.Equal(sample.Length, found.Length);
        for (int i = 0; i < sample.Length - 1; i++)
        {
            if (expected[sample[i]] is { } rva) Assert.Equal(baseAddress + rva, Convert.ToUInt64(found[i], 16));
            else Assert.Null(found[i]);
        }
        Assert.Null(found[^1]);
    }
}
