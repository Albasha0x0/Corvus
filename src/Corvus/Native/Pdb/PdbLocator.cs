using Corvus.Core;
using Corvus.Native.Pe;

namespace Corvus.Native.Pdb;

/// <summary>One place looked at while locating a PDB, and what was there.</summary>
public sealed record PdbProbe(string Location, string Outcome);

/// <summary>Outcome of <see cref="PdbLocator.Locate"/>: the matching PDB (or null) and every place looked at.</summary>
public sealed record PdbLocation(string? Path, IReadOnlyList<PdbProbe> Probes, IReadOnlyList<string> Servers);

/// <summary>Finds an image's PDB by RSDS GUID and age in local paths and _NT_SYMBOL_PATH stores, without network access; a mismatch is reported, never used. <see cref="DownloadAsync"/> runs only on request.</summary>
public static class PdbLocator
{
    public const string DefaultServer = "https://msdl.microsoft.com/download/symbols";
    /// <summary>Overrides the download cache directory.</summary>
    public const string CacheVariable = "CORVUS_SYMBOL_CACHE";
    public const long DefaultMaxDownloadBytes = 2L << 30;

    public static string DownloadCache =>
        Providers.ExternalTools.ReadVariable(CacheVariable) is { Length: > 0 } custom
            ? custom
            : Providers.DataFolder.Combine("symbols");

    /// <summary>The symbol store key: GUID (32 upper-case hex digits) followed by the age in hex.</summary>
    public static string StoreKey(PeCodeView cv) => cv.Guid.ToString("N").ToUpperInvariant() + cv.Age.ToString("X");

    /// <summary>The PDB file name from the CodeView path (either slash), or null when it has none.</summary>
    public static string? PdbFileName(PeCodeView cv)
    {
        var p = cv.PdbPath.Replace('/', '\\');
        int slash = p.LastIndexOf('\\');
        var name = slash >= 0 ? p[(slash + 1)..] : p;
        return name.Length == 0 || name.IndexOfAny(System.IO.Path.GetInvalidFileNameChars()) >= 0 ? null : name;
    }

    /// <summary>Local symbol directories and stores in search order; <paramref name="servers"/> receives the symbol path's http(s) servers.</summary>
    public static List<string> LocalStores(List<string> servers, string? symbolPath = null)
    {
        var stores = new List<string>();
        var paths = symbolPath != null ? [symbolPath]
            : new[] { Providers.ExternalTools.ReadVariable("_NT_SYMBOL_PATH"), Providers.ExternalTools.ReadVariable("_NT_ALT_SYMBOL_PATH") };
        foreach (var path in paths)
            if (path != null) ParseSymbolPath(path, stores, servers);
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var temp = System.IO.Path.GetTempPath();
        string?[] defaults =
        [
            local.Length > 0 ? System.IO.Path.Combine(local, "Temp", "SymbolCache") : null, // Visual Studio
            System.IO.Path.Combine(temp, "SymbolCache"),
            OperatingSystem.IsWindows() ? @"C:\ProgramData\dbg\sym" : null, // WinDbg
            OperatingSystem.IsWindows() ? @"C:\symbols" : null,
            OperatingSystem.IsWindows() ? @"C:\SymCache" : null,
            System.IO.Path.Combine(temp, "ida"),
            DownloadCache,
        ];
        foreach (var d in defaults)
            if (d != null && Directory.Exists(d)) AddDistinct(stores, d);
        return stores;
    }

    /// <summary>The symbol servers a download may use: the http(s) servers of _NT_SYMBOL_PATH and _NT_ALT_SYMBOL_PATH, then <see cref="DefaultServer"/>.</summary>
    public static List<string> ConfiguredServers()
    {
        var servers = new List<string>();
        foreach (var path in new[] { Providers.ExternalTools.ReadVariable("_NT_SYMBOL_PATH"), Providers.ExternalTools.ReadVariable("_NT_ALT_SYMBOL_PATH") })
            if (path != null) ParseSymbolPath(path, [], servers);
        AddDistinct(servers, DefaultServer);
        return servers;
    }

    /// <summary>Throws invalid_argument unless <paramref name="server"/> is one of <paramref name="configured"/>, before any connection; <paramref name="setting"/> names where servers are configured.</summary>
    public static void RequireConfigured(string server, IReadOnlyList<string> configured, string setting)
    {
        var wanted = server.Trim().TrimEnd('/');
        if (configured.Any(c => string.Equals(c.TrimEnd('/'), wanted, StringComparison.OrdinalIgnoreCase))) return;
        throw new ToolError(ErrorCode.InvalidArgument,
            $"server '{wanted}' is not a configured symbol server; configured: {(configured.Count > 0 ? string.Join(", ", configured) : "none")}.",
            $"add it to {setting}, or omit server") { Details = new { server = wanted, configured } };
    }

    /// <summary>Splits a symbol path ("srv*C:\cache*https://server;C:\dir;cache*C:\c2") into local directories and servers.</summary>
    public static void ParseSymbolPath(string symbolPath, List<string> stores, List<string> servers)
    {
        foreach (var raw in symbolPath.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = raw.Split('*', StringSplitOptions.TrimEntries);
            string head = parts[0].ToLowerInvariant();
            bool tagged = parts.Length > 1 && head is "srv" or "symsrv" or "cache";
            foreach (var (part, i) in parts.Select((p, i) => (p, i)))
            {
                if (part.Length == 0 || (tagged && i == 0)) continue;
                if (part.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) continue; // symsrv*symsrv.dll*...
                if (part.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || part.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                    AddDistinct(servers, part.TrimEnd('/'));
                else if (IsUsablePath(part)) AddDistinct(stores, Environment.ExpandEnvironmentVariables(part));
            }
        }
    }

    private static bool IsUsablePath(string p) => p.IndexOfAny(System.IO.Path.GetInvalidPathChars()) < 0 && !p.Contains("://");

    private static void AddDistinct(List<string> list, string item)
    {
        if (!list.Contains(item, StringComparer.OrdinalIgnoreCase)) list.Add(item);
    }

    /// <summary>Looks for the image's PDB locally, <paramref name="explicitPath"/> first; no network.</summary>
    public static PdbLocation Locate(PeFile image, string? explicitPath = null, string? symbolPath = null)
    {
        var probes = new List<PdbProbe>();
        var servers = new List<string>();
        var cv = image.CodeView;
        string? name = cv != null ? PdbFileName(cv) : null;
        string imageDir = System.IO.Path.GetDirectoryName(image.Path) ?? "";
        string fallbackName = System.IO.Path.GetFileNameWithoutExtension(image.Path) + ".pdb";

        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            if (Directory.Exists(explicitPath))
            {
                if (name != null) candidates.Add(System.IO.Path.Combine(explicitPath, name));
                candidates.Add(System.IO.Path.Combine(explicitPath, fallbackName));
                if (name != null && cv != null) candidates.Add(System.IO.Path.Combine(explicitPath, name, StoreKey(cv), name));
            }
            else candidates.Add(explicitPath);
        }
        if (cv == null || cv.Format != "RSDS")
        {
            // Without a GUID only an explicit file can be used, unverified.
            if (candidates.Count > 0 && File.Exists(candidates[0]) && !Directory.Exists(explicitPath))
                return new PdbLocation(candidates[0], [new PdbProbe(candidates[0], cv == null ? "used unverified: the image has no CodeView record" : "used unverified: the image has a PDB 2.0 (NB10) record")], servers);
            probes.Add(new PdbProbe(image.Path, cv == null ? "the image has no CodeView debug record: it names no PDB" : "the image has a PDB 2.0 (NB10) record; only PDB 7.0 (RSDS) is matched"));
            return new PdbLocation(null, probes, servers);
        }

        if (imageDir.Length > 0)
        {
            if (name != null) candidates.Add(System.IO.Path.Combine(imageDir, name));
            candidates.Add(System.IO.Path.Combine(imageDir, fallbackName));
        }
        if (cv.PdbPath.Length > 0 && IsUsablePath(cv.PdbPath) && System.IO.Path.IsPathFullyQualified(cv.PdbPath))
        {
            if (InputFiles.NamedProblem(cv.PdbPath) is { } refused) probes.Add(new PdbProbe(cv.PdbPath, refused));
            else candidates.Add(cv.PdbPath);
        }
        if (name != null)
        {
            string key = StoreKey(cv);
            foreach (var store in LocalStores(servers, symbolPath))
            {
                candidates.Add(System.IO.Path.Combine(store, name, key, name));
                if (File.Exists(System.IO.Path.Combine(store, "index2.txt")) && name.Length >= 2)
                    candidates.Add(System.IO.Path.Combine(store, name[..2], name, key, name));
                candidates.Add(System.IO.Path.Combine(store, name));
            }
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in candidates)
        {
            string full;
            try { full = System.IO.Path.GetFullPath(c); }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { continue; }
            if (!seen.Add(full)) continue;
            if (!File.Exists(full)) { probes.Add(new PdbProbe(full, "not found")); continue; }
            var outcome = Check(full, cv);
            probes.Add(new PdbProbe(full, outcome ?? "match"));
            if (outcome == null) return new PdbLocation(full, probes, servers);
        }
        return new PdbLocation(null, probes, servers);
    }

    /// <summary>Null when <paramref name="path"/> is the PDB of <paramref name="cv"/>; else why not.</summary>
    public static string? Check(string path, PeCodeView cv)
    {
        try
        {
            var (guid, infoAge, dbiAge) = PdbFile.ReadIdentity(path);
            uint age = dbiAge != 0 ? dbiAge : infoAge;
            if (guid != cv.Guid) return $"different build (GUID {guid:D}, image wants {cv.Guid:D})";
            if (age != cv.Age) return $"different age ({age}, image wants {cv.Age})";
            return null;
        }
        catch (ToolError e) { return "unreadable: " + e.Message; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return "unreadable: " + ex.Message; }
    }

    /// <summary>Downloads the PDB from <paramref name="server"/> to a temporary file, verifies GUID and age, then moves it into the cache; a mismatching or oversized file is deleted. Returns the cached path.</summary>
    public static async Task<string> DownloadAsync(PeCodeView cv, string server, TimeSpan timeout, long maxBytes, HttpMessageHandler? handler = null, string? cache = null,
        CancellationToken ct = default)
    {
        if (cv.Format != "RSDS" || PdbFileName(cv) is not { } name)
            throw new ToolError(ErrorCode.Unsupported, "The image has no PDB 7.0 (RSDS) CodeView record with a file name; there is nothing to download.");
        var baseUri = ServerUri(server);
        return await Fetch(baseUri, name, StoreKey(cv), "PDB", path => Check(path, cv), timeout, maxBytes, handler, cache, ct).ConfigureAwait(false);
    }

    /// <summary>The symbol store key of a PE image: TimeDateStamp (8 hex digits) followed by SizeOfImage in hex.</summary>
    public static string ImageKey(uint timeDateStamp, uint sizeOfImage) => $"{timeDateStamp:X8}{sizeOfImage:x}";

    /// <summary>Downloads a PE image stored under <paramref name="key"/> into the cache, accepted by <paramref name="check"/> (default: any PE file); returns the cached path.</summary>
    public static Task<string> DownloadImageAsync(string fileName, string key, Func<string, string?>? check, string server, TimeSpan timeout, long maxBytes,
        HttpMessageHandler? handler = null, string? cache = null, CancellationToken ct = default)
    {
        if (fileName.Length == 0 || fileName.IndexOfAny(System.IO.Path.GetInvalidFileNameChars()) >= 0)
            throw new ToolError(ErrorCode.InvalidArgument, $"'{fileName}' is not a file name.");
        return Fetch(ServerUri(server), fileName, key, "image", check ?? IsPe, timeout, maxBytes, handler, cache, ct);
    }

    private static Uri ServerUri(string server) =>
        Uri.TryCreate(server.TrimEnd('/') + "/", UriKind.Absolute, out var baseUri)
        && (baseUri.Scheme == Uri.UriSchemeHttps || (baseUri.Scheme == Uri.UriSchemeHttp && NetworkPolicy.PlainHttpAllowed(baseUri))) ? baseUri
            : throw new ToolError(ErrorCode.InvalidArgument, $"'{server}' is not an https symbol server URL.",
                $"for example {DefaultServer}; an http server must be listed in {NetworkPolicy.HttpServersVariable}");

    /// <summary>
    /// The servers a symbol download from <paramref name="baseUri"/> may request;
    /// a server of the symbol path is configured, so it may be private.
    /// </summary>
    private static NetworkServers ServersOf(Uri baseUri)
    {
        var servers = new List<string>();
        foreach (var path in new[] { Providers.ExternalTools.ReadVariable("_NT_SYMBOL_PATH"), Providers.ExternalTools.ReadVariable("_NT_ALT_SYMBOL_PATH") })
            if (path != null) ParseSymbolPath(path, [], servers);
        bool configured = servers.Any(s => Uri.TryCreate(s, UriKind.Absolute, out var u) && string.Equals(u.Authority, baseUri.Authority, StringComparison.OrdinalIgnoreCase));
        // Microsoft's server answers with a redirect to its blob storage.
        var redirects = string.Equals(baseUri.Authority, new Uri(DefaultServer).Authority, StringComparison.OrdinalIgnoreCase) ? ["*.blob.core.windows.net"] : Array.Empty<string>();
        return new NetworkServers([baseUri.ToString()], configured, redirects);
    }

    private static string? IsPe(string path)
    {
        try { PeFile.Open(path); return null; }
        catch (ToolError e) { return "not a PE image: " + e.Message; }
    }

    /// <summary>Null when the PE at <paramref name="path"/> has this TimeDateStamp and SizeOfImage; else why not.</summary>
    public static string? CheckImage(string path, uint timeDateStamp, uint sizeOfImage)
    {
        try
        {
            var pe = PeFile.Open(path);
            if (pe.Coff.TimeDateStamp != timeDateStamp || pe.SizeOfImage != sizeOfImage)
                return $"different build (timestamp 0x{pe.Coff.TimeDateStamp:X8}, size 0x{pe.SizeOfImage:X}; wanted 0x{timeDateStamp:X8}, 0x{sizeOfImage:X})";
            return null;
        }
        catch (ToolError e) { return "unreadable: " + e.Message; }
    }

    /// <summary>Downloads <c>name/key/name</c> from a symbol server into the cache; a temporary file first, a failing <paramref name="check"/> deletes it.</summary>
    private static async Task<string> Fetch(Uri baseUri, string name, string key, string what, Func<string, string?> check, TimeSpan timeout, long maxBytes,
        HttpMessageHandler? handler, string? cache, CancellationToken ct)
    {
        var target = System.IO.Path.Combine(cache ?? DownloadCache, name, key, name);
        var url = new Uri(baseUri, $"{Uri.EscapeDataString(name)}/{key}/{Uri.EscapeDataString(name)}");
        return await FetchUrl(url, target, what, check, timeout, maxBytes, ServersOf(baseUri), handler, ct).ConfigureAwait(false);
    }

    /// <summary>Downloads <paramref name="url"/> to <paramref name="target"/> (kept when already there and accepted); a temporary file first, a failing <paramref name="check"/> deletes it.</summary>
    internal static async Task<string> FetchUrl(Uri url, string target, string what, Func<string, string?> check, TimeSpan timeout, long maxBytes,
        NetworkServers servers, HttpMessageHandler? handler, CancellationToken ct)
    {
        if (File.Exists(target) && check(target) == null) return target;
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(target)!);
        var temp = target + $".{Environment.ProcessId}.{Guid.NewGuid():N}.part";
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeout);
        try
        {
            using var http = NetworkPolicy.Client(servers, Timeout.InfiniteTimeSpan, handler, "Microsoft-Symbol-Server/10.0.0.0");
            using var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, timeoutCts.Token).ConfigureAwait(false);
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                throw new ToolError(ErrorCode.NotFound, $"{url} does not have this {what} (404).", "the build may not be on that server; try another server or a local path");
            if (!response.IsSuccessStatusCode)
                throw new ToolError(ErrorCode.ProviderUnavailable, $"{url} answered {(int)response.StatusCode} {response.ReasonPhrase}.");
            if (response.Content.Headers.ContentLength is { } declared && declared > maxBytes)
                throw new ToolError(ErrorCode.LimitExceeded, $"{url} is {declared} bytes; the download limit is {maxBytes} bytes.");
            await using (var body = await response.Content.ReadAsStreamAsync(timeoutCts.Token).ConfigureAwait(false))
            await using (var file = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 16, useAsync: true))
            {
                var buffer = new byte[1 << 16];
                long total = 0;
                int n;
                while ((n = await body.ReadAsync(buffer, timeoutCts.Token).ConfigureAwait(false)) > 0)
                {
                    total += n;
                    if (total > maxBytes)
                        throw new ToolError(ErrorCode.LimitExceeded, $"{url} is larger than the download limit of {maxBytes} bytes.");
                    await file.WriteAsync(buffer.AsMemory(0, n), timeoutCts.Token).ConfigureAwait(false);
                }
            }
            if (check(temp) is { } why)
                throw new ToolError(ErrorCode.MalformedInput, $"The file downloaded from {url} is not the expected {what}: {why}.");
            File.Move(temp, target, overwrite: true);
            return target;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new ToolError(ErrorCode.Timeout, $"Downloading {url} took longer than {timeout.TotalSeconds:0} s.");
        }
        catch (HttpRequestException ex) when (NetworkPolicy.Refusal(ex) is { } refused)
        {
            throw new ToolError(ErrorCode.AccessDenied, $"Downloading {url} refused: {refused.Message}",
                "set the server in the symbol path or the debuginfod URLs, over https; unset CORVUS_OFFLINE to download");
        }
        catch (HttpRequestException ex)
        {
            throw new ToolError(ErrorCode.ProviderUnavailable, $"Downloading {url} failed: {ex.Message}");
        }
        catch (IOException ex)
        {
            throw new ToolError(ErrorCode.IoError, $"Writing {target} failed: {ex.Message}");
        }
        finally
        {
            try { if (File.Exists(temp)) File.Delete(temp); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }
}
