using System.Security.Cryptography;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Native.Providers;

/// <summary>
/// Per-user directory where providers keep a private copy of each input and their analysis databases, keyed by the
/// input's SHA-256: <c>root/provider/sha256/input/name</c> plus the provider's database files beside it. Engines
/// never write next to the user's file, and a later open of the same bytes finds the saved database.
/// </summary>
public sealed class AnalysisCache(string root)
{
    public const string RootVariable = "NDM_ANALYSIS_CACHE";

    public string Root { get; } = Path.GetFullPath(root);

    public static string DefaultRoot =>
        Environment.GetEnvironmentVariable(RootVariable) is { Length: > 0 } custom
            ? custom
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.Create), "NetDecompilerMcp", "analysis");

    /// <summary>
    /// Locks the entry for <paramref name="imagePath"/>'s bytes and makes sure its private copy exists and hashes to
    /// <paramref name="expectedSha256"/> (the source's hash when null). Throws NotFound, IoError, InvalidArgument or
    /// Conflict (bytes differ from the expected hash, or the entry is open in another session or process).
    /// </summary>
    public CacheEntry Acquire(string providerId, string imagePath, string? expectedSha256)
    {
        var source = Path.GetFullPath(imagePath);
        if (!File.Exists(source))
            throw new ToolError(ErrorCode.NotFound, $"{imagePath} does not exist.");
        string sha;
        if (expectedSha256 != null)
        {
            sha = expectedSha256.Trim().ToLowerInvariant();
            if (sha.Length != 64 || !sha.All(Uri.IsHexDigit))
                throw new ToolError(ErrorCode.InvalidArgument, $"'{expectedSha256}' is not a SHA-256 (64 hex digits).");
        }
        else sha = Io(source, () => HashFile(source));

        var dir = Path.Combine(Root, providerId, sha);
        Io(dir, () => Directory.CreateDirectory(Path.Combine(dir, "input")));
        var lockFile = OpenLock(dir);
        try
        {
            var copy = Io(dir, () => EnsureCopy(source, Path.Combine(dir, "input"), sha));
            return new CacheEntry(dir, copy, sha, source, lockFile);
        }
        catch
        {
            lockFile.Dispose();
            throw;
        }
    }

    public static string HashFile(string path)
    {
        using var s = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan);
        return Convert.ToHexStringLower(SHA256.HashData(s));
    }

    private static FileStream OpenLock(string dir)
    {
        var path = Path.Combine(dir, ".lock");
        try
        {
            return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.DeleteOnClose);
        }
        catch (IOException ex) when (ex is not FileNotFoundException and not DirectoryNotFoundException
            && (!OperatingSystem.IsWindows() || (ex.HResult & 0xFFFF) is 32 or 33)) // sharing / lock violation
        {
            throw new ToolError(ErrorCode.Conflict, $"The analysis database in {dir} is open in another session or process.",
                "Close the other session (or the other server process) first, or work in that session.");
        }
    }

    private static string EnsureCopy(string source, string inputDir, string sha)
    {
        var existing = Directory.GetFiles(inputDir).Where(f => !f.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase)).ToList();
        foreach (var f in existing)
        {
            if (HashFile(f) == sha) return f;
            File.Delete(f); // damaged or replaced copy
        }
        foreach (var stale in Directory.GetFiles(inputDir, "*.tmp")) File.Delete(stale);

        var name = SafeName(Path.GetFileName(source));
        var target = Path.Combine(inputDir, name);
        var temp = target + "." + Guid.NewGuid().ToString("N")[..8] + ".tmp";
        string copied;
        using (var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan))
        using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 16))
        using (var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
        {
            var buffer = new byte[1 << 16];
            int n;
            while ((n = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                hash.AppendData(buffer, 0, n);
                output.Write(buffer, 0, n);
            }
            output.Flush(flushToDisk: true);
            copied = Convert.ToHexStringLower(hash.GetHashAndReset());
        }
        if (copied != sha)
        {
            File.Delete(temp);
            throw new ToolError(ErrorCode.Conflict, $"{source} has SHA-256 {copied}, not the expected {sha}: the file changed since it was loaded.",
                "Reload the file and open it again.");
        }
        File.Move(temp, target, overwrite: true);
        // Read back what landed on disk.
        if (HashFile(target) != sha)
        {
            File.Delete(target);
            throw new ToolError(ErrorCode.IoError, $"The private copy of {source} in {inputDir} does not match the source after writing.", "Check the disk and retry.");
        }
        return target;
    }

    private static string SafeName(string name)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var clean = new string(name.Select(c => invalid.Contains(c) || c < ' ' ? '_' : c).ToArray()).Trim(' ', '.');
        return clean.Length == 0 ? "input.bin" : clean.Length > 100 ? clean[..100] : clean;
    }

    private static T Io<T>(string path, Func<T> action)
    {
        try { return action(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new ToolError(ErrorCode.IoError, $"I/O error on {path}: {ex.Message}", "Check that the path is readable and the cache directory is writable (NDM_ANALYSIS_CACHE selects another).");
        }
    }
}

/// <summary>A locked cache entry; disposing releases the lock.</summary>
public sealed class CacheEntry(string directory, string inputCopy, string sha256, string source, FileStream lockFile) : IDisposable
{
    public string Directory { get; } = directory;
    /// <summary>The verified private copy of the input.</summary>
    public string InputCopy { get; } = inputCopy;
    public string Sha256 { get; } = sha256;
    public string SourcePath { get; } = source;

    public void Dispose() => lockFile.Dispose();
}
