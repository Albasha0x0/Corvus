using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Services.Analysis;

namespace Corvus.Tools;

/// <summary>Moves what a sandboxed worker extracted into the folder the call named, so only the server writes to a user folder.</summary>
internal static class StagedExtraction
{
    /// <summary>A new folder under the low-labelled scratch folder, for the worker to extract into.</summary>
    internal static string NewStaging() => Path.Combine(WindowsSandbox.Scratch(), "extract-" + Guid.NewGuid().ToString("N"));

    /// <summary>Moves the files of <paramref name="staging"/> into <paramref name="target"/> and returns the extraction with its paths there; a non-empty target that is not an earlier extract of the same file is refused.</summary>
    internal static UnpackService.Extraction Place(UnpackService.Extraction extraction, string staging, string target)
    {
        try
        {
            var root = SafeFile.Output(target);
            var staged = Path.Combine(staging, UnpackService.Marker);
            if (Directory.Exists(root) && Directory.EnumerateFileSystemEntries(root).Any()
                && !(File.Exists(staged) && File.Exists(Path.Combine(root, UnpackService.Marker)) && File.ReadAllText(staged) == File.ReadAllText(Path.Combine(root, UnpackService.Marker))))
                throw new ToolError(ErrorCode.Conflict,
                    $"Output directory {root} is not empty and is not an earlier unpack of this file by this data folder. Choose an empty or new directory.");
            Directory.CreateDirectory(root);
            // The worker is untrusted: a link in staging must not make the server move files from elsewhere.
            var options = new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = FileAttributes.ReparsePoint };
            foreach (var file in Directory.EnumerateFiles(staging, "*", options))
            {
                var destination = SafeFile.OutputUnderRoot(root, Path.GetRelativePath(staging, file));
                SafeFile.MoveToOutput(file, destination, overwrite: true);
            }
            string Moved(string text) => text.Replace(staging, root, StringComparison.OrdinalIgnoreCase);
            return extraction with
            {
                OutputDirectory = root,
                Files = [.. extraction.Files.Select(f => f with { Path = Moved(f.Path) })],
                Notes = [.. extraction.Notes.Select(Moved)],
            };
        }
        finally { try { Directory.Delete(staging, recursive: true); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { } }
    }
}
