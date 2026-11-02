namespace Corvus.Native.Providers;

/// <summary>A session whose engine database can be written to another file, leaving its own in the analysis cache.</summary>
internal interface IEngineDatabase
{
    /// <summary>The session's own database file.</summary>
    string DatabasePath { get; }

    /// <summary>What an export result tells the user to do with the written file.</summary>
    string ExportNote { get; }

    /// <summary>Writes the database, with every edit made so far, to <paramref name="path"/> and returns its size in bytes.</summary>
    Task<long> SaveAsAsync(string path, CancellationToken cancellationToken);
}
