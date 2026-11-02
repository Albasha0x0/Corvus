namespace Corvus.Native.Dump;

/// <summary>A module image written from a dump: its file name, address, size, SHA-256 and the share of its pages the dump held.</summary>
/// <param name="Metadata">The metadata state of a .NET image (readable, partial or unreadable); omitted for a native image.</param>
/// <param name="MetadataReason">Why the metadata is not readable; omitted when it is readable.</param>
public sealed record ExportedModule(string File, string Base, uint Size, string Sha256, int CapturedPercent,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? Metadata = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? MetadataReason = null);

/// <summary>A module left out of the export, with the reason.</summary>
public sealed record SkippedModule(string Name, string Base, string Reason);

/// <summary>The images written to a folder and the modules left out.</summary>
public sealed record ModuleExport(string Folder, IReadOnlyList<ExportedModule> Written, IReadOnlyList<SkippedModule> Skipped);
