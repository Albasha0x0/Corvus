namespace Corvus.Core.Installers;

/// <summary>A script command at its entry index: a program it starts or a DLL function it calls.</summary>
internal sealed record InstallerCommand(int Index, string Kind, string Text);

/// <summary>A registry value a script writes, at its entry index; <c>Value</c> is null when the data is binary.</summary>
internal sealed record InstallerRegistryWrite(int Index, string Kind, string Key, string? Name, string? Value);

/// <summary>
/// The commands an installer's script runs; <c>Unknown</c> names why they could not be read, and then
/// <c>Commands</c> and <c>Registry</c> are empty. <c>CompiledCode</c> is null when the format has no such field.
/// </summary>
internal sealed record InstallerScript(string Builder, IReadOnlyList<InstallerCommand> Commands, IReadOnlyList<InstallerRegistryWrite> Registry, bool? CompiledCode, string? Unknown)
{
    /// <summary>A script whose commands could not be read, for the reason given.</summary>
    public static InstallerScript Undecoded(string builder, string reason, bool? compiledCode = null) => new(builder, [], [], compiledCode, reason);
}
