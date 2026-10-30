using Corvus.Core;

namespace Corvus.Services.Web.Scripts;

/// <summary>Types embedded text with <see cref="ScriptReader.Detect"/>.</summary>
internal sealed class ScriptSniffer : IScriptSniffer
{
    public string? Language(string text) => ScriptReader.Detect("embedded.txt", text);
}
