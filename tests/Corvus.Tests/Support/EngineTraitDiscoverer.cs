using Xunit.Abstractions;
using Xunit.Sdk;

namespace Corvus.Tests;

/// <summary>
/// Gives each <see cref="IdaFactAttribute"/> test the trait Engine=ida and each <see cref="GhidraFactAttribute"/> test
/// Engine=ghidra, so a filter can split a class that uses both engines (test-remote.psm1).
/// </summary>
public sealed class EngineTraitDiscoverer : ITraitDiscoverer
{
    public const string TypeName = "Corvus.Tests.EngineTraitDiscoverer";
    public const string AssemblyName = "Corvus.Tests";

    public IEnumerable<KeyValuePair<string, string>> GetTraits(IAttributeInfo traitAttribute) =>
        [new("Engine", traitAttribute is IReflectionAttributeInfo { Attribute: GhidraFactAttribute } ? "ghidra" : "ida")];
}
