namespace Corvus.Tests;

/// <summary>
/// Tests that build MCP tool registrations in this process run one at a time: the SDK's schema generation races when
/// registrations run concurrently (a RequestContext parameter leaks into tool schemas).
/// </summary>
[CollectionDefinition(Name)]
public sealed class InProcessCatalogCollection
{
    public const string Name = "in-process catalog";
}
