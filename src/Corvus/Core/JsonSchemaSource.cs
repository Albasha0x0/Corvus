using System.Text.Json;
using System.Text.Json.Nodes;

namespace Corvus.Core;

/// <summary>
/// A JSON converter that names the schema of what it writes; output schemas
/// take it for the converted type.
/// </summary>
public interface IJsonSchemaSource
{
    /// <summary>The schema of the values the converter writes; never null.</summary>
    JsonNode Schema(JsonSerializerOptions options);
}
