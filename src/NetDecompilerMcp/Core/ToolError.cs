using ModelContextProtocol;

namespace NetDecompilerMcp.Core;

/// <summary>
/// An error the model should see verbatim (bad input, symbol not found, ambiguity...).
/// McpException messages are propagated to the client as a tool error result.
/// </summary>
public sealed class ToolError(string message) : McpException(message);
