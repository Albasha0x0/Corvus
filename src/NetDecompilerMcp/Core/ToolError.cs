using ModelContextProtocol;

namespace NetDecompilerMcp.Core;

/// <summary>
/// A user-facing error; as an McpException its message is returned verbatim to the client as a tool error result.
/// </summary>
public sealed class ToolError(string message) : McpException(message);
