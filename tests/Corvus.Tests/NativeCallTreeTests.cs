using System.Text.Json;
using Corvus.Mcp;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>native_call_tree records and the shared <see cref="NativeTreeNode"/> row.</summary>
public class NativeCallTreeTests
{
    [Fact]
    public void TreeNodeSerializesCompactWithCamelCaseFields()
    {
        var root = new NativeTreeNode(0, null, 0, "main", "0x401000", null, null, null);
        var child = new NativeTreeNode(1, 0, 1, "kernel32.dll!CreateFileW", "0x402000", "lib.dll", "import", ["more"]) { Note = "KERNELBASE.dll!CreateFileW" };
        var json = JsonSerializer.Serialize(new[] { root, child }, ToolOutput.Json);
        Assert.Equal("""[{"id":0,"depth":0,"name":"main","address":"0x401000"},{"id":1,"parent":0,"depth":1,"name":"kernel32.dll!CreateFileW","address":"0x402000","image":"lib.dll","edge":"import","flags":["more"],"note":"KERNELBASE.dll!CreateFileW"}]""", json);
    }
}
