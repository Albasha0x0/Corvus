using System.Text.Json;

namespace Corvus.Tests;

/// <summary>Runtime options the server ships with.</summary>
public class RuntimeConfigTests
{
    [Fact]
    public void Tier_up_starts_without_the_call_counting_delay()
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "corvus.runtimeconfig.json")));
        var options = doc.RootElement.GetProperty("runtimeOptions").GetProperty("configProperties");
        Assert.Equal("0", options.GetProperty("System.Runtime.TieredCompilation.CallCountingDelayMs").ToString());
    }
}