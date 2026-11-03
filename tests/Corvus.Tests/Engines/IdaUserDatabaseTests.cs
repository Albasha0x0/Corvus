using Corvus.Native.Providers.Ida;

namespace Corvus.Tests;

public class IdaUserDatabaseTests
{
    [Fact]
    public void An_i64_beside_the_input_is_found_and_a_32_bit_idb_is_not()
    {
        using var dir = new TempDir();
        var image = Path.Combine(dir.Path, "app.dll");
        File.WriteAllBytes(image, [1]);
        File.WriteAllBytes(Path.Combine(dir.Path, "app.idb"), [1]);
        File.WriteAllBytes(image + ".idb", [1]);
        Assert.Null(IdaSession.UserDatabase(image));

        File.WriteAllBytes(image + ".i64", [1]);
        Assert.Equal(image + ".i64", IdaSession.UserDatabase(image));
    }
}
