using Corvus.Native.Providers.Ida;

namespace Corvus.Tests;

public class IdaUserDatabaseTests
{
    [Fact]
    public void A_32_bit_idb_beside_the_input_is_found_after_an_i64()
    {
        using var dir = new TempDir();
        var image = Path.Combine(dir.Path, "app.dll");
        File.WriteAllBytes(image, [1]);
        Assert.Null(IdaSession.UserDatabase(image));

        File.WriteAllBytes(Path.Combine(dir.Path, "app.idb"), [1]);
        Assert.Equal(Path.Combine(dir.Path, "app.idb"), IdaSession.UserDatabase(image));

        File.WriteAllBytes(image + ".idb", [1]);
        Assert.Equal(Path.Combine(dir.Path, "app.idb"), IdaSession.UserDatabase(image));

        File.WriteAllBytes(image + ".i64", [1]);
        Assert.Equal(image + ".i64", IdaSession.UserDatabase(image));
    }

    [Fact]
    public void An_empty_idb_is_not_used()
    {
        using var dir = new TempDir();
        var image = Path.Combine(dir.Path, "app.dll");
        File.WriteAllBytes(image, [1]);
        File.WriteAllBytes(Path.Combine(dir.Path, "app.idb"), []);
        Assert.Null(IdaSession.UserDatabase(image));
    }
}
