namespace Fixture.Model;

// Singleton whose static accessor is declared on a generic base class.
public abstract class Singleton<T> where T : class, new()
{
    private static T? _instance;
    public static T Instance => _instance ??= new T();
    protected int Version;
    public void Touch() => Version++;
}

public sealed class Bank : Singleton<Bank>
{
    public int Credit;
}

// A static property whose type is the base's type parameter, instantiated with a value type.
public abstract class Holder<T>
{
    public static T? Current { get; set; }
}

public sealed class CountHolder : Holder<int>
{
}
