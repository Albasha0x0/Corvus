namespace Fixture.Game;

public interface IDamageable
{
    void TakeDamage(int amount);
    bool IsAlive { get; }
}

public abstract class Entity
{
    public string Name = "";
    public abstract void Tick(float dt);
    public virtual int Score() => 0;
}

public class Player : Entity, IDamageable
{
    public const int MaxHealth = 100;
    private int _health = MaxHealth;
    public static int PlayerCount;

    public event EventHandler? Died;

    public Player(string name)
    {
        Name = name;
        PlayerCount++;
    }

    public int Health
    {
        get => _health;
        set => _health = value;
    }

    public bool IsAlive => _health > 0;

    public void TakeDamage(int amount)
    {
        _health -= amount;
        if (_health <= 0)
            Died?.Invoke(this, EventArgs.Empty);
    }

    public void TakeDamage(int amount, string source)
    {
        Log("hit by " + source);
        TakeDamage(amount);
    }

    public override void Tick(float dt) { }

    public override int Score() => _health * 2;

    public bool CheckLicense() => Secret.Validate("LICENSE-KEY-123");

    public async Task<int> LoadAsync()
    {
        await Task.Delay(1);
        return Health;
    }

    public IEnumerable<int> Range()
    {
        yield return 1;
        yield return 2;
    }

    public int SumPositive(List<int> values) => values.Where(v => v > 0).Sum();

    private static void Log(string message) => Console.WriteLine("[Player] " + message);

    public class Inventory
    {
        public List<string> Items = new();
        public int Count => Items.Count;
    }
}

public sealed class Boss : Player
{
    public Boss() : base("Boss") { }
    public override int Score() => 1000;
}

public struct Vec2
{
    public float X, Y;
    public Vec2(float x, float y) { X = x; Y = y; }
    public float Length() => MathF.Sqrt(X * X + Y * Y);
}

public enum Team : byte { Red = 1, Blue = 2 }

internal static class Secret
{
    public static bool Validate(string key) => key.StartsWith("LICENSE-") && key.Length > 10;
}

public class Container<T> where T : class
{
    public T? Value;
    public T? Get() => Value;
}
