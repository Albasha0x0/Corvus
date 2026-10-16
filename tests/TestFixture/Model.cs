namespace Fixture.Model;

public interface IChargeable
{
    void Charge(int amount);
    bool IsActive { get; }
}

public abstract class Entity
{
    public string Name = "";
    public abstract void Tick(float dt);
    public virtual int Score() => 0;
}

public class Account : Entity, IChargeable
{
    public const int MaxBalance = 100;
    private int _balance = MaxBalance;
    public static int AccountCount;

    public event EventHandler? Closed;

    public Account(string name)
    {
        Name = name;
        AccountCount++;
    }

    public int Balance
    {
        get => _balance;
        set => _balance = value;
    }

    public bool IsActive => _balance > 0;

    public void Charge(int amount)
    {
        _balance -= amount;
        if (_balance <= 0)
            Closed?.Invoke(this, EventArgs.Empty);
    }

    public void Charge(int amount, string source)
    {
        Log("charged by " + source);
        Charge(amount);
    }

    public override void Tick(float dt) { }

    public override int Score() => _balance * 2;

    public bool CheckPreview() => Secret.Validate("PREVIEW-CODE-42");

    public async Task<int> LoadAsync()
    {
        await Task.Delay(1);
        return Balance;
    }

    public IEnumerable<int> Range()
    {
        yield return 1;
        yield return 2;
    }

    public int SumPositive(List<int> values) => values.Where(v => v > 0).Sum();

    private static void Log(string message) => Console.WriteLine("[Account] " + message);

    public class Inventory
    {
        public List<string> Items = new();
        public int Count => Items.Count;
    }
}

public sealed class PremiumAccount : Account
{
    public PremiumAccount() : base("PremiumAccount") { }
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
    public static bool Validate(string code) => code.StartsWith("PREVIEW-") && code.Length > 10;
}

public class Container<T> where T : class
{
    public T? Value;
    public T? Get() => Value;
}
