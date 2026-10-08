namespace Fixture.Model;

/// <summary>Targets for C# patching: private state, initializers, expression bodies, overloads, indexers, generics.</summary>
public class Shop
{
    private int _credit = 50;
    private readonly Dictionary<string, int> _prices = new() { ["pen"] = 30, ["book"] = 20 };

    public int Credit => _credit;

    public int Discount { get; set; } = 10;

    public int this[string item] => PriceOf(item);

    public bool Buy(string item)
    {
        if (!_prices.TryGetValue(item, out var price))
            return false;
        if (price > _credit)
            return false;
        _credit -= price;
        return true;
    }

    public int PriceOf(string item) => _prices.TryGetValue(item, out var p) ? p : -1;

    public int PriceOf(string item, int quantity) => PriceOf(item) * quantity;

    public string Describe() => string.Join(",", _prices.Keys.Select(k => k.ToUpperInvariant()));

    public T Pick<T>(T first, T second) => first;

    public static Shop Create() => new();

    // Same-arity overloads (C++ bindings must resolve these by exact signature).
    public int Apply(int amount) => amount;

    public int Apply(string code) => code.Length;
}
