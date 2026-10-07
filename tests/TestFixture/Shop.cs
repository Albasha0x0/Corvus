namespace Fixture.Game;

/// <summary>Targets for C# patching: private state, initializers, expression bodies, overloads, indexers, generics.</summary>
public class Shop
{
    private int _gold = 50;
    private readonly Dictionary<string, int> _prices = new() { ["sword"] = 30, ["shield"] = 20 };

    public int Gold => _gold;

    public int Discount { get; set; } = 10;

    public int this[string item] => PriceOf(item);

    public bool Buy(string item)
    {
        if (!_prices.TryGetValue(item, out var price))
            return false;
        if (price > _gold)
            return false;
        _gold -= price;
        return true;
    }

    public int PriceOf(string item) => _prices.TryGetValue(item, out var p) ? p : -1;

    public int PriceOf(string item, int quantity) => PriceOf(item) * quantity;

    public string Describe() => string.Join(",", _prices.Keys.Select(k => k.ToUpperInvariant()));

    public T Pick<T>(T first, T second) => first;

    public static Shop Create() => new();
}
