using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Corvus.Services.Simplify;

/// <summary>Keys compare as the default comparer compares the modelled key types: numbers by value, strings ordinally.</summary>
internal sealed class KeyComparer : IEqualityComparer<object>
{
    public static readonly KeyComparer Instance = new();
    public new bool Equals(object? x, object? y) => x != null && y != null && x.GetType() == y.GetType() && x.Equals(y);
    public int GetHashCode(object obj) => obj.GetHashCode();
}

/// <summary>A Dictionary&lt;K, V&gt;: its entries, enumerated in the order they were added (until an entry is removed).</summary>
internal sealed class DictionaryObject(TypeSig keyType, TypeSig valueType) : HeapObject
{
    public TypeSig KeyType { get; } = keyType;
    public TypeSig ValueType { get; } = valueType;
    public Dictionary<object, object?> Entries { get; private init; } = new(KeyComparer.Instance);
    public List<object> Order { get; private init; } = new();
    /// <summary>After a removal the CLR may reuse the freed slot: the enumeration order is no longer the order of addition.</summary>
    public bool Removed { get; set; }
    public int Version { get; set; }

    public DictionaryObject Copy() => new(KeyType, ValueType) { Entries = new(Entries, KeyComparer.Instance), Order = new(Order), Removed = Removed };
}

/// <summary>A List&lt;T&gt;.</summary>
internal sealed class ListObject(TypeSig itemType) : HeapObject
{
    public TypeSig ItemType { get; } = itemType;
    public List<object?> Items { get; private init; } = new();
    public int Version { get; set; }

    public ListObject Copy() => new(ItemType) { Items = new(Items) };
}

/// <summary>A List or Dictionary enumerator (a struct the evaluator keeps as this one object), or a KeyValuePair.</summary>
internal sealed class EnumeratorObject(HeapObject collection, int version) : HeapObject
{
    public HeapObject Collection { get; } = collection;
    public int Version { get; } = version;
    public int Position { get; set; } = -1;
}

internal sealed record PairObject(object Key, object? Value);

/// <summary>StringComparer.Ordinal or OrdinalIgnoreCase.</summary>
internal sealed record ComparerObject(bool IgnoreCase);

internal sealed partial class IlEvaluator
{
    private const string GenericNamespace = "System.Collections.Generic.";

    /// <summary>Framework structs of the modelled collections: kept as the evaluator's own objects.</summary>
    private static bool IsCollectionStruct(GenericInstSig sig) => sig.GenericType.FullName is
        GenericNamespace + "List`1/Enumerator" or GenericNamespace + "Dictionary`2/Enumerator" or GenericNamespace + "KeyValuePair`2";

    /// <summary>Calls on Dictionary, List, their enumerators and KeyValuePair; null when the method is not one of them.</summary>
    private object? CollectionCall(IMethod method, Code op, object?[] args, out bool handled)
    {
        handled = false;
        if (method.DeclaringType?.TryGetGenericInstSig() is not { } owner) return null;
        var generic = owner.GenericType.FullName;
        if (!generic.StartsWith(GenericNamespace, StringComparison.Ordinal)) return null;
        var sig = method.MethodSig;
        string name = method.Name;
        int count = sig?.Params.Count ?? 0;
        object? Receiver() => args[0] is Pointer p ? p.Get() : args[0];
        handled = true;
        switch (generic)
        {
            case GenericNamespace + "Dictionary`2":
            {
                if (op == Code.Newobj)
                {
                    if (count == 1 && sig!.Params[0].FullName.Contains("IEqualityComparer", StringComparison.Ordinal))
                    {
                        // StringComparer.Ordinal compares string keys as the default comparer does; any other does not.
                        if (!(args[0] is ComparerObject { IgnoreCase: false } && owner.GenericArguments[0].ElementType == ElementType.String))
                            throw Bail(FallbackReason.CacheDependent, "a dictionary with a custom comparer");
                    }
                    else if (count == 1 && sig!.Params[0].ElementType != ElementType.I4)
                        throw Bail(FallbackReason.UnsupportedCall, $"calls {Describe(method)}, which is not evaluable");
                    if (count > 1) throw Bail(FallbackReason.UnsupportedCall, $"calls {Describe(method)}, which is not evaluable");
                    Allocate(64);
                    return new DictionaryObject(owner.GenericArguments[0], owner.GenericArguments[1]) { Shared = _cctorDepth > 0 };
                }
                var d = Receiver() as DictionaryObject ?? throw Bail(FallbackReason.UnsupportedValue, "a dictionary the evaluation did not create");
                return (name, count) switch
                {
                    ("get_Count", 0) => d.Entries.Count,
                    ("ContainsKey", 1) => d.Entries.ContainsKey(Key(d, args[1])) ? 1 : 0,
                    ("get_Item", 1) => d.Entries.TryGetValue(Key(d, args[1]), out var v) ? Load(SlotOf(d.ValueType), v) : throw Bail(FallbackReason.RuntimeError, "key not found"),
                    ("TryGetValue", 2) => TryGetValue(d, args[1], args[2]),
                    ("set_Item", 2) => Put(d, args[1], args[2], replace: true),
                    ("Add", 2) => Put(d, args[1], args[2], replace: false),
                    ("Remove", 1) => Remove(d, args[1]),
                    ("Clear", 0) => Mutate(d, () => { d.Entries.Clear(); d.Order.Clear(); }),
                    ("GetEnumerator", 0) => d.Removed
                        ? throw Bail(FallbackReason.PlatformDependent, "enumerating a dictionary after a removal (the order is the runtime's own)")
                        : new EnumeratorObject(d, d.Version),
                    _ => throw Bail(FallbackReason.UnsupportedCall, $"calls {Describe(method)}, which is not evaluable"),
                };
            }
            case GenericNamespace + "List`1":
            {
                if (op == Code.Newobj)
                {
                    if (count == 1 && sig!.Params[0].ElementType != ElementType.I4)
                        throw Bail(FallbackReason.UnsupportedCall, $"calls {Describe(method)}, which is not evaluable");
                    Allocate(32);
                    return new ListObject(owner.GenericArguments[0]) { Shared = _cctorDepth > 0 };
                }
                var l = Receiver() as ListObject ?? throw Bail(FallbackReason.UnsupportedValue, "a list the evaluation did not create");
                var slot = SlotOf(l.ItemType);
                int Index(object? i, int limit) => (uint)I4(i) < (uint)limit ? I4(i) : throw Bail(FallbackReason.RuntimeError, "index out of range");
                return (name, count) switch
                {
                    ("get_Count", 0) => l.Items.Count,
                    ("get_Item", 1) => Load(slot, l.Items[Index(args[1], l.Items.Count)]),
                    ("set_Item", 2) => Mutate(l, () => l.Items[Index(args[1], l.Items.Count)] = Element(slot, args[2])),
                    ("Add", 1) => Mutate(l, () => l.Items.Add(Element(slot, args[1]))),
                    ("Insert", 2) => Mutate(l, () => l.Items.Insert(Index(args[1], l.Items.Count + 1), Element(slot, args[2]))),
                    ("RemoveAt", 1) => Mutate(l, () => l.Items.RemoveAt(Index(args[1], l.Items.Count))),
                    ("Clear", 0) => Mutate(l, () => l.Items.Clear()),
                    ("Contains", 1) => l.Items.Any(i => Equal(i, args[1])) ? 1 : 0,
                    ("IndexOf", 1) => l.Items.FindIndex(i => Equal(i, args[1])),
                    ("ToArray", 0) => ToArray(l),
                    ("GetEnumerator", 0) => new EnumeratorObject(l, l.Version),
                    _ => throw Bail(FallbackReason.UnsupportedCall, $"calls {Describe(method)}, which is not evaluable"),
                };
            }
            case GenericNamespace + "List`1/Enumerator":
            case GenericNamespace + "Dictionary`2/Enumerator":
            {
                var e = Receiver() as EnumeratorObject ?? throw Bail(FallbackReason.UnsupportedValue, "an enumerator the evaluation did not create");
                return name switch
                {
                    "MoveNext" => MoveNext(e),
                    "get_Current" => Current(e),
                    "Dispose" => Void,
                    _ => throw Bail(FallbackReason.UnsupportedCall, $"calls {Describe(method)}, which is not evaluable"),
                };
            }
            case GenericNamespace + "KeyValuePair`2":
            {
                var pair = Receiver() as PairObject ?? throw Bail(FallbackReason.UnsupportedValue, "a key-value pair the evaluation did not create");
                return name switch
                {
                    "get_Key" => pair.Key,
                    "get_Value" => pair.Value,
                    _ => throw Bail(FallbackReason.UnsupportedCall, $"calls {Describe(method)}, which is not evaluable"),
                };
            }
        }
        handled = false;
        return null;
    }

    /// <summary>The caches of the current evaluation: copies of the static collections, as their initialization left them.</summary>
    private readonly Dictionary<FieldDef, HeapObject> _scratch = new();

    /// <summary>A copy of a static cache collection as its type initializer left it, which the call may fill.</summary>
    private HeapObject Scratch(FieldDef field, HeapObject initial)
    {
        if (_scratch.TryGetValue(field, out var copy)) return copy;
        string? why;
        using (Meter?.Exclude()) why = _facts.CacheUse(field);
        if (why != null) throw Bail(FallbackReason.CacheDependent, $"the collection in {field.DeclaringType.FullName}::{field.Name} {why}");
        copy = initial switch
        {
            DictionaryObject d => d.Copy(),
            ListObject l => l.Copy(),
            _ => throw Bail(FallbackReason.InvalidCode, "a cache that is not a collection"),
        };
        _scratch[field] = copy;
        return copy;
    }

    /// <summary>Whether two results of the same call are the same value (numbers, strings, null; arrays element by element).</summary>
    private static bool SameResult(object? a, object? b) => (a, b) switch
    {
        (null, null) => true,
        (string x, string y) => x == y,
        (ArrayObject x, ArrayObject y) => x.Data.Length == y.Data.Length && Enumerable.Range(0, x.Data.Length).All(i => SameResult(x.Data.GetValue(i), y.Data.GetValue(i))),
        _ when Numeric.IsNumber(a) && Numeric.IsNumber(b) => a!.GetType() == b!.GetType() && a.Equals(b),
        _ when a is char or byte or sbyte or short or ushort or uint or ulong && b != null => a.Equals(b),
        _ => false,
    };

    /// <summary>A key of a modelled type (numbers and strings); null throws, as the CLR does.</summary>
    private static object Key(DictionaryObject d, object? key) => key switch
    {
        null => throw Bail(FallbackReason.RuntimeError, "null dictionary key"),
        int or long or string => key,
        _ => throw Bail(FallbackReason.UnsupportedValue, $"a dictionary key of type {d.KeyType.FullName}"),
    };

    private static bool Equal(object? a, object? b) => a == null ? b == null : KeyComparer.Instance.Equals(a, b) || ReferenceEquals(a, b);

    private object? Element(Slot slot, object? value)
    {
        Allocate(8);
        return Store(slot, value);
    }

    private object? Mutate(HeapObject collection, Action change)
    {
        RequireMutable(collection);
        int before = Size(collection);
        change();
        Resized(collection, before, Size(collection));
        switch (collection)
        {
            case DictionaryObject d: d.Version++; break;
            case ListObject l: l.Version++; break;
        }
        return Void;
    }

    private static int Size(HeapObject collection) => collection switch
    {
        DictionaryObject d => d.Entries.Count,
        ListObject l => l.Items.Count,
        _ => 0,
    };

    private object? Put(DictionaryObject d, object? key, object? value, bool replace) => Mutate(d, () =>
    {
        var k = Key(d, key);
        bool exists = d.Entries.ContainsKey(k);
        if (exists && !replace) throw Bail(FallbackReason.RuntimeError, "an item with the same key has already been added");
        Allocate(24);
        d.Entries[k] = Store(SlotOf(d.ValueType), value);
        if (!exists) d.Order.Add(k);
    });

    private object? Remove(DictionaryObject d, object? key)
    {
        var k = Key(d, key);
        if (!d.Entries.ContainsKey(k)) return 0;
        Mutate(d, () =>
        {
            d.Entries.Remove(k);
            d.Order.Remove(k);
            d.Removed = true;
        });
        return 1;
    }

    private object? TryGetValue(DictionaryObject d, object? key, object? output)
    {
        var target = output as Pointer ?? throw Bail(FallbackReason.InvalidCode, "TryGetValue without an out address");
        var slot = SlotOf(d.ValueType);
        bool found = d.Entries.TryGetValue(Key(d, key), out var value);
        target.Set(found ? Load(slot, value) : Default(slot));
        return found ? 1 : 0;
    }

    private ArrayObject ToArray(ListObject l) =>
        NewArray(l.Items.Count == 0 ? Array.CreateInstance(ElementClrType(l.ItemType), 0) : FillArray(l));

    private Array FillArray(ListObject l)
    {
        var array = Array.CreateInstance(ElementClrType(l.ItemType), l.Items.Count);
        for (int i = 0; i < l.Items.Count; i++) SetElement(array, i, l.Items[i]);
        return array;
    }

    private static int CollectionVersion(HeapObject collection) => collection switch
    {
        DictionaryObject d => d.Version,
        ListObject l => l.Version,
        _ => 0,
    };

    private static object MoveNext(EnumeratorObject e)
    {
        if (CollectionVersion(e.Collection) != e.Version) throw Bail(FallbackReason.RuntimeError, "the collection was modified during enumeration");
        int count = e.Collection switch { DictionaryObject d => d.Order.Count, ListObject l => l.Items.Count, _ => 0 };
        if (e.Position < count) e.Position++;
        return e.Position < count ? 1 : 0;
    }

    private object? Current(EnumeratorObject e)
    {
        switch (e.Collection)
        {
            case ListObject l when e.Position >= 0 && e.Position < l.Items.Count:
                return Load(SlotOf(l.ItemType), l.Items[e.Position]);
            case DictionaryObject d when e.Position >= 0 && e.Position < d.Order.Count:
                var key = d.Order[e.Position];
                return new PairObject(key, d.Entries[key]);
            default:
                throw Bail(FallbackReason.InvalidCode, "Current outside the enumeration");
        }
    }
}

/// <summary>A System.Collections.SortedList with integer keys: its entries, in key order.</summary>
internal sealed class SortedListObject : HeapObject
{
    public List<(BoxedValue Key, object? Value)> Entries { get; } = new();
}

internal sealed partial class IlEvaluator
{
    /// <summary>System.Collections.SortedList calls with boxed integer keys of one type; string keys sort by culture and are refused.</summary>
    private object? SortedListCall(IMethod method, Code op, object?[] args, out bool handled)
    {
        handled = method.DeclaringType?.FullName == "System.Collections.SortedList";
        if (!handled) return null;
        int count = method.MethodSig?.Params.Count ?? 0;
        if (op == Code.Newobj)
        {
            if (count > 1 || count == 1 && method.MethodSig!.Params[0].ElementType != ElementType.I4)
                throw Bail(FallbackReason.UnsupportedCall, $"calls {Describe(method)}, which is not evaluable");
            Allocate(48);
            return new SortedListObject { Shared = _cctorDepth > 0 };
        }
        var list = (args[0] is Pointer p ? p.Get() : args[0]) as SortedListObject ?? throw Bail(FallbackReason.UnsupportedValue, "a sorted list the evaluation did not create");
        int Find(object? key)
        {
            var k = SortedKey(key);
            if (list.Entries.Count > 0 && list.Entries[0].Key.Type.ElementType != k.Type.ElementType)
                throw Bail(FallbackReason.RuntimeError, "sorted list keys of different types (ArgumentException)");
            long value = KeyValue(k);
            int lo = 0, hi = list.Entries.Count - 1;
            while (lo <= hi)
            {
                int mid = (lo + hi) / 2;
                long at = KeyValue(list.Entries[mid].Key);
                if (at == value) return mid;
                if (at < value) lo = mid + 1; else hi = mid - 1;
            }
            return ~lo;
        }
        object? Change(Action change)
        {
            RequireMutable(list);
            int before = list.Entries.Count;
            change();
            Resized(list, before, list.Entries.Count);
            return Void;
        }
        int Index(object? i) => (uint)I4(i) < (uint)list.Entries.Count ? I4(i) : throw Bail(FallbackReason.RuntimeError, "index out of range");
        switch (method.Name.String, count)
        {
            case ("get_Count", 0): return list.Entries.Count;
            case ("ContainsKey", 1) or ("Contains", 1): return Find(args[1]) >= 0 ? 1 : 0;
            case ("IndexOfKey", 1): return Math.Max(Find(args[1]), -1);
            case ("get_Item", 1): return Find(args[1]) is var at and >= 0 ? list.Entries[at].Value : null;
            case ("GetByIndex", 1): return list.Entries[Index(args[1])].Value;
            case ("GetKey", 1): return list.Entries[Index(args[1])].Key;
            case ("Add", 2):
                return Change(() =>
                {
                    int at = Find(args[1]);
                    if (at >= 0) throw Bail(FallbackReason.RuntimeError, "an item with the same key has already been added");
                    Allocate(24);
                    list.Entries.Insert(~at, (SortedKey(args[1]), args[2]));
                });
            case ("set_Item", 2):
                return Change(() =>
                {
                    int at = Find(args[1]);
                    Allocate(24);
                    if (at >= 0) list.Entries[at] = (list.Entries[at].Key, args[2]);
                    else list.Entries.Insert(~at, (SortedKey(args[1]), args[2]));
                });
            case ("Remove", 1): return Change(() => { if (Find(args[1]) is var at and >= 0) list.Entries.RemoveAt(at); });
            case ("Clear", 0): return Change(list.Entries.Clear);
            default: throw Bail(FallbackReason.UnsupportedCall, $"calls {Describe(method)}, which is not evaluable");
        }
    }

    private static BoxedValue SortedKey(object? key) => key switch
    {
        null => throw Bail(FallbackReason.RuntimeError, "null key (ArgumentNullException)"),
        BoxedValue { Type.ElementType: ElementType.I1 or ElementType.U1 or ElementType.I2 or ElementType.U2 or ElementType.I4 or ElementType.U4 or ElementType.I8 or ElementType.Char } b => b,
        string => throw Bail(FallbackReason.PlatformDependent, "sorted list string keys (the default comparer orders them by the current culture)"),
        _ => throw Bail(FallbackReason.UnsupportedValue, "a sorted list key that is not a boxed integer"),
    };

    /// <summary>A key's value in the order the default comparer gives it.</summary>
    private static long KeyValue(BoxedValue key) => key.Type.ElementType switch
    {
        ElementType.U4 => (uint)(int)key.Value!,
        ElementType.I8 => (long)key.Value!,
        _ => (int)key.Value!,
    };
}
