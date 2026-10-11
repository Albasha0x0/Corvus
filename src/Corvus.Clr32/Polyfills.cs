// Language and library pieces .NET Framework lacks, for the source shared with the server.

global using System;
global using System.Collections.Generic;
global using System.IO;
global using System.Linq;
global using System.Threading;
global using System.Threading.Tasks;

namespace System.Runtime.CompilerServices
{
    internal static class IsExternalInit;
}

namespace System
{
    internal readonly struct Index
    {
        private readonly int _value;

        public Index(int value, bool fromEnd = false) => _value = fromEnd ? ~value : value;

        public bool IsFromEnd => _value < 0;
        public int Value => _value < 0 ? ~_value : _value;

        public int GetOffset(int length) => IsFromEnd ? length - Value : Value;

        public static implicit operator Index(int value) => new(value);
    }

    internal readonly struct Range(Index start, Index end)
    {
        public Index Start { get; } = start;
        public Index End { get; } = end;

        public static Range StartAt(Index start) => new(start, new Index(0, true));
        public static Range EndAt(Index end) => new(new Index(0), end);
        public static Range All => new(new Index(0), new Index(0, true));
    }
}

namespace System.Collections.Generic
{
    internal static class DictionaryPolyfills
    {
        public static TValue? GetValueOrDefault<TKey, TValue>(this Dictionary<TKey, TValue> dictionary, TKey key) where TKey : notnull =>
            dictionary.TryGetValue(key, out var value) ? value : default;
    }
}
