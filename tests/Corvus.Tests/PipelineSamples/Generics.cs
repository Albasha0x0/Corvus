// A .NET Framework program for the pipeline round trip (PipelineRoundTripTests): shared generics over
// reference and value types, constraints, variance, per-instantiation statics, generic virtuals; its output depends only on its code.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Globalization;
using System.Text;

namespace Generics
{
    // Type names would change under renaming: a type is described by what it is.
    static class Names
    {
        public static string Of(Type t)
        {
            if (t == typeof(int)) return "int";
            if (t == typeof(long?)) return "long?";
            if (t == typeof(string)) return "string";
            if (t == typeof(object)) return "object";
            if (t.IsGenericType) return "generic`" + t.GetGenericArguments().Length + "<" + string.Join(",", t.GetGenericArguments().Select(Of)) + ">";
            return t.IsValueType ? "struct" : "class";
        }
    }

    interface IShape { int Area(); string Name { get; } }

    abstract class ShapeBase : IShape
    {
        public abstract int Area();
        public virtual string Name { get { return "shape"; } }
    }

    sealed class Rect : ShapeBase
    {
        readonly int w, h;
        public Rect() : this(1, 1) { }
        public Rect(int w, int h) { this.w = w; this.h = h; }
        public override int Area() { return w * h; }
        public override string Name { get { return "rect" + w + "x" + h; } }
    }

    sealed class Square : ShapeBase
    {
        readonly int s;
        public Square() : this(2) { }
        public Square(int s) { this.s = s; }
        public override int Area() { return s * s; }
        public override string Name { get { return "square" + s; } }
    }

    interface IProducer<out T> { T Produce(int i); }
    interface IConsumer<in T> { string Consume(T item); }

    class ShapeProducer : IProducer<Rect>
    {
        public Rect Produce(int i) { return new Rect(i, i + 1); }
    }

    class ShapeConsumer : IConsumer<IShape>
    {
        public string Consume(IShape item) { return item.Name + "=" + item.Area().ToString(CultureInfo.InvariantCulture); }
    }

    // A static field per closed type
    static class Counter<T>
    {
        public static int Count;
        public static string Tag = Names.Of(typeof(T));
        public static void Hit() { Count++; }
    }

    class Box<T>
    {
        public T Value;
        public Box(T value) { Value = value; Counter<Box<T>>.Hit(); }
        public Box<TOut> Map<TOut>(Func<T, TOut> f) { return new Box<TOut>(f(Value)); }
        public bool IsDefault() { return EqualityComparer<T>.Default.Equals(Value, default(T)); }
        public override string ToString() { return "Box(" + (Value == null ? "null" : Convert.ToString(Value, CultureInfo.InvariantCulture)) + ")"; }
    }

    class Pair<TKey, TValue> where TKey : IComparable<TKey>
    {
        public readonly TKey Key; public readonly TValue Val;
        public Pair(TKey k, TValue v) { Key = k; Val = v; }
        public class Node
        {
            public Pair<TKey, TValue> Item; public Node Next;
        }
    }

    class Visitor
    {
        public virtual string Visit<T>(T item) { return "V:" + Describe(item); }
        protected static string Describe<T>(T item)
        {
            return Names.Of(typeof(T)) + "/" + (item == null ? "null" : Convert.ToString(item, CultureInfo.InvariantCulture));
        }
    }

    class LoudVisitor : Visitor
    {
        public override string Visit<T>(T item) { return base.Visit(item).ToUpperInvariant() + "!"; }
    }

    struct Accum : IComparable<Accum>
    {
        public int Total;
        public int CompareTo(Accum other) { return Total.CompareTo(other.Total); }
        public override string ToString() { return "A" + Total.ToString(CultureInfo.InvariantCulture); }
    }

    static class Algo
    {
        public static T Max<T>(IList<T> items) where T : IComparable<T>
        {
            T best = items[0];
            for (int i = 1; i < items.Count; i++)
                if (items[i].CompareTo(best) > 0) best = items[i];
            return best;
        }

        public static T Create<T>() where T : new() { return new T(); }

        public static T FirstOrNull<T>(IEnumerable<T> items, Predicate<T> p) where T : class
        {
            foreach (T t in items) if (p(t)) return t;
            return null;
        }

        public static T? FindValue<T>(T[] items, Predicate<T> p) where T : struct
        {
            for (int i = 0; i < items.Length; i++) if (p(items[i])) return items[i];
            return null;
        }

        public static int TotalArea<T>(IEnumerable<T> shapes) where T : ShapeBase
        {
            int sum = 0;
            foreach (T s in shapes) sum += s.Area();
            return sum;
        }

        public static void Swap<T>(ref T a, ref T b) { T t = a; a = b; b = t; }

        public static string Join<T>(IEnumerable<T> items)
        {
            var sb = new StringBuilder("[");
            bool first = true;
            foreach (T x in items)
            {
                if (!first) sb.Append(',');
                sb.Append(x == null ? "null" : Convert.ToString(x, CultureInfo.InvariantCulture));
                first = false;
            }
            return sb.Append(']').ToString();
        }

        public static Dictionary<TK, List<TV>> GroupInto<TK, TV>(IEnumerable<TV> items, Func<TV, TK> key)
        {
            var d = new Dictionary<TK, List<TV>>();
            foreach (TV v in items)
            {
                TK k = key(v);
                List<TV> list;
                if (!d.TryGetValue(k, out list)) { list = new List<TV>(); d.Add(k, list); }
                list.Add(v);
            }
            return d;
        }
    }

    static class Program
    {
        static void Main()
        {
            Console.WriteLine("-- defaults");
            Console.WriteLine("int=" + default(int) + " string=" + (default(string) == null) + " double=" + default(double).ToString(CultureInfo.InvariantCulture));
            Console.WriteLine("Box<int>(0).IsDefault=" + new Box<int>(0).IsDefault() + " Box<string>(\"x\").IsDefault=" + new Box<string>("x").IsDefault());
            Console.WriteLine("Box<long?>(null)=" + new Box<long?>(null) + " default=" + new Box<long?>(null).IsDefault());

            Console.WriteLine("-- boxes and maps");
            var b = new Box<int>(21);
            Box<string> bs = b.Map(x => (x * 2).ToString(CultureInfo.InvariantCulture));
            Box<int> bl = bs.Map(s => s.Length);
            Box<Rect> br = bl.Map(n => new Rect(n, 7));
            Console.WriteLine(b + " " + bs + " " + bl + " area=" + br.Value.Area());
            for (int i = 0; i < 3; i++) new Box<decimal>(i * 1.5m);
            Console.WriteLine("Box<int>=" + Counter<Box<int>>.Count + " Box<string>=" + Counter<Box<string>>.Count
                + " Box<decimal>=" + Counter<Box<decimal>>.Count + " Box<Rect>=" + Counter<Box<Rect>>.Count
                + " Box<long?>=" + Counter<Box<long?>>.Count);
            Counter<int>.Hit(); Counter<int>.Hit(); Counter<object>.Hit();
            Console.WriteLine("Counter<int>=" + Counter<int>.Count + " Counter<object>=" + Counter<object>.Count + " tags=" + Counter<int>.Tag + "," + Counter<object>.Tag + "," + Counter<Box<int>>.Tag);

            Console.WriteLine("-- constraints");
            Console.WriteLine("max int=" + Algo.Max(new List<int> { 4, 19, 7, 3 }));
            Console.WriteLine("max string=" + Algo.Max(new[] { "pear", "apple", "zucchini", "fig" }));
            Console.WriteLine("max accum=" + Algo.Max(new[] { new Accum { Total = 5 }, new Accum { Total = 42 }, new Accum { Total = 17 } }));
            Rect created = Algo.Create<Rect>();
            Square sq = Algo.Create<Square>();
            Accum ac = Algo.Create<Accum>();
            Console.WriteLine("created " + created.Name + " " + sq.Name + " " + ac);
            var names = new List<string> { "alpha", "beta", "gamma", "delta" };
            Console.WriteLine("firstOrNull=" + Algo.FirstOrNull(names, s => s.StartsWith("g", StringComparison.Ordinal))
                + " missing=" + (Algo.FirstOrNull(names, s => s.Length > 10) ?? "<none>"));
            int? fv = Algo.FindValue(new[] { 3, 8, 12, 15 }, v => v % 4 == 0);
            int? nf = Algo.FindValue(new[] { 3, 5 }, v => v > 100);
            Console.WriteLine("findValue=" + fv + " hasValue=" + nf.HasValue);
            var shapes = new List<ShapeBase> { new Rect(2, 3), new Square(4), new Rect(5, 1) };
            Console.WriteLine("totalArea base=" + Algo.TotalArea(shapes) + " rects=" + Algo.TotalArea(new[] { new Rect(3, 3), new Rect(1, 9) }));

            Console.WriteLine("-- swap");
            int x1 = 1, x2 = 2; string s1 = "one", s2 = "two";
            Algo.Swap(ref x1, ref x2); Algo.Swap(ref s1, ref s2);
            Console.WriteLine(x1 + " " + x2 + " " + s1 + " " + s2);

            Console.WriteLine("-- variance");
            IProducer<Rect> pr = new ShapeProducer();
            IProducer<IShape> pi = pr;
            IConsumer<IShape> ci = new ShapeConsumer();
            IConsumer<Rect> cr = ci;
            for (int i = 1; i <= 3; i++) Console.WriteLine("variance " + i + ": " + cr.Consume(pr.Produce(i)) + " | " + ci.Consume(pi.Produce(i * 2)));
            IEnumerable<object> objs = new List<string> { "s1", "s2" };
            Func<object, string> fo = o => "<" + o + ">";
            Func<string, object> fs = fo;
            Console.WriteLine("covariant enumerable=" + Algo.Join(objs) + " contravariant func=" + fs("q"));

            Console.WriteLine("-- generic virtual");
            Visitor[] visitors = { new Visitor(), new LoudVisitor() };
            foreach (Visitor v in visitors)
            {
                Console.WriteLine(v.Visit(42) + " " + v.Visit("abc") + " " + v.Visit(2.5) + " " + v.Visit<string>(null) + " " + v.Visit(new Accum { Total = 9 }));
            }

            Console.WriteLine("-- nested generics");
            var nested = new Dictionary<string, List<KeyValuePair<int, Box<string>>>>();
            string[] words = { "ant", "bee", "cat", "dog", "eel", "fox", "gnu" };
            for (int i = 0; i < words.Length; i++)
            {
                string key = (i % 3).ToString(CultureInfo.InvariantCulture);
                List<KeyValuePair<int, Box<string>>> l;
                if (!nested.TryGetValue(key, out l)) nested[key] = l = new List<KeyValuePair<int, Box<string>>>();
                l.Add(new KeyValuePair<int, Box<string>>(i * i, new Box<string>(words[i])));
            }
            var keys = new List<string>(nested.Keys); keys.Sort(StringComparer.Ordinal);
            foreach (string k in keys)
            {
                var sb = new StringBuilder();
                foreach (var kv in nested[k]) sb.Append(kv.Key).Append(':').Append(kv.Value.Value).Append(' ');
                Console.WriteLine("group " + k + " -> " + sb.ToString().TrimEnd());
            }

            Pair<int, string>.Node head = null;
            for (int i = 5; i >= 1; i--) head = new Pair<int, string>.Node { Item = new Pair<int, string>(i, new string((char)('a' + i), i)), Next = head };
            var chain = new StringBuilder();
            int keySum = 0;
            for (var n = head; n != null; n = n.Next) { chain.Append(n.Item.Key).Append('=').Append(n.Item.Val).Append(';'); keySum += n.Item.Key; }
            Console.WriteLine("chain " + chain + " sum=" + keySum);

            var grouped = Algo.GroupInto(new[] { 11, 22, 33, 14, 25, 36, 17 }, v => v % 10 > 4 ? "high" : "low");
            Console.WriteLine("grouped high=" + Algo.Join(grouped["high"]) + " low=" + Algo.Join(grouped["low"]));
            var byLen = Algo.GroupInto(words, w => w[0] < 'd');
            Console.WriteLine("byLen true=" + Algo.Join(byLen[true]) + " false=" + Algo.Join(byLen[false]));

            Console.WriteLine("-- switch over closed types");
            object[] samples = { new Box<int>(3), new Box<string>("t"), new Box<Rect>(new Rect(2, 2)), 7, "str", new Accum { Total = 1 } };
            int score = 0;
            foreach (object o in samples)
            {
                string kind;
                switch (o)
                {
                    case Box<int> bi: kind = "box-int " + (bi.Value * 10); score += bi.Value; break;
                    case Box<string> bstr: kind = "box-str " + bstr.Value.Length; score += 100; break;
                    case Box<Rect> brr: kind = "box-rect " + brr.Value.Area(); score += brr.Value.Area(); break;
                    case int iv when iv > 5: kind = "int>5"; score *= iv; break;
                    case IComparable<Accum> _: kind = "accum"; score -= 1; break;
                    default: kind = "other " + o; break;
                }
                Console.WriteLine("  " + kind);
            }
            Console.WriteLine("score=" + score);
        }
    }
}
