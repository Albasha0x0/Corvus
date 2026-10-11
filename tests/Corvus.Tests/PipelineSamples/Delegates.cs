// A .NET Framework program for the pipeline round trip (PipelineRoundTripTests): custom and generic delegates,
// multicast combine/remove, closures, method groups, field-like and custom events, delegate equality and variance; its output depends only on its code.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Delegates
{
    delegate int BinaryOp(int a, int b);
    delegate void Notify(string message);
    delegate Animal AnimalFactory(string name);
    delegate void Handler<in T>(T item);

    class Animal
    {
        public readonly string Name;
        public Animal(string name) { Name = name; }
        public virtual string Speak() { return Name + " makes a sound"; }
    }

    class Dog : Animal
    {
        public Dog(string name) : base(name) { }
        public override string Speak() { return Name + " barks"; }
    }

    sealed class PriceChangedEventArgs : EventArgs
    {
        public readonly int OldPrice, NewPrice;
        public PriceChangedEventArgs(int oldPrice, int newPrice) { OldPrice = oldPrice; NewPrice = newPrice; }
    }

    sealed class Stock
    {
        readonly string symbol;
        int price;
        EventHandler<PriceChangedEventArgs> priceChanged;
        readonly List<string> audit;

        public Stock(string symbol, int price, List<string> audit) { this.symbol = symbol; this.price = price; this.audit = audit; }

        // field-like event
        public event EventHandler Touched;

        // custom accessors
        public event EventHandler<PriceChangedEventArgs> PriceChanged
        {
            add { audit.Add("add handler to " + symbol); priceChanged += value; }
            remove { audit.Add("remove handler from " + symbol); priceChanged -= value; }
        }

        public int HandlerCount { get { return priceChanged == null ? 0 : priceChanged.GetInvocationList().Length; } }

        public int Price
        {
            get { return price; }
            set
            {
                EventHandler touched = Touched;
                if (touched != null) touched(this, EventArgs.Empty);
                if (value == price) return;
                int old = price;
                price = value;
                EventHandler<PriceChangedEventArgs> h = priceChanged;
                if (h != null) h(this, new PriceChangedEventArgs(old, value));
            }
        }

        public override string ToString() { return symbol; }
    }

    sealed class Accumulator
    {
        public int Total;
        readonly int factor;
        public Accumulator(int factor) { this.factor = factor; }
        public void Add(string s) { Total += s.Length * factor; }
        public Func<int, int> Scaler() { return x => x * factor + Total; }
        public static void Shout(string s) { Program.Out("SHOUT " + s.ToUpperInvariant()); }
        public void Whisper(string s) { Program.Out("whisper(" + factor + ") " + s.ToLowerInvariant()); }
    }

    static class Program
    {
        public static void Out(string s) { Console.WriteLine(s); }

        static int Add(int a, int b) { return a + b; }
        static int Mul(int a, int b) { return a * b; }
        static int Mod(int a, int b) { return b == 0 ? 0 : a % b; }

        static string Names(Delegate d)
        {
            if (d == null) return "<null>";
            // Shape of the invocation list without member names, which a transformation may rename.
            var sb = new StringBuilder();
            foreach (Delegate x in d.GetInvocationList())
            {
                if (sb.Length > 0) sb.Append('+');
                sb.Append(x.Target is Accumulator ? "acc" : "fn");
            }
            return sb.ToString();
        }

        static int Fold(int[] xs, int seed, BinaryOp op)
        {
            int acc = seed;
            foreach (int x in xs) acc = op(acc, x);
            return acc;
        }

        static void Main()
        {
            Out("-- custom delegates and method groups");
            BinaryOp[] ops = { Add, Mul, Mod, (a, b) => a - b, delegate (int a, int b) { return Math.Max(a, b); } };
            int[] data = { 7, 3, 12, 5 };
            for (int i = 0; i < ops.Length; i++)
                Out("op" + i + " " + Names(ops[i]) + " 17,5=" + ops[i](17, 5) + " fold=" + Fold(data, i + 1, ops[i]));

            Out("-- multicast");
            var log = new List<string>();
            Notify n = s => log.Add("first:" + s);
            n += s => log.Add("second:" + s.Length);
            var acc = new Accumulator(3);
            n += acc.Add;
            Notify shout = Accumulator.Shout;
            n += shout;
            n("hello");
            Out("log=" + string.Join(",", log) + " total=" + acc.Total + " list=" + Names(n));
            n -= shout;
            n -= acc.Add; // a new delegate instance equal to the one added
            log.Clear();
            n("bye");
            Out("after remove log=" + string.Join(",", log) + " total=" + acc.Total + " count=" + n.GetInvocationList().Length);
            n -= Accumulator.Shout; // not present: no-op
            Out("after removing absent count=" + n.GetInvocationList().Length);

            Out("-- Delegate.Combine / Remove / RemoveAll");
            var a1 = new Accumulator(1);
            var a2 = new Accumulator(2);
            Notify w1 = a1.Whisper, w2 = a2.Whisper, s0 = Accumulator.Shout;
            Notify combo = (Notify)Delegate.Combine(new Delegate[] { w1, s0, w2, w1, s0 });
            Out("combo=" + Names(combo) + " len=" + combo.GetInvocationList().Length);
            combo("Mixed Case");
            combo = (Notify)Delegate.Remove(combo, w1);
            Out("after Remove(w1) len=" + combo.GetInvocationList().Length);
            combo = (Notify)Delegate.RemoveAll(combo, s0);
            Out("after RemoveAll(shout) len=" + combo.GetInvocationList().Length);
            combo("Tail");
            Notify empty = (Notify)Delegate.Remove(w2, w2);
            Out("removing self gives null=" + (empty == null) + " combine null=" + (Delegate.Combine(null, w1) == (Delegate)w1));

            Out("-- equality");
            Notify e1 = a1.Whisper, e2 = a1.Whisper, e3 = a2.Whisper;
            Func<int, int, int> f1 = Add, f2 = Add;
            Out("same target eq=" + (e1 == e2) + " Equals=" + e1.Equals(e2) + " diff target=" + (e1 == e3)
                + " static eq=" + f1.Equals(f2) + " combined eq=" + ((Notify)(e1 + e3)).Equals(e2 + e3)
                + " target is a1=" + ReferenceEquals(e1.Target, a1) + " static target null=" + (f1.Target == null));

            Out("-- Func / Action and closures");
            int counter = 0;
            Action inc = () => counter++;
            Action twice = inc + inc;
            for (int i = 0; i < 3; i++) twice();
            Out("counter=" + counter);
            Func<int, Func<int, int>> adder = x => y => x + y * counter;
            Func<int, int> add10 = adder(10);
            counter = 2;
            Out("curried=" + add10(5) + " " + adder(1)(1));
            Func<int, int> scaler = a2.Scaler();
            a2.Total = 100;
            Out("instance closure=" + scaler(4));
            Func<int, int> square = x => x * x;
            Func<int, int> composed = Compose(square, x => x + 1);
            Func<int, int> chain = Compose(composed, Compose(x => x * 2, x => x - 3));
            var sb = new StringBuilder();
            for (int i = 0; i < 6; i++) sb.Append(chain(i)).Append(' ');
            Out("composed: " + sb.ToString().TrimEnd());
            var actions = new List<Action>();
            var trace = new StringBuilder();
            for (int i = 0; i < 4; i++)
            {
                int captured = i * 10;
                switch (i % 3)
                {
                    case 0: actions.Add(() => trace.Append("z").Append(captured)); break;
                    case 1: actions.Add(() => trace.Append("o").Append(captured + 1)); break;
                    default: actions.Add(() => trace.Append("t").Append(captured + 2)); break;
                }
            }
            foreach (Action act in actions) act();
            Out("actions: " + trace);
            Func<int, int> fib = null;
            var memo = new Dictionary<int, int>();
            fib = k => { int r; if (memo.TryGetValue(k, out r)) return r; r = k < 2 ? k : fib(k - 1) + fib(k - 2); memo[k] = r; return r; };
            Out("fib(30)=" + fib(30) + " memo=" + memo.Count);

            Out("-- events");
            var audit = new List<string>();
            var stock = new Stock("ACME", 100, audit);
            int touches = 0;
            EventHandler touch = (s, e) => touches++;
            stock.Touched += touch;
            var history = new List<string>();
            EventHandler<PriceChangedEventArgs> onChange = (s, e) =>
                history.Add(s + ":" + e.OldPrice + "->" + e.NewPrice + "(" + (e.NewPrice > e.OldPrice ? "+" : "") + (e.NewPrice - e.OldPrice) + ")");
            EventHandler<PriceChangedEventArgs> bigMoves = (s, e) =>
            {
                int pct = (e.NewPrice - e.OldPrice) * 100 / e.OldPrice;
                if (Math.Abs(pct) >= 10) history.Add("big move " + pct.ToString(CultureInfo.InvariantCulture) + "%");
            };
            stock.PriceChanged += onChange;
            stock.PriceChanged += bigMoves;
            Out("handlers=" + stock.HandlerCount);
            int[] prices = { 101, 101, 120, 95, 96, 70 };
            foreach (int p in prices) stock.Price = p;
            stock.PriceChanged -= bigMoves;
            stock.Touched -= touch;
            stock.Price = 80;
            Out("handlers after remove=" + stock.HandlerCount + " touches=" + touches + " price=" + stock.Price);
            foreach (string h in history) Out("  " + h);
            Out("audit: " + string.Join("; ", audit));

            Out("-- variance");
            AnimalFactory factory = name => new Dog(name);
            Func<string, Dog> dogMaker = name => new Dog(name + "!");
            Func<string, Animal> animalMaker = dogMaker;
            Handler<Animal> pet = x => Out("pet " + x.Speak());
            Handler<Dog> petDog = pet;
            petDog(new Dog("Rex"));
            Out(factory("Fido").Speak() + " / " + animalMaker("Spot").Speak() + " / " + new Animal("Cat").Speak());
            Action<object> printObj = o => Out("object handler got " + o);
            Action<string> printStr = printObj;
            printStr("a string");
            Out("variance identity=" + ReferenceEquals(printObj, printStr));
        }

        static Func<int, int> Compose(Func<int, int> outer, Func<int, int> inner)
        {
            return x => outer(inner(x));
        }
    }
}
