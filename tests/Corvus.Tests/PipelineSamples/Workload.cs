// A .NET Framework program for the pipeline round trip (PipelineRoundTripTests): it prints a transcript that depends
// only on its code, so the original, processed and simplified builds must print the same one.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;

namespace Workload
{
    internal interface IShape
    {
        double Area();
        string Name { get; }
    }

    internal abstract class Shape : IShape
    {
        public abstract double Area();
        public virtual string Name => "shape";
        public override string ToString() => Name + ":" + Area().ToString("F2", CultureInfo.InvariantCulture);
    }

    internal sealed class Circle : Shape
    {
        private readonly double _r;
        public Circle(double r) { _r = r; }
        public override double Area() => Math.PI * _r * _r;
        public override string Name => "circle";
    }

    internal sealed class Rect : Shape
    {
        private readonly double _w, _h;
        public Rect(double w, double h) { _w = w; _h = h; }
        public override double Area() => _w * _h;
    }

    internal struct Point
    {
        public int X, Y;
        public Point(int x, int y) { X = x; Y = y; }
        public int Manhattan() => Math.Abs(X) + Math.Abs(Y);
        public override string ToString() => "(" + X + "," + Y + ")";
    }

    internal static class Tables
    {
        public static readonly int[] Primes = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29 };
        public static readonly string[] Words = { "alpha", "beta", "gamma", "delta", "epsilon" };
        public static readonly byte[] Key = { 0x13, 0x37, 0xC0, 0xDE, 0x42 };
        public static readonly Dictionary<string, int> Index = new Dictionary<string, int>();
        public static readonly Func<int, int> Square = x => x * x;

        static Tables()
        {
            for (int i = 0; i < Words.Length; i++) Index[Words[i]] = i;
        }
    }

    internal static class Program
    {
        private static readonly StringBuilder Log = new StringBuilder();
        private static int _counter;
        private const string Banner = "pipeline round trip";

        private static void Out(string label, object value)
        {
            Console.WriteLine(label + " = " + Convert.ToString(value, CultureInfo.InvariantCulture));
        }

        private static int Main(string[] args)
        {
            Thread.CurrentThread.CurrentCulture = CultureInfo.InvariantCulture;
            Out("banner", Banner);
            Strings();
            Numbers();
            Flow();
            Objects();
            Generics();
            Exceptions();
            Resources();
            Out("log", Log.ToString());
            Out("counter", _counter);
            return 0;
        }

        private static void Strings()
        {
            string s = "The quick brown fox";
            Out("upper", s.ToUpperInvariant());
            Out("words", string.Join("|", s.Split(' ').Reverse()));
            Out("unicode", "été|λόγος|日本語".Length);
            Out("concat", string.Concat("a", 1, 'b', 2.5));
            Out("format", string.Format(CultureInfo.InvariantCulture, "{0:D4}-{1:X}-{2}", 42, 255, "z"));
            var sb = new StringBuilder();
            for (int i = 0; i < 5; i++) sb.Append(Tables.Words[i][0]).Append(i);
            Out("builder", sb.ToString());
            Out("empty", string.IsNullOrEmpty("") + "/" + string.IsNullOrEmpty(null) + "/" + string.IsNullOrEmpty("x"));
            Out("xor", Xor("secret", Tables.Key));
            Out("escape", "tab\tnew\\line \"quoted\"");
        }

        private static string Xor(string text, byte[] key)
        {
            var chars = text.ToCharArray();
            for (int i = 0; i < chars.Length; i++) chars[i] = (char)(chars[i] ^ key[i % key.Length]);
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(chars));
        }

        private static void Numbers()
        {
            Out("int", int.MaxValue + "/" + int.MinValue);
            Out("long", long.MaxValue / 3);
            Out("double", Math.Sqrt(2).ToString("F10", CultureInfo.InvariantCulture));
            Out("float", (1.0f / 3).ToString("F5", CultureInfo.InvariantCulture));
            Out("decimal", 1.1m * 3);
            Out("primes", Tables.Primes.Sum());
            Out("square", Tables.Square(12));
            unchecked
            {
                int h = 17;
                foreach (var w in Tables.Words) h = h * 31 + w.Length;
                Out("hash", h);
            }
            Out("shift", (0x80000000u >> 3) + ":" + (-16 >> 2) + ":" + (1L << 40));
            Out("checked", Checked(int.MaxValue));
            Out("fib", Fib(20));
            Out("gcd", Gcd(1071, 462));
        }

        private static string Checked(int value)
        {
            try { return checked(value + 1).ToString(); }
            catch (OverflowException) { return "overflow"; }
        }

        private static long Fib(int n) => n < 2 ? n : Fib(n - 1) + Fib(n - 2);

        private static int Gcd(int a, int b)
        {
            while (b != 0)
            {
                int t = a % b;
                a = b;
                b = t;
            }
            return a;
        }

        private static string Classify(int n)
        {
            switch (n % 7)
            {
                case 0: return "zero";
                case 1: return "one";
                case 2: return "two";
                case 3: case 4: return "few";
                case 5: return "five";
                default: return "many";
            }
        }

        private static string Day(string name)
        {
            switch (name)
            {
                case "mon": return "Monday";
                case "tue": return "Tuesday";
                case "wed": return "Wednesday";
                case "thu": return "Thursday";
                case "fri": return "Friday";
                case "sat": return "Saturday";
                case "sun": return "Sunday";
                default: return "?";
            }
        }

        private static void Flow()
        {
            var parts = new List<string>();
            for (int i = 0; i < 10; i++) parts.Add(Classify(i * 3));
            Out("classify", string.Join(",", parts));
            Out("days", Day("mon") + Day("sun") + Day("xyz"));
            int total = 0, j = 0;
            do
            {
                if (j % 3 == 0) continue;
                if (j > 40) break;
                total += j;
            } while (++j < 50);
            Out("loop", total);
            int nested = 0;
            for (int a = 0; a < 6; a++)
                for (int b = 0; b < 6; b++)
                    if ((a ^ b) % 2 == 0 && a != b) nested += a * b;
            Out("nested", nested);
            bool flag = total > 100 && nested < 1000 || Day("x") == "?";
            Out("flag", flag);
            Out("ternary", total > 500 ? "big" : total > 100 ? "mid" : "small");
            _counter += parts.Count;
        }

        private static void Objects()
        {
            var shapes = new List<IShape> { new Circle(1.5), new Rect(2, 3.5), new Circle(0.5) };
            Out("shapes", string.Join(";", shapes.Select(s => s.ToString())));
            Out("largest", shapes.OrderByDescending(s => s.Area()).First().Name);
            var p = new Point(3, -4);
            var q = p;
            q.X = 10;
            Out("points", p + "" + q + p.Manhattan());
            Action<string> log = m => Log.Append(m).Append(';');
            log("first");
            Func<int, int, int> add = (a, b) => a + b;
            log("sum=" + add(20, 22));
            EventHandler handler = null;
            handler += (o, e) => _counter++;
            handler += (o, e) => _counter += 10;
            handler(null, EventArgs.Empty);
            Out("index", Tables.Index["gamma"]);
        }

        private static T Max<T>(IEnumerable<T> items) where T : IComparable<T>
        {
            T best = default(T);
            bool first = true;
            foreach (var item in items)
            {
                if (first || item.CompareTo(best) > 0) best = item;
                first = false;
            }
            return best;
        }

        private static void Generics()
        {
            Out("max-int", Max(new[] { 4, 9, 2 }));
            Out("max-str", Max(Tables.Words));
            var pairs = Tables.Words.Zip(Tables.Primes, (w, n) => w + n).Where(x => x.Length > 5).ToArray();
            Out("zip", string.Join(",", pairs));
            var groups = Enumerable.Range(1, 20).GroupBy(n => n % 3).Select(g => g.Key + ":" + g.Sum());
            Out("groups", string.Join(" ", groups));
            var stack = new Stack<int>(Tables.Primes);
            Out("stack", stack.Pop() + stack.Peek());
            Out("yield", string.Join(",", Evens(12)));
        }

        private static IEnumerable<int> Evens(int limit)
        {
            for (int i = 0; i <= limit; i += 2)
            {
                if (i == 8) yield return -1;
                yield return i;
            }
        }

        private static void Exceptions()
        {
            var trace = new StringBuilder();
            try
            {
                trace.Append("try;");
                Thrower(2);
            }
            catch (InvalidOperationException e)
            {
                trace.Append("catch:" + e.Message + ";");
            }
            finally
            {
                trace.Append("finally;");
            }
            try
            {
                int zero = trace.Length - trace.Length;
                trace.Append(10 / zero);
            }
            catch (DivideByZeroException)
            {
                trace.Append("div0;");
            }
            try
            {
                try { throw new ArgumentException("inner"); }
                finally { trace.Append("inner-finally;"); }
            }
            catch (Exception e) when (e.Message == "inner")
            {
                trace.Append("filtered;");
            }
            using (var reader = new StringReader("line1\nline2"))
                trace.Append(reader.ReadLine());
            Out("exceptions", trace.ToString());
        }

        private static void Thrower(int depth)
        {
            if (depth == 0) throw new InvalidOperationException("deep");
            Thrower(depth - 1);
        }

        private static void Resources()
        {
            var asm = Assembly.GetExecutingAssembly();
            using (var stream = asm.GetManifestResourceStream("Workload.data.txt"))
            {
                if (stream == null)
                {
                    Out("resource", "missing");
                    return;
                }
                using (var reader = new StreamReader(stream, Encoding.UTF8))
                    Out("resource", reader.ReadToEnd().Trim());
            }
        }
    }
}
