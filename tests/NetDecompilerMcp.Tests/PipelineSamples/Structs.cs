// A .NET Framework program for the pipeline round trip (PipelineRoundTripTests): struct-heavy code - mutable and
// readonly structs, explicit layout with overlapping fields, struct arrays, ref/out/in parameters, ref returns and
// ref locals, interface calls on structs (boxed vs constrained), default vs overridden equality, nested structs,
// Nullable<T> and copies in foreach; its output depends only on its code.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;

namespace Structs
{
    interface ICounter { int Count { get; } void Increment(); }

    struct Counter : ICounter
    {
        int count;
        public int Count { get { return count; } }
        public void Increment() { count++; }
    }

    struct Point
    {
        public int X, Y;
        public Point(int x, int y) { X = x; Y = y; }
        public void Move(int dx, int dy) { X += dx; Y += dy; }
        public int Manhattan { get { return Math.Abs(X) + Math.Abs(Y); } }
        public override string ToString() { return "(" + X + "," + Y + ")"; }
    }

    readonly struct Money : IEquatable<Money>, IComparable<Money>
    {
        public readonly long Cents;
        public readonly string Currency;
        public Money(long cents, string currency) { Cents = cents; Currency = currency; }
        public Money Add(Money o) { if (o.Currency != Currency) throw new InvalidOperationException("currency"); return new Money(Cents + o.Cents, Currency); }
        public bool Equals(Money o) { return Cents == o.Cents && Currency == o.Currency; }
        public override bool Equals(object obj) { return obj is Money && Equals((Money)obj); }
        public override int GetHashCode() { return (int)Cents ^ Currency.Length; }
        public int CompareTo(Money o) { return Cents.CompareTo(o.Cents); }
        public static bool operator ==(Money a, Money b) { return a.Equals(b); }
        public static bool operator !=(Money a, Money b) { return !a.Equals(b); }
        public override string ToString() { return (Cents < 0 ? "-" : "") + (Math.Abs(Cents) / 100).ToString(CultureInfo.InvariantCulture) + "." + Math.Abs(Cents % 100).ToString("D2", CultureInfo.InvariantCulture) + " " + Currency; }
    }

    struct Plain { public int A; public short B; public byte C; }
    struct WithRef { public int A; public string S; }

    [StructLayout(LayoutKind.Explicit)]
    struct Overlay
    {
        [FieldOffset(0)] public int Int;
        [FieldOffset(0)] public float Float;
        [FieldOffset(0)] public byte B0;
        [FieldOffset(1)] public byte B1;
        [FieldOffset(2)] public byte B2;
        [FieldOffset(3)] public byte B3;
        [FieldOffset(0)] public ushort Low;
        [FieldOffset(2)] public ushort High;
    }

    [StructLayout(LayoutKind.Explicit)]
    struct Wide
    {
        [FieldOffset(0)] public long Long;
        [FieldOffset(0)] public double Double;
        [FieldOffset(0)] public int Lo;
        [FieldOffset(4)] public int Hi;
    }

    struct Rect
    {
        public Point TopLeft;
        public Point BottomRight;
        public int Area { get { return (BottomRight.X - TopLeft.X) * (BottomRight.Y - TopLeft.Y); } }
        public override string ToString() { return "[" + TopLeft + "-" + BottomRight + "]"; }
    }

    static class Program
    {
        static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

        static void Bump<T>(ref T counter) where T : ICounter { counter.Increment(); }
        static void BumpCopy<T>(T counter) where T : ICounter { counter.Increment(); }
        static void BumpIface(ICounter counter) { counter.Increment(); }

        static void Scale(ref Point p, int f) { p.X *= f; p.Y *= f; }
        static void Split(int value, out Point hi, out Point lo) { hi = new Point(value >> 16, value >> 24); lo = new Point(value & 0xFF, (value >> 8) & 0xFF); }
        static int Dot(in Point a, in Point b) { return a.X * b.X + a.Y * b.Y; }

        static ref Point Farthest(Point[] pts)
        {
            int best = 0;
            for (int i = 1; i < pts.Length; i++)
                if (pts[i].Manhattan > pts[best].Manhattan) best = i;
            return ref pts[best];
        }

        static ref int Slot(int[] arr, int key) { return ref arr[(key % arr.Length + arr.Length) % arr.Length]; }

        static Money? Parse(string s)
        {
            if (string.IsNullOrEmpty(s)) return null;
            int sp = s.IndexOf(' ');
            if (sp < 0) return null;
            long cents;
            if (!long.TryParse(s.Substring(0, sp), NumberStyles.Integer, Inv, out cents)) return null;
            return new Money(cents, s.Substring(sp + 1));
        }

        static int Main()
        {
            // Mutable struct copy semantics
            var a = new Point(1, 2);
            var b = a;
            b.Move(10, 10);
            Console.WriteLine("copy: a=" + a + " b=" + b);
            Scale(ref a, 7);
            Point hi, lo;
            Split(0x12345678, out hi, out lo);
            Console.WriteLine("ref/out: a=" + a + " hi=" + hi + " lo=" + lo + " dot=" + Dot(a, lo) + " dotIn=" + Dot(in hi, in lo));

            // Struct arrays, ref returns and ref locals
            var pts = new Point[8];
            for (int i = 0; i < pts.Length; i++) pts[i] = new Point(i * 3 - 10, (i * i) % 7 - 3);
            ref Point far = ref Farthest(pts);
            Console.WriteLine("farthest=" + far + " manhattan=" + far.Manhattan);
            far.Move(100, -100);
            far = ref Farthest(pts);
            far.X = 0;
            int sumX = 0, sumY = 0;
            foreach (Point p in pts) { sumX += p.X; sumY += p.Y; }
            Console.WriteLine("after ref edits: " + string.Join(" ", pts) + " sum=" + sumX + "/" + sumY);
            var buckets = new int[5];
            for (int k = -12; k < 30; k += 3) Slot(buckets, k) += k;
            ref int first = ref buckets[0];
            first *= 10;
            Console.WriteLine("buckets=" + string.Join(",", buckets));

            // foreach copies and List<T> indexer copies
            var list = new List<Point> { new Point(1, 1), new Point(2, 2), new Point(3, 3) };
            foreach (Point p in list) { Point q = p; q.Move(5, 5); }
            Point tmp = list[1];
            tmp.Move(50, 50);
            Console.WriteLine("list unchanged: " + string.Join(" ", list) + " tmp=" + tmp);
            list[1] = tmp;
            for (int i = 0; i < pts.Length; i++) pts[i].Move(i, -i);
            Console.WriteLine("list replaced: " + string.Join(" ", list) + " pts[7]=" + pts[7]);

            // Interface calls: boxing vs constrained
            var c = new Counter();
            c.Increment();
            Bump(ref c);
            BumpCopy(c);
            BumpIface(c);
            ICounter boxed = c;
            boxed.Increment();
            boxed.Increment();
            Counter unboxed = (Counter)boxed;
            unboxed.Increment();
            Console.WriteLine("counter: c=" + c.Count + " boxed=" + boxed.Count + " unboxed=" + unboxed.Count);
            var counters = new Counter[3];
            for (int r = 0; r < 10; r++) Bump(ref counters[r % 3]);
            ICounter[] ifaceArr = { counters[0], counters[1], counters[2] };
            foreach (ICounter ic in ifaceArr) ic.Increment();
            Console.WriteLine("counters: " + counters[0].Count + "," + counters[1].Count + "," + counters[2].Count + " boxedCopies: " + ifaceArr[0].Count + "," + ifaceArr[1].Count + "," + ifaceArr[2].Count);

            // Equality
            var p1 = new Plain { A = 1, B = 2, C = 3 };
            var p2 = new Plain { A = 1, B = 2, C = 3 };
            var p3 = new Plain { A = 1, B = 2, C = 4 };
            var w1 = new WithRef { A = 5, S = "x" + 1 };
            var w2 = new WithRef { A = 5, S = "x1" };
            Console.WriteLine("equals: plain=" + p1.Equals(p2) + "/" + p1.Equals(p3) + " withRef=" + w1.Equals(w2) + " boxedSame=" + ((object)p1).Equals(p2) + " refEq=" + ReferenceEquals(p1, p1));
            var m1 = new Money(1050, "EUR");
            var m2 = new Money(-325, "EUR");
            var m3 = m1.Add(m2);
            Console.WriteLine("money: " + m3 + " eq=" + (m3 == new Money(725, "EUR")) + " ne=" + (m1 != m2) + " cmp=" + m1.CompareTo(m2) + " neg=" + m2);
            var monies = new List<Money> { new Money(500, "USD"), new Money(-20, "USD"), new Money(1999, "USD"), new Money(0, "USD") };
            monies.Sort();
            Console.WriteLine("sorted money: " + string.Join(" | ", monies) + " index=" + monies.IndexOf(new Money(1999, "USD")));
            try { m1.Add(monies[0]); }
            catch (InvalidOperationException e) { Console.WriteLine("money mismatch: " + e.Message); }

            // Explicit layout
            var o = new Overlay { Float = 1.0f };
            Console.WriteLine("overlay 1.0f: int=0x" + o.Int.ToString("X8", Inv) + " bytes=" + o.B0 + "," + o.B1 + "," + o.B2 + "," + o.B3 + " low=" + o.Low + " high=" + o.High);
            o.B3 = 0xC0;
            Console.WriteLine("overlay set B3: float=" + o.Float.ToString("F2", Inv) + " int=" + o.Int);
            o.Int = 0x01020304;
            o.High ^= 0xFF00;
            Console.WriteLine("overlay xor: int=0x" + o.Int.ToString("X8", Inv) + " b3=" + o.B3 + " size=" + Marshal.SizeOf(typeof(Overlay)));
            var w = new Wide { Double = -2.5 };
            Console.WriteLine("wide -2.5: long=0x" + w.Long.ToString("X16", Inv) + " hi=0x" + w.Hi.ToString("X8", Inv) + " lo=" + w.Lo);
            w.Hi = 0x40590000; w.Lo = 0;
            Console.WriteLine("wide set: double=" + w.Double.ToString("F1", Inv) + " size=" + Marshal.SizeOf(typeof(Wide)));

            // Nested structs
            var rect = new Rect { TopLeft = new Point(1, 1), BottomRight = new Point(4, 6) };
            var rect2 = rect;
            rect2.BottomRight.Move(2, 2);
            rect.TopLeft.X = -1;
            Console.WriteLine("nested: " + rect + " area=" + rect.Area + " " + rect2 + " area=" + rect2.Area);
            var rects = new Rect[4];
            int areaSum = 0;
            for (int i = 0; i < rects.Length; i++)
            {
                rects[i].BottomRight = new Point(i + 2, i * 2 + 1);
                rects[i].TopLeft.Move(i, 0);
                switch (i % 3)
                {
                    case 0: rects[i].BottomRight.Y += 3; break;
                    case 1: Scale(ref rects[i].BottomRight, 2); break;
                    default: rects[i].TopLeft.Y = -2; break;
                }
                areaSum += rects[i].Area;
            }
            Console.WriteLine("rect array: " + string.Join(" ", rects) + " areaSum=" + areaSum);

            // Nullable<T> of structs
            string[] inputs = { "1200 USD", "", "abc USD", "-75 USD", "300", "45 USD" };
            Money total = new Money(0, "USD");
            int nulls = 0;
            foreach (string s in inputs)
            {
                Money? m = Parse(s);
                if (m.HasValue) total = total.Add(m.Value); else nulls++;
                Console.WriteLine("  parse '" + s + "' -> " + (m.HasValue ? m.Value.ToString() : "null") + " default=" + m.GetValueOrDefault().Cents);
            }
            Console.WriteLine("nullable total=" + total + " nulls=" + nulls);
            int? x = 5, y = null;
            int? z = x + y, zz = x * 3;
            Point? np = null;
            Point? np2 = new Point(2, 3);
            Console.WriteLine("lifted: z=" + (z.HasValue ? "value" : "null") + " zz=" + zz + " cmp=" + (x > y) + " coalesce=" + (y ?? -1) + " np=" + (np ?? new Point(-1, -1)) + " np2=" + np2.Value.Manhattan + " eq=" + (np == null));

            // Struct churn checksum
            var grid = new Point[16];
            uint chk = 2166136261;
            for (int round = 0; round < 50; round++)
            {
                ref Point cell = ref grid[(round * 7) % grid.Length];
                cell.Move(round % 5 - 2, round % 3 - 1);
                Scale(ref grid[round % grid.Length], (round & 1) == 0 ? 1 : -1);
                for (int i = 0; i < grid.Length; i++) chk = unchecked((chk ^ (uint)(grid[i].X * 31 + grid[i].Y)) * 16777619);
            }
            Console.WriteLine("grid checksum=" + chk.ToString("X8", Inv) + " corner=" + grid[0] + " last=" + grid[15]);
            return 0;
        }
    }
}
