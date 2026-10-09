// A .NET Framework program for the pipeline round trip (PipelineRoundTripTests): async/await state machines
// (chained awaits, try/catch/finally, ConfigureAwait, WhenAll) and iterators (yield, try/finally, nesting); its output depends only on its code.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Threading.Tasks;

namespace AsyncIterators
{
    sealed class Log
    {
        readonly List<string> lines = new List<string>();
        public void Add(string s) { lock (lines) lines.Add(s); }
        public void Flush(string title)
        {
            Console.WriteLine("[" + title + "]");
            foreach (string s in lines) Console.WriteLine("  " + s);
            lines.Clear();
        }
    }

    class Tree<T>
    {
        public T Value; public Tree<T> Left, Right;
        public Tree(T v, Tree<T> l = null, Tree<T> r = null) { Value = v; Left = l; Right = r; }

        public IEnumerable<T> InOrder()
        {
            if (Left != null) foreach (T t in Left.InOrder()) yield return t;
            yield return Value;
            if (Right != null) foreach (T t in Right.InOrder()) yield return t;
        }
    }

    static class Iter
    {
        public static IEnumerable<int> Range(int start, int count, int step)
        {
            for (int i = 0; i < count; i++) yield return start + i * step;
        }

        public static IEnumerable<int> Fib()
        {
            int a = 0, b = 1;
            while (true)
            {
                yield return a;
                int t = a + b; a = b; b = t;
            }
        }

        public static IEnumerable<T> TakeUntil<T>(IEnumerable<T> src, Func<T, bool> stop)
        {
            foreach (T t in src)
            {
                if (stop(t)) yield break;
                yield return t;
            }
        }

        public static IEnumerable<string> Guarded(Log log, string name, int n)
        {
            log.Add(name + ": enter");
            try
            {
                for (int i = 0; i < n; i++)
                {
                    try
                    {
                        yield return name + i;
                    }
                    finally
                    {
                        log.Add(name + ": inner finally " + i);
                    }
                }
            }
            finally
            {
                log.Add(name + ": outer finally");
            }
        }

        public static IEnumerable<KeyValuePair<TA, TB>> Cross<TA, TB>(IEnumerable<TA> a, IEnumerable<TB> b)
        {
            foreach (TA x in a)
                foreach (TB y in b)
                    yield return new KeyValuePair<TA, TB>(x, y);
        }

        public static IEnumerable<string> Words(string text)
        {
            var sb = new StringBuilder();
            foreach (char c in text)
            {
                if (char.IsLetter(c)) { sb.Append(char.ToLowerInvariant(c)); continue; }
                if (sb.Length > 0) { yield return sb.ToString(); sb.Clear(); }
            }
            if (sb.Length > 0) yield return sb.ToString();
        }
    }

    sealed class Worker
    {
        readonly Log log;
        int calls;
        public Worker(Log log) { this.log = log; }

        public async Task<int> ComputeAsync(int x)
        {
            calls++;
            await Task.Yield();
            int y = x * x;
            await Task.Delay(0).ConfigureAwait(false);
            return y + calls;
        }

        public async Task<string> ChainAsync(int seed)
        {
            int a = await ComputeAsync(seed);
            int b = await ComputeAsync(a % 17);
            int c = await ComputeAsync(b % 11).ConfigureAwait(false);
            return a + "->" + b + "->" + c;
        }

        public async Task<int> ParseAsync(string s)
        {
            await Task.Yield();
            return int.Parse(s, NumberStyles.Integer, CultureInfo.InvariantCulture);
        }

        public async Task<int> SafeParseAsync(string s)
        {
            log.Add("parse '" + s + "' start");
            try
            {
                int v = await ParseAsync(s);
                log.Add("parsed " + v);
                return v;
            }
            catch (FormatException)
            {
                log.Add("format error for '" + s + "'");
                return -1;
            }
            catch (OverflowException)
            {
                log.Add("overflow for '" + s + "'");
                return -2;
            }
            finally
            {
                log.Add("parse '" + s + "' done");
            }
        }

        public async Task ThrowAfterAwaitAsync(int code)
        {
            await Task.Yield();
            if (code > 0) throw new InvalidOperationException("code " + code);
        }

        public async Task<int> SumWithRetriesAsync(int[] codes)
        {
            int total = 0;
            foreach (int code in codes)
            {
                try
                {
                    await ThrowAfterAwaitAsync(code);
                    total += 1;
                }
                catch (InvalidOperationException ex)
                {
                    total += 10 * code;
                    log.Add("caught " + ex.Message);
                }
            }
            return total;
        }

        public Task<int> Completed(int v) { return Task.FromResult(v * 3); }

        public async Task<string> DescribeAsync(int n)
        {
            switch (n % 4)
            {
                case 0: return "zero:" + await Completed(n);
                case 1: await Task.Yield(); return "one:" + (n + 1);
                case 2: return "two:" + string.Join("|", await Task.WhenAll(Completed(n), Completed(n + 1)));
                default: return "three:" + (await ComputeAsync(n) - calls);
            }
        }
    }

    static class Program
    {
        static async Task RunAsync()
        {
            var log = new Log();
            var w = new Worker(log);

            Console.WriteLine("chain 3: " + await w.ChainAsync(3));
            Console.WriteLine("chain 8: " + await w.ChainAsync(8).ConfigureAwait(false));

            string[] inputs = { "42", "x7", "99999999999", "-15" };
            int sum = 0;
            foreach (string s in inputs) sum += await w.SafeParseAsync(s);
            Console.WriteLine("parse sum=" + sum);
            log.Flush("parse log");

            int retries = await w.SumWithRetriesAsync(new[] { 0, 3, 0, 5, 1 });
            Console.WriteLine("retries total=" + retries);
            log.Flush("retry log");

            int[] results = await Task.WhenAll(w.Completed(1), w.Completed(2), w.Completed(7));
            Console.WriteLine("whenAll=" + string.Join(",", results));

            var descs = new List<string>();
            for (int i = 0; i < 6; i++) descs.Add(await w.DescribeAsync(i));
            Console.WriteLine("describe: " + string.Join(" ", descs));

            try
            {
                await Task.WhenAll(w.ThrowAfterAwaitAsync(0), w.ThrowAfterAwaitAsync(4));
            }
            catch (InvalidOperationException ex)
            {
                Console.WriteLine("whenAll threw: " + ex.Message);
            }

            Task<int> faulted = Task.FromException<int>(new ArgumentException("bad arg"));
            try { await faulted; }
            catch (ArgumentException ex) { Console.WriteLine("faulted: " + ex.Message + " status=" + faulted.Status); }
        }

        static void Main()
        {
            Console.WriteLine("== async");
            RunAsync().GetAwaiter().GetResult();
            int direct = new Worker(new Log()).ChainAsync(5).GetAwaiter().GetResult().Length;
            Console.WriteLine("direct length=" + direct);

            Console.WriteLine("== iterators");
            Console.WriteLine("range: " + string.Join(",", Iter.Range(10, 5, -3)));
            Console.WriteLine("fib<200: " + string.Join(",", Iter.TakeUntil(Iter.Fib(), f => f >= 200)));
            long evenFibSum = 0;
            foreach (int f in Iter.TakeUntil(Iter.Fib(), f => f > 4000000)) if ((f & 1) == 0) evenFibSum += f;
            Console.WriteLine("even fib sum=" + evenFibSum);

            var log = new Log();
            foreach (string s in Iter.Guarded(log, "full", 3)) log.Add("got " + s);
            log.Flush("full enumeration");
            foreach (string s in Iter.Guarded(log, "early", 5))
            {
                log.Add("got " + s);
                if (s.EndsWith("1", StringComparison.Ordinal)) break;
            }
            log.Flush("early break");
            using (IEnumerator<string> e = Iter.Guarded(log, "manual", 2).GetEnumerator())
            {
                log.Add("created");
                e.MoveNext(); log.Add("current " + e.Current);
            }
            log.Flush("manual dispose");

            var tree = new Tree<string>("m",
                new Tree<string>("f", new Tree<string>("b"), new Tree<string>("h")),
                new Tree<string>("t", new Tree<string>("p", null, new Tree<string>("r")), new Tree<string>("x")));
            Console.WriteLine("inorder: " + string.Join("", tree.InOrder()));
            var numTree = new Tree<int>(50, new Tree<int>(20, new Tree<int>(5)), new Tree<int>(80, new Tree<int>(60), new Tree<int>(95)));
            int acc = 0;
            foreach (int v in numTree.InOrder()) acc = acc * 3 + v;
            Console.WriteLine("tree fold=" + acc);

            var sb = new StringBuilder();
            foreach (var kv in Iter.Cross(new[] { 'a', 'b', 'c' }, Iter.Range(1, 3, 1)))
                sb.Append(kv.Key).Append(kv.Value).Append(' ');
            Console.WriteLine("cross: " + sb.ToString().TrimEnd());

            var counts = new SortedDictionary<string, int>(StringComparer.Ordinal);
            foreach (string word in Iter.Words("The quick brown fox; the lazy dog. The END, quick!"))
            {
                int c;
                counts.TryGetValue(word, out c);
                counts[word] = c + 1;
            }
            foreach (var kv in counts) Console.WriteLine("word " + kv.Key + "=" + kv.Value);

            IEnumerable<int> deferred = Iter.Range(1, 4, 2);
            int total = 0;
            for (int round = 0; round < 3; round++) foreach (int v in deferred) total += v * (round + 1);
            Console.WriteLine("reenumerated total=" + total);
        }
    }
}
