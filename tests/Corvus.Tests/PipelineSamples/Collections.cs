// A .NET Framework program for the pipeline round trip (PipelineRoundTripTests): collection churn - List<T> with
// comparers, Dictionary add/remove/re-add, HashSet set operations, SortedDictionary, SortedSet, Queue, Stack,
// LinkedList, multidimensional and jagged arrays, Array.Copy/Resize/BinarySearch, an LRU cache and a hand-written
// priority queue, with checksums; its output depends only on its code.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace Collections
{
    sealed class Lcg
    {
        uint state;
        public Lcg(uint seed) { state = seed; }
        public int Next(int max) { state = unchecked(state * 1664525u + 1013904223u); return (int)((state >> 8) % (uint)max); }
    }

    sealed class LruCache<TKey, TValue>
    {
        readonly int capacity;
        readonly Dictionary<TKey, LinkedListNode<KeyValuePair<TKey, TValue>>> map = new Dictionary<TKey, LinkedListNode<KeyValuePair<TKey, TValue>>>();
        readonly LinkedList<KeyValuePair<TKey, TValue>> order = new LinkedList<KeyValuePair<TKey, TValue>>();
        public int Hits, Misses, Evictions;

        public LruCache(int capacity) { this.capacity = capacity; }

        public bool TryGet(TKey key, out TValue value)
        {
            LinkedListNode<KeyValuePair<TKey, TValue>> node;
            if (map.TryGetValue(key, out node))
            {
                order.Remove(node);
                order.AddFirst(node);
                value = node.Value.Value;
                Hits++;
                return true;
            }
            Misses++;
            value = default(TValue);
            return false;
        }

        public void Put(TKey key, TValue value)
        {
            LinkedListNode<KeyValuePair<TKey, TValue>> node;
            if (map.TryGetValue(key, out node)) order.Remove(node);
            else if (map.Count == capacity)
            {
                var last = order.Last;
                order.RemoveLast();
                map.Remove(last.Value.Key);
                Evictions++;
            }
            map[key] = order.AddFirst(new KeyValuePair<TKey, TValue>(key, value));
        }

        public IEnumerable<TKey> KeysMostRecentFirst() { foreach (var kv in order) yield return kv.Key; }
    }

    sealed class MinHeap<T>
    {
        readonly List<T> items = new List<T>();
        readonly IComparer<T> cmp;
        public MinHeap(IComparer<T> cmp) { this.cmp = cmp; }
        public int Count { get { return items.Count; } }

        public void Push(T item)
        {
            items.Add(item);
            int i = items.Count - 1;
            while (i > 0)
            {
                int parent = (i - 1) / 2;
                if (cmp.Compare(items[i], items[parent]) >= 0) break;
                T t = items[i]; items[i] = items[parent]; items[parent] = t;
                i = parent;
            }
        }

        public T Pop()
        {
            T top = items[0];
            int lastIdx = items.Count - 1;
            items[0] = items[lastIdx];
            items.RemoveAt(lastIdx);
            int i = 0;
            while (true)
            {
                int l = i * 2 + 1, r = l + 1, m = i;
                if (l < items.Count && cmp.Compare(items[l], items[m]) < 0) m = l;
                if (r < items.Count && cmp.Compare(items[r], items[m]) < 0) m = r;
                if (m == i) break;
                T t = items[i]; items[i] = items[m]; items[m] = t;
                i = m;
            }
            return top;
        }
    }

    sealed class ByLastDigitThenValue : IComparer<int>
    {
        public int Compare(int a, int b)
        {
            int c = (Math.Abs(a) % 10).CompareTo(Math.Abs(b) % 10);
            return c != 0 ? c : a.CompareTo(b);
        }
    }

    static class Program
    {
        static string J<T>(IEnumerable<T> items) { return string.Join(",", items); }

        static uint Checksum(IEnumerable<int> items)
        {
            uint h = 2166136261;
            foreach (int v in items) h = unchecked((h ^ (uint)v) * 16777619);
            return h;
        }

        static string Hex(uint v) { return v.ToString("X8", CultureInfo.InvariantCulture); }

        static int Main()
        {
            var rng = new Lcg(12345);

            // List<T>: insert, remove, sort with comparers
            var list = new List<int>();
            for (int i = 0; i < 30; i++) list.Add(rng.Next(200) - 50);
            list.Insert(0, 999);
            list.Insert(list.Count / 2, -999);
            list.RemoveAt(5);
            int removed = list.RemoveAll(v => v % 7 == 0);
            list.Remove(list[3]);
            Console.WriteLine("list count=" + list.Count + " removed7=" + removed + " sum=" + list.Sum() + " idx(-999)=" + list.IndexOf(-999));
            var byDigit = new List<int>(list);
            byDigit.Sort(new ByLastDigitThenValue());
            Console.WriteLine("by digit: " + J(byDigit.Take(12)));
            list.Sort((a, b) => b.CompareTo(a));
            Console.WriteLine("desc: " + J(list.Take(10)) + " ... min=" + list[list.Count - 1]);
            list.Reverse(2, 5);
            Console.WriteLine("partial reverse: " + J(list.GetRange(0, 9)) + " binsearch(asc copy)=" + list.OrderBy(v => v).ToList().BinarySearch(list[4]));

            // Dictionary churn with sorted printing
            var dict = new Dictionary<string, int>(StringComparer.Ordinal);
            for (int i = 0; i < 40; i++) dict["k" + (i * 7 % 23)] = i;
            int dRemoved = 0;
            for (int i = 0; i < 23; i += 3) if (dict.Remove("k" + i)) dRemoved++;
            for (int i = 0; i < 6; i++) { int val; if (!dict.TryGetValue("k" + i, out val)) dict.Add("k" + i, -i); else dict["k" + i] = val * 100; }
            bool dup = false;
            try { dict.Add("k1", 0); } catch (ArgumentException) { dup = true; }
            var dKeys = dict.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();
            Console.WriteLine("dict count=" + dict.Count + " removed=" + dRemoved + " dupThrew=" + dup + " containsK3=" + dict.ContainsKey("k3") + " containsValue39=" + dict.ContainsValue(39));
            Console.WriteLine("dict sorted: " + string.Join(" ", dKeys.Select(k => k + "=" + dict[k])));

            // HashSet set operations
            var evens = new HashSet<int>(Enumerable.Range(0, 30).Where(v => v % 2 == 0));
            var threes = new HashSet<int>(Enumerable.Range(0, 30).Where(v => v % 3 == 0));
            var union = new HashSet<int>(evens); union.UnionWith(threes);
            var inter = new HashSet<int>(evens); inter.IntersectWith(threes);
            var except = new HashSet<int>(evens); except.ExceptWith(threes);
            var sym = new HashSet<int>(evens); sym.SymmetricExceptWith(threes);
            Console.WriteLine("sets: union=" + union.Count + " inter=" + J(inter.OrderBy(v => v)) + " except=" + except.Count + " sym=" + sym.Count + " sumSym=" + sym.Sum());
            Console.WriteLine("set rel: subset=" + inter.IsSubsetOf(evens) + " superset=" + union.IsSupersetOf(threes) + " overlaps=" + except.Overlaps(threes) + " addDup=" + evens.Add(4) + " removeMissing=" + evens.Remove(5));

            // SortedDictionary and SortedSet
            var sd = new SortedDictionary<int, string>();
            for (int i = 0; i < 15; i++) sd[(i * 37) % 50] = "v" + i;
            sd.Remove(37); sd.Remove(24); sd[24] = "back";
            Console.WriteLine("sorteddict: " + string.Join(" ", sd.Select(kv => kv.Key + ":" + kv.Value)));
            var ss = new SortedSet<int>(new[] { 50, 10, 40, 20, 30, 10, 60 });
            ss.Remove(40); ss.Add(35); ss.Add(5);
            Console.WriteLine("sortedset: " + J(ss) + " min=" + ss.Min + " max=" + ss.Max + " view[15..45]=" + J(ss.GetViewBetween(15, 45)) + " rev=" + J(ss.Reverse().Take(3)));

            // Queue and Stack: simulated scheduling
            var queue = new Queue<int>();
            var stack = new Stack<int>();
            int processed = 0, pushed = 0;
            for (int step = 0; step < 60; step++)
            {
                switch (step % 4)
                {
                    case 0: queue.Enqueue(step); break;
                    case 1: queue.Enqueue(step * 2); stack.Push(step); pushed++; break;
                    case 2: if (queue.Count > 0) { processed += queue.Dequeue(); } break;
                    default: if (stack.Count > 1) { int a = stack.Pop(); stack.Push(a + stack.Pop()); } break;
                }
            }
            Console.WriteLine("queue count=" + queue.Count + " peek=" + queue.Peek() + " processed=" + processed + " stack count=" + stack.Count + " top=" + stack.Peek() + " pushed=" + pushed);
            Console.WriteLine("queue items=" + J(queue.Take(8)) + " stack items=" + J(stack));

            // LinkedList
            var ll = new LinkedList<int>(Enumerable.Range(1, 10));
            var node = ll.Find(5);
            ll.AddBefore(node, 50); ll.AddAfter(node, 55);
            ll.Remove(1); ll.RemoveLast(); ll.AddFirst(0);
            for (var n = ll.First; n != null; )
            {
                var next = n.Next;
                if (n.Value % 3 == 0 && n.Value != 0) ll.Remove(n);
                n = next;
            }
            Console.WriteLine("linkedlist: " + J(ll) + " count=" + ll.Count + " first=" + ll.First.Value + " last=" + ll.Last.Value);

            // Arrays: multidimensional, jagged, Copy, Resize, BinarySearch
            var grid = new int[4, 5];
            for (int r = 0; r < 4; r++) for (int c = 0; c < 5; c++) grid[r, c] = r * 10 + c * c;
            int diag = 0; for (int i = 0; i < 4; i++) diag += grid[i, i];
            Console.WriteLine("grid rank=" + grid.Rank + " len=" + grid.Length + " dim1=" + grid.GetLength(1) + " diag=" + diag + " corner=" + grid[3, 4]);
            var jag = new int[5][];
            for (int i = 0; i < jag.Length; i++) { jag[i] = new int[i + 1]; for (int k = 0; k <= i; k++) jag[i][k] = (i == 0 || k == 0 || k == i) ? 1 : jag[i - 1][k - 1] + jag[i - 1][k]; }
            Console.WriteLine("pascal: " + string.Join(" | ", jag.Select(row => J(row))));
            int[] src = Enumerable.Range(0, 12).Select(v => v * v - 20).ToArray();
            int[] dst = new int[8];
            Array.Copy(src, 3, dst, 1, 6);
            Array.Resize(ref dst, 11);
            dst[10] = 77;
            Array.Sort(dst);
            Console.WriteLine("array: " + J(dst) + " bs(16)=" + Array.BinarySearch(dst, 16) + " bs(17)=" + Array.BinarySearch(dst, 17) + " idx77=" + Array.IndexOf(dst, 77));
            object[] mixed = new object[3];
            Array.Copy(new[] { "a", "b" }, mixed, 2);
            Array.Clear(dst, 0, 3);
            Console.WriteLine("clear: " + J(dst.Take(5)) + " mixedNull=" + (mixed[2] == null) + " reverse=" + J(src.Reverse().Take(4)));

            // LRU cache
            var cache = new LruCache<int, string>(4);
            int[] accesses = { 1, 2, 3, 1, 4, 5, 2, 1, 6, 3, 1, 7, 4, 1, 2 };
            foreach (int key in accesses)
            {
                string v;
                if (!cache.TryGet(key, out v)) cache.Put(key, "item" + key);
            }
            Console.WriteLine("lru: hits=" + cache.Hits + " misses=" + cache.Misses + " evictions=" + cache.Evictions + " order=" + J(cache.KeysMostRecentFirst()));

            // Priority queue
            var heap = new MinHeap<KeyValuePair<int, int>>(Comparer<KeyValuePair<int, int>>.Create((a, b) => a.Key != b.Key ? a.Key.CompareTo(b.Key) : a.Value.CompareTo(b.Value)));
            for (int i = 0; i < 20; i++) heap.Push(new KeyValuePair<int, int>(rng.Next(10), i));
            var popped = new List<string>();
            for (int i = 0; i < 8; i++) { var kv = heap.Pop(); popped.Add(kv.Key + "/" + kv.Value); }
            for (int i = 0; i < 5; i++) heap.Push(new KeyValuePair<int, int>(i - 2, 100 + i));
            var rest = new List<int>();
            while (heap.Count > 0) rest.Add(heap.Pop().Key);
            Console.WriteLine("heap popped: " + string.Join(" ", popped));
            Console.WriteLine("heap rest: " + J(rest) + " sorted=" + rest.SequenceEqual(rest.OrderBy(v => v)));

            // Sliding window with Queue and running counts in a SortedDictionary
            var window = new Queue<int>();
            var freq = new SortedDictionary<int, int>();
            int windowSum = 0;
            for (int i = 0; i < 48; i++)
            {
                int v = rng.Next(6);
                window.Enqueue(v); windowSum += v;
                int f; freq[v] = freq.TryGetValue(v, out f) ? f + 1 : 1;
                if (window.Count > 5)
                {
                    int old = window.Dequeue(); windowSum -= old;
                    if (--freq[old] == 0) freq.Remove(old);
                }
                if (i % 6 == 5)
                    Console.WriteLine("window " + i + ": items=" + J(window) + " sum=" + windowSum + " distinct=" + freq.Count + " freq=" + string.Join(" ", freq.Select(kv => kv.Key + "x" + kv.Value)));
            }

            // Many add/remove cycles with checksums
            var bag = new Dictionary<int, int>();
            var live = new SortedSet<int>();
            var churnList = new List<int>();
            for (int cycle = 0; cycle < 5; cycle++)
            {
                for (int i = 0; i < 200; i++)
                {
                    int k = rng.Next(150);
                    int op = rng.Next(3);
                    if (op == 0) { bag.Remove(k); live.Remove(k); churnList.Remove(k); }
                    else
                    {
                        int prev;
                        bag[k] = bag.TryGetValue(k, out prev) ? prev + i : i;
                        live.Add(k);
                        if (op == 2) churnList.Add(k);
                    }
                }
                var keys = bag.Keys.ToList();
                keys.Sort();
                Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "cycle {0}: dict={1} set={2} list={3} keysum={4} chkKeys={5} chkVals={6} chkList={7}",
                    cycle, bag.Count, live.Count, churnList.Count, keys.Sum(), Hex(Checksum(keys)), Hex(Checksum(keys.Select(k => bag[k]))), Hex(Checksum(churnList))));
            }
            return 0;
        }
    }
}
