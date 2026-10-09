// A .NET Framework program for the pipeline round trip (PipelineRoundTripTests): LINQ query and method syntax,
// grouping, joins, ordering, aggregation, lookups, deferred execution, closures, anonymous types; its output depends only on its code.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;

namespace Linq
{
    sealed class Employee
    {
        public int Id; public string Name; public string Dept; public int Salary; public int? ManagerId;
        public Employee(int id, string name, string dept, int salary, int? managerId)
        { Id = id; Name = name; Dept = dept; Salary = salary; ManagerId = managerId; }
    }

    sealed class Order
    {
        public int OrderId; public int EmployeeId; public string Product; public int Qty; public decimal Price;
        public Order(int orderId, int employeeId, string product, int qty, decimal price)
        { OrderId = orderId; EmployeeId = employeeId; Product = product; Qty = qty; Price = price; }
    }

    static class Program
    {
        static readonly CultureInfo Inv = CultureInfo.InvariantCulture;
        static int evaluations;

        static string F(decimal d) { return d.ToString("0.00", Inv); }
        static string F(double d) { return d.ToString("0.###", Inv); }

        static IEnumerable<int> Source(int n)
        {
            for (int i = 1; i <= n; i++) { evaluations++; yield return i; }
        }

        static void Main()
        {
            var employees = new List<Employee>
            {
                new Employee(1, "Ada", "Eng", 180, null),
                new Employee(2, "Brian", "Eng", 120, 1),
                new Employee(3, "Chen", "Ops", 95, 1),
                new Employee(4, "Dana", "Eng", 135, 2),
                new Employee(5, "Eve", "Sales", 88, 1),
                new Employee(6, "Farid", "Ops", 101, 3),
                new Employee(7, "Gita", "Sales", 92, 5),
                new Employee(8, "Hugo", "Eng", 120, 2),
                new Employee(9, "Iris", "Legal", 140, null),
            };
            var orders = new List<Order>
            {
                new Order(100, 5, "Widget", 3, 9.99m), new Order(101, 7, "Gadget", 1, 24.50m),
                new Order(102, 5, "Gizmo", 10, 1.25m), new Order(103, 2, "Widget", 2, 9.99m),
                new Order(104, 7, "Widget", 5, 9.49m), new Order(105, 6, "Gadget", 2, 23.00m),
                new Order(106, 5, "Gadget", 1, 24.50m), new Order(107, 42, "Orphan", 1, 1.00m),
            };

            Console.WriteLine("-- query syntax");
            var wellPaid = from e in employees
                           where e.Salary >= 100
                           orderby e.Dept, e.Salary descending, e.Name
                           select new { e.Name, e.Dept, Band = e.Salary / 50 };
            foreach (var x in wellPaid) Console.WriteLine("  " + x.Dept + " " + x.Name + " band" + x.Band);

            Console.WriteLine("-- group by");
            var byDept = from e in employees
                         group e by e.Dept into g
                         orderby g.Key
                         select new { Dept = g.Key, Count = g.Count(), Total = g.Sum(e => e.Salary), Avg = g.Average(e => e.Salary), Top = g.OrderByDescending(e => e.Salary).ThenBy(e => e.Name).First().Name };
            foreach (var g in byDept) Console.WriteLine("  " + g.Dept + ": n=" + g.Count + " total=" + g.Total + " avg=" + F(g.Avg) + " top=" + g.Top);

            Console.WriteLine("-- join");
            var joined = from o in orders
                         join e in employees on o.EmployeeId equals e.Id
                         let line = o.Qty * o.Price
                         orderby line descending, o.OrderId
                         select o.OrderId + " " + e.Name + " " + o.Product + " " + F(line);
            foreach (string s in joined) Console.WriteLine("  " + s);

            Console.WriteLine("-- group join (left outer)");
            var perEmployee = employees.GroupJoin(orders, e => e.Id, o => o.EmployeeId,
                (e, os) => new { e.Name, Orders = os.Count(), Revenue = os.Sum(o => o.Qty * o.Price) })
                .Where(x => x.Orders > 0 || x.Name.Length <= 3)
                .OrderByDescending(x => x.Revenue).ThenBy(x => x.Name);
            foreach (var p in perEmployee) Console.WriteLine("  " + p.Name + " orders=" + p.Orders + " revenue=" + F(p.Revenue));
            var outer = from e in employees
                        join o in orders on e.Id equals o.EmployeeId into eo
                        from o in eo.DefaultIfEmpty()
                        where e.Dept == "Ops"
                        select e.Name + ":" + (o == null ? "-" : o.Product);
            Console.WriteLine("  ops outer: " + string.Join(", ", outer));

            Console.WriteLine("-- self join / manager chain");
            var mgr = employees.Join(employees, e => e.ManagerId, m => (int?)m.Id, (e, m) => new { E = e.Name, M = m.Name })
                .OrderBy(p => p.M, StringComparer.Ordinal).ThenByDescending(p => p.E, StringComparer.Ordinal);
            Console.WriteLine("  " + string.Join(" ", mgr.Select(p => p.E + "<" + p.M)));
            var byId = employees.ToDictionary(e => e.Id);
            Func<Employee, int> depth = null;
            depth = e => e.ManagerId.HasValue ? 1 + depth(byId[e.ManagerId.Value]) : 0;
            Console.WriteLine("  depths: " + string.Join(",", employees.Select(e => e.Name.Substring(0, 1) + depth(e))));

            Console.WriteLine("-- SelectMany / Distinct / Zip");
            string[] sentences = { "the cat sat", "the dog ran far", "a cat ran" };
            var words = sentences.SelectMany(s => s.Split(' '), (s, w) => new { Len = s.Length, W = w });
            Console.WriteLine("  distinct: " + string.Join(",", words.Select(x => x.W).Distinct().OrderBy(w => w, StringComparer.Ordinal)));
            Console.WriteLine("  pairs: " + string.Join(" ", words.Where(x => x.W.Length == 3).Select(x => x.W + x.Len).Take(5)));
            var products = orders.Select(o => o.Product).Distinct().ToArray();
            var codes = products.Zip(Enumerable.Range(1, 10), (p, i) => p.Substring(0, 2).ToUpperInvariant() + i * 7);
            Console.WriteLine("  zip: " + string.Join(",", codes));
            var grid = from a in Enumerable.Range(1, 4) from b in Enumerable.Range(a, 3) where (a + b) % 3 == 0 select a * 10 + b;
            Console.WriteLine("  grid: " + string.Join(",", grid));

            Console.WriteLine("-- Aggregate");
            int fact = Enumerable.Range(1, 10).Aggregate(1, (acc, n) => acc * n % 1000003);
            string csv = employees.Select(e => e.Name).Aggregate((a, b) => a + ";" + b);
            var stats = employees.Aggregate(new { Min = int.MaxValue, Max = int.MinValue, Sum = 0 },
                (acc, e) => new { Min = Math.Min(acc.Min, e.Salary), Max = Math.Max(acc.Max, e.Salary), Sum = acc.Sum + e.Salary },
                acc => "min=" + acc.Min + " max=" + acc.Max + " sum=" + acc.Sum);
            Console.WriteLine("  fact=" + fact + " " + stats);
            Console.WriteLine("  csv=" + csv);
            ulong hash = orders.Aggregate(14695981039346656037UL, (h, o) => unchecked((h ^ (ulong)o.OrderId) * 1099511628211UL));
            Console.WriteLine("  fnv=" + hash.ToString("X16", Inv));

            Console.WriteLine("-- ToLookup / ToDictionary");
            ILookup<char, string> lookup = employees.ToLookup(e => e.Name[0] < 'E' ? 'A' : 'E', e => e.Name);
            foreach (var grp in lookup.OrderBy(g => g.Key)) Console.WriteLine("  " + grp.Key + ": " + string.Join(",", grp));
            Console.WriteLine("  missing key count=" + lookup['Z'].Count());
            var productQty = orders.GroupBy(o => o.Product).ToDictionary(g => g.Key, g => g.Sum(o => o.Qty));
            foreach (var key in productQty.Keys.OrderBy(k => k, StringComparer.Ordinal)) Console.WriteLine("  qty " + key + "=" + productQty[key]);

            Console.WriteLine("-- Skip / Take / While");
            int[] seq = { 3, 6, 9, 2, 12, 15, 4, 8 };
            Console.WriteLine("  skip2take3=" + string.Join(",", seq.Skip(2).Take(3))
                + " takeWhile=" + string.Join(",", seq.TakeWhile(n => n % 3 == 0))
                + " skipWhile=" + string.Join(",", seq.SkipWhile((n, i) => n > i))
                + " page2=" + string.Join(",", seq.OrderBy(n => n).Skip(3).Take(3)));
            Console.WriteLine("  any>14=" + seq.Any(n => n > 14) + " all>1=" + seq.All(n => n > 1) + " contains9=" + seq.Contains(9)
                + " firstOrDefault>100=" + seq.FirstOrDefault(n => n > 100) + " last even=" + seq.Last(n => n % 2 == 0));

            Console.WriteLine("-- deferred vs immediate");
            evaluations = 0;
            var lazy = Source(6).Where(n => n % 2 == 1).Select(n => n * n);
            Console.WriteLine("  after build evaluations=" + evaluations);
            int first = lazy.First();
            Console.WriteLine("  after First()=" + first + " evaluations=" + evaluations);
            List<int> eager = lazy.ToList();
            Console.WriteLine("  after ToList " + string.Join(",", eager) + " evaluations=" + evaluations);
            var list = new List<int> { 1, 2, 3 };
            var view = list.Select(n => n * 100);
            var snapshot = view.ToArray();
            list.Add(4);
            Console.WriteLine("  view=" + string.Join(",", view) + " snapshot=" + string.Join(",", snapshot));

            Console.WriteLine("-- closures over loops");
            var funcs = new List<Func<int>>();
            for (int i = 0; i < 4; i++) { int copy = i; funcs.Add(() => copy * copy + 1); }
            foreach (int v in new[] { 5, 6, 7 }) funcs.Add(() => v * 2);
            Console.WriteLine("  " + string.Join(",", funcs.Select(f => f())));
            int threshold = 100;
            var filtered = employees.Where(e => e.Salary > threshold);
            int c1 = filtered.Count();
            threshold = 130;
            int c2 = filtered.Count();
            Console.WriteLine("  captured threshold counts " + c1 + " then " + c2);
            var queries = new List<IEnumerable<string>>();
            foreach (string dept in new[] { "Eng", "Ops", "Sales" }) queries.Add(employees.Where(e => e.Dept == dept).Select(e => e.Name));
            Console.WriteLine("  " + string.Join(" | ", queries.Select(q => string.Join("+", q))));

            Console.WriteLine("-- switch and string building");
            var sb = new StringBuilder();
            foreach (var e in employees.OrderBy(e => e.Salary).ThenBy(e => e.Id))
            {
                char grade;
                switch (e.Salary / 25)
                {
                    case 3: grade = 'C'; break;
                    case 4: grade = 'B'; break;
                    case 5: grade = 'A'; break;
                    default: grade = e.Salary > 150 ? 'S' : '?'; break;
                }
                sb.Append(grade);
            }
            Console.WriteLine("  grades=" + sb + " anon equals=" + new { A = 1, B = "x" }.Equals(new { A = 1, B = "x" })
                + " anon ToString=" + new { Id = 7, Tag = "t" });
        }
    }
}
