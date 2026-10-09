// A .NET Framework program for the pipeline round trip (PipelineRoundTripTests): reflection over its own members -
// members located through custom id attributes (never by name), MethodInfo/ConstructorInfo invocation, Activator,
// field and property access, attribute data, MakeGenericType/MakeGenericMethod, delegates from MethodInfo and enum
// reflection; its output depends only on its code.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;

namespace Reflection
{
    [AttributeUsage(AttributeTargets.All, AllowMultiple = false)]
    sealed class IdAttribute : Attribute
    {
        public int Id { get; private set; }
        public string Tag { get; set; }
        public int Weight;
        public IdAttribute(int id) { Id = id; }
    }

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
    sealed class NoteAttribute : Attribute
    {
        public string Text { get; private set; }
        public Type Kind { get; private set; }
        public int[] Numbers { get; set; }
        public NoteAttribute(string text, Type kind) { Text = text; Kind = kind; }
    }

    interface IShape { double Area(); int Corners { get; } }

    [Id(301)] class Square : IShape { public double Side = 3; public double Area() { return Side * Side; } public int Corners { get { return 4; } } }
    [Id(302)] class Triangle : IShape { public double Area() { return 0.5 * 6 * 5; } public int Corners { get { return 3; } } }
    [Id(303)] class Circle : IShape { public double Area() { return Math.PI * 4; } public int Corners { get { return 0; } } }

    enum Color : byte { Black = 0, Red = 1, Green = 2, Blue = 4, White = 7 }

    [Flags] enum Perm { None = 0, Read = 1, Write = 2, Exec = 4, All = Read | Write | Exec }

    struct Point
    {
        [Id(1)] public int X;
        [Id(2)] public int Y;
        public override string ToString() { return "(" + X + "," + Y + ")"; }
    }

    [Id(100, Tag = "calc", Weight = 9)]
    [Note("first", typeof(int), Numbers = new[] { 1, 2, 3 })]
    [Note("second", typeof(string))]
    public class Calculator
    {
        [Id(1)] public int Accumulator;
        [Id(2)] private int hidden = 5;
        [Id(3)] public static int Instances;

        [Id(10)] public int Scale { get; set; }
        [Id(11)] private string Label { get; set; }
        [Id(12)] public int ReadOnlyTwice { get { return Scale * 2; } }

        [Id(0)] public Calculator() : this(1, "none") { }
        [Id(1)] public Calculator(int scale) : this(scale, "s" + scale) { }
        [Id(2)] public Calculator(int scale, string label) { Instances++; Scale = scale; Label = label; }

        [Id(20, Tag = "add")] public int Add(int a, int b) { return (a + b) * Scale; }
        [Id(21)] private int Mix(int a) { return a * 31 + hidden; }
        [Id(22)] public static long Fact(int n) { long r = 1; for (int i = 2; i <= n; i++) r *= i; return r; }
        [Id(23)] public string Describe() { return Label + ":" + Accumulator + "x" + Scale; }
        [Id(24)] public int Accumulate(params int[] values) { foreach (int v in values) Accumulator += v; return Accumulator; }
        [Id(25)] private static int Pick(int x) { return x * 10; }
        [Id(26)] private static int Pick(string s) { return s.Length; }
        [Id(27)] public T Echo<T>(T v) { return v; }
        [Id(28)] [Note("throws", typeof(InvalidOperationException))] public void Fail(int code) { throw new InvalidOperationException("fail " + code); }
        [Id(29)] public void Swap(ref int a, out int b) { b = a; a = a * Scale; }
    }

    [Id(200)]
    public class Box<T>
    {
        [Id(1)] public T Value;
        [Id(2)] public Box(T value) { Value = value; }
        [Id(3)] public string Show() { return "Box(" + Value + ")"; }
        [Id(4)] public Box<T> With(T next) { return new Box<T>(next); }
    }

    public class Pair<TA, TB> { public TA A; public TB B; }

    static class Program
    {
        const BindingFlags All = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;
        static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

        static int IdOf(MemberInfo m)
        {
            var a = (IdAttribute)Attribute.GetCustomAttribute(m, typeof(IdAttribute));
            return a == null ? -1 : a.Id;
        }

        static T ById<T>(IEnumerable<T> members, int id) where T : MemberInfo
        {
            return members.Single(m => IdOf(m) == id);
        }

        static MethodInfo Method(Type t, int id) { return ById(t.GetMethods(All), id); }
        static FieldInfo Field(Type t, int id) { return ById(t.GetFields(All), id); }
        static PropertyInfo Property(Type t, int id) { return ById(t.GetProperties(All), id); }
        static ConstructorInfo Ctor(Type t, int id) { return ById(t.GetConstructors(All), id); }

        static string TypeKey(Type t)
        {
            // Types are identified by comparison, never by name.
            if (t == typeof(int)) return "int";
            if (t == typeof(string)) return "string";
            if (t == typeof(InvalidOperationException)) return "invalidOp";
            return "other";
        }

        static string Fmt(object o)
        {
            if (o == null) return "null";
            if (o is double) return ((double)o).ToString("F3", Inv);
            if (o is Array)
            {
                var arr = (Array)o;
                var items = new List<string>();
                foreach (object x in arr) items.Add(Fmt(x));
                return "[" + string.Join(",", items) + "]";
            }
            return Convert.ToString(o, Inv);
        }

        static int Main()
        {
            Type ct = typeof(Calculator);
            var calcAttr = (IdAttribute)Attribute.GetCustomAttribute(ct, typeof(IdAttribute));
            Console.WriteLine("class id=" + calcAttr.Id + " tag=" + calcAttr.Tag + " weight=" + calcAttr.Weight);
            var notes = ct.GetCustomAttributes(typeof(NoteAttribute), false).Cast<NoteAttribute>().OrderBy(n => n.Text, StringComparer.Ordinal).ToList();
            foreach (var n in notes)
                Console.WriteLine("  note " + n.Text + " kind=" + TypeKey(n.Kind) + " numbers=" + (n.Numbers == null ? "none" : string.Join("+", n.Numbers) + "=" + n.Numbers.Sum()));

            Console.WriteLine("attributed: methods=" + ct.GetMethods(All).Count(m => IdOf(m) >= 0)
                + " fields=" + ct.GetFields(All).Count(f => IdOf(f) >= 0)
                + " props=" + ct.GetProperties(All).Count(p => IdOf(p) >= 0)
                + " ctors=" + ct.GetConstructors(All).Count(c => IdOf(c) >= 0));
            var ids = ct.GetMethods(All).Select(IdOf).Where(i => i >= 0).OrderBy(i => i).ToArray();
            Console.WriteLine("method ids: " + string.Join(",", ids));
            foreach (int id in ids)
            {
                MethodInfo mi = Method(ct, id);
                Console.WriteLine(string.Format(Inv, "  m{0}: params={1} static={2} generic={3} returnsVoid={4} notes={5}",
                    id, mi.GetParameters().Length, mi.IsStatic, mi.IsGenericMethodDefinition, mi.ReturnType == typeof(void),
                    mi.GetCustomAttributes(typeof(NoteAttribute), false).Length));
            }

            // Constructors via ConstructorInfo and Activator
            var c0 = (Calculator)Ctor(ct, 0).Invoke(null);
            var c1 = (Calculator)Ctor(ct, 1).Invoke(new object[] { 3 });
            var c2 = (Calculator)Activator.CreateInstance(ct, 4, "four");
            var c3 = (Calculator)Activator.CreateInstance(ct);
            Console.WriteLine("ctors: " + c0.Describe() + " " + c1.Describe() + " " + c2.Describe() + " " + c3.Describe() + " instances=" + Field(ct, 3).GetValue(null));

            // Invocation
            Console.WriteLine("add=" + Method(ct, 20).Invoke(c1, new object[] { 5, 6 }) + " mix=" + Method(ct, 21).Invoke(c2, new object[] { 2 }) + " fact=" + Method(ct, 22).Invoke(null, new object[] { 15 }));
            Console.WriteLine("accumulate=" + Method(ct, 24).Invoke(c2, new object[] { new[] { 10, 20, 30 } }) + " then=" + Method(ct, 24).Invoke(c2, new object[] { new int[0] }));
            Console.WriteLine("pick int=" + Method(ct, 25).Invoke(null, new object[] { 7 }) + " pick string=" + Method(ct, 26).Invoke(null, new object[] { "seven" }));
            MethodInfo echo = Method(ct, 27);
            Console.WriteLine("echo int=" + echo.MakeGenericMethod(typeof(int)).Invoke(c0, new object[] { 42 }) + " echo arr=" + Fmt(echo.MakeGenericMethod(typeof(int[])).Invoke(c0, new object[] { new[] { 3, 1, 2 } })) + " genArgs=" + echo.GetGenericArguments().Length);
            try
            {
                Method(ct, 28).Invoke(c0, new object[] { 77 });
            }
            catch (TargetInvocationException tie)
            {
                Console.WriteLine("invoke threw invalidOp=" + (tie.InnerException is InvalidOperationException) + ": " + tie.InnerException.Message);
            }
            object[] swapArgs = { 9, null };
            Method(ct, 29).Invoke(c1, swapArgs);
            Console.WriteLine("ref/out args: a=" + swapArgs[0] + " b=" + swapArgs[1] + " byRef=" + Method(ct, 29).GetParameters().Count(p => p.ParameterType.IsByRef) + " out=" + Method(ct, 29).GetParameters().Count(p => p.IsOut));

            // Fields and properties
            Field(ct, 1).SetValue(c3, 123);
            Field(ct, 2).SetValue(c3, 1000);
            Property(ct, 10).SetValue(c3, 6, null);
            Property(ct, 11).SetValue(c3, "renamed", null);
            Console.WriteLine("fields: acc=" + Field(ct, 1).GetValue(c3) + " hidden=" + Field(ct, 2).GetValue(c3) + " mix=" + Method(ct, 21).Invoke(c3, new object[] { 1 }) + " describe=" + c3.Describe());
            PropertyInfo twice = Property(ct, 12);
            Console.WriteLine("props: twice=" + twice.GetValue(c3, null) + " canWrite=" + twice.CanWrite + " labelSetterPublic=" + (Property(ct, 11).GetSetMethod() != null) + " labelSetterAny=" + (Property(ct, 11).GetSetMethod(true) != null));

            // Delegates from MethodInfo
            var add = (Func<int, int, int>)Delegate.CreateDelegate(typeof(Func<int, int, int>), c2, Method(ct, 20));
            var fact = (Func<int, long>)Delegate.CreateDelegate(typeof(Func<int, long>), Method(ct, 22));
            long dsum = 0;
            for (int i = 1; i <= 10; i++) dsum += add(i, i * i) + fact(i % 6);
            Console.WriteLine("delegates sum=" + dsum);

            // Struct fields through a box
            object boxed = new Point { X = 1, Y = 2 };
            FieldInfo px = ById(typeof(Point).GetFields(All), 1), py = ById(typeof(Point).GetFields(All), 2);
            px.SetValue(boxed, 40);
            py.SetValue(boxed, (int)py.GetValue(boxed) * 21);
            Console.WriteLine("boxed point=" + boxed + " isValueType=" + typeof(Point).IsValueType);

            // Generics
            Type openBox = typeof(Box<>);
            Type intBox = openBox.MakeGenericType(typeof(int));
            Type strBox = openBox.MakeGenericType(typeof(string));
            object ib = Ctor(intBox, 2).Invoke(new object[] { 5 });
            object sb = Activator.CreateInstance(strBox, "abc");
            object ib2 = Method(intBox, 4).Invoke(ib, new object[] { 99 });
            Console.WriteLine("generic: " + Method(intBox, 3).Invoke(ib, null) + " " + Method(strBox, 3).Invoke(sb, null) + " " + Method(intBox, 3).Invoke(ib2, null) + " value=" + Field(intBox, 1).GetValue(ib2));
            Console.WriteLine("generic info: open=" + openBox.IsGenericTypeDefinition + " closed=" + intBox.IsGenericTypeDefinition + " same=" + (intBox == typeof(Box<int>)) + " defBack=" + (intBox.GetGenericTypeDefinition() == openBox) + " arg=" + TypeKey(intBox.GetGenericArguments()[0]) + " id=" + IdOf(intBox));
            Type pair = typeof(Pair<,>).MakeGenericType(typeof(long), typeof(Box<string>));
            Console.WriteLine("pair arity=" + pair.GetGenericArguments().Length + " containsOpen=" + pair.ContainsGenericParameters + " second generic=" + pair.GetGenericArguments()[1].IsGenericType);
            Type listOfBox = typeof(List<>).MakeGenericType(intBox);
            var list = (System.Collections.IList)Activator.CreateInstance(listOfBox);
            for (int i = 0; i < 4; i++) list.Add(Ctor(intBox, 2).Invoke(new object[] { i * i }));
            int gsum = 0;
            foreach (object o in list) gsum += (int)Field(intBox, 1).GetValue(o);
            Console.WriteLine("list of boxes count=" + list.Count + " sum=" + gsum);

            // Types found by attribute, invoked through an interface
            var shapes = typeof(Program).Assembly.GetTypes()
                .Where(t => typeof(IShape).IsAssignableFrom(t) && !t.IsInterface && IdOf(t) > 0)
                .OrderBy(IdOf).ToList();
            double totalArea = 0;
            foreach (Type t in shapes)
            {
                var s = (IShape)Activator.CreateInstance(t);
                totalArea += s.Area();
                Console.WriteLine("shape " + IdOf(t) + ": area=" + s.Area().ToString("F4", Inv) + " corners=" + s.Corners + " ifaces=" + t.GetInterfaces().Length);
            }
            Console.WriteLine("shapes=" + shapes.Count + " total=" + totalArea.ToString("F4", Inv));

            // Enum reflection (values and counts only)
            Array colors = Enum.GetValues(typeof(Color));
            var colorInts = new List<int>();
            foreach (object c in colors) colorInts.Add(Convert.ToInt32(c, Inv));
            Console.WriteLine("enum color names=" + Enum.GetNames(typeof(Color)).Length + " values=" + string.Join(",", colorInts) + " byte=" + (Enum.GetUnderlyingType(typeof(Color)) == typeof(byte)));
            int defined = 0;
            for (int v = 0; v < 10; v++) if (Enum.IsDefined(typeof(Color), (byte)v)) defined += 1 << v;
            Console.WriteLine("enum defined mask=" + defined);
            var perm = (Perm)Enum.ToObject(typeof(Perm), 5);
            Console.WriteLine("flags: value=" + (int)perm + " read=" + perm.HasFlag(Perm.Read) + " write=" + perm.HasFlag(Perm.Write) + " all=" + (int)Perm.All + " isFlags=" + typeof(Perm).IsDefined(typeof(FlagsAttribute), false) + " names=" + Enum.GetNames(typeof(Perm)).Length);
            int permSum = 0;
            foreach (Perm p in Enum.GetValues(typeof(Perm)))
            {
                switch (p)
                {
                    case Perm.None: permSum += 1000; break;
                    case Perm.All: permSum += 100; break;
                    default: permSum += (int)p * 3; break;
                }
            }
            Console.WriteLine("perm switch sum=" + permSum);

            Console.WriteLine("type checks: calcBaseObject=" + (ct.BaseType == typeof(object)) + " calcAbstract=" + ct.IsAbstract + " shapeIface=" + typeof(IShape).IsInterface + " arrayRank=" + typeof(int[,]).GetArrayRank() + " byRef=" + typeof(int).MakeByRefType().IsByRef);
            return 0;
        }
    }
}
