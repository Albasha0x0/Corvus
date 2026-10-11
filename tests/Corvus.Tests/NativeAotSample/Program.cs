using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace Sample.Zoo
{
    public interface ISpeaker { string Speak(); int Legs { get; } }
    public abstract class Animal : ISpeaker
    {
        public string Name;
        protected Animal(string name) { Name = name; }
        public abstract string Speak();
        public virtual int Legs => 4;
        public override string ToString() => "Animal:" + Name;
    }
    public sealed class Dog : Animal
    {
        public int Barks;
        public Dog(string n) : base(n) { }
        public override string Speak() { Barks++; return "Woof from " + Name; }
    }
    public class Bird : Animal
    {
        public Bird(string n) : base(n) { }
        public override string Speak() => "Tweet";
        public override int Legs => 2;
    }
    public struct Point { public int X, Y; public override string ToString() => $"({X},{Y})"; }
    public class Box<T> { public T Value; public Box(T v) { Value = v; } [MethodImpl(MethodImplOptions.NoInlining)] public T Get() => Value; }
    public class Reflected { public int Field1; public string Prop1 { get; set; } = "p"; public void Hello() => Console.WriteLine("hello via reflection"); }

    public static class Program
    {
        static readonly int[] Table = { 1, 2, 3, 5, 8, 13 };
        const string Secret = "FROZEN_LITERAL_MARKER_42";

        [MethodImpl(MethodImplOptions.NoInlining)]
        static int Compute(int a, int b) { int s = 0; foreach (var t in Table) s += t * a ^ b; return s; }

        [MethodImpl(MethodImplOptions.NoInlining)]
        static void Thrower(int depth) { if (depth == 0) throw new InvalidOperationException("boom"); Thrower(depth - 1); }

        public static int Main(string[] args)
        {
            var list = new List<ISpeaker> { new Dog("rex"), new Bird("tweety") };
            foreach (var s in list) Console.WriteLine(s.Speak() + " " + s.Legs);
            Console.WriteLine(Secret + Compute(args.Length, 7));
            Console.WriteLine(new Box<Point>(new Point { X = 1, Y = 2 }).Get());
            Console.WriteLine(new Box<string>("s").Get());
            var t = typeof(Reflected);
            object o = Activator.CreateInstance(t)!;
            t.GetMethod("Hello")!.Invoke(o, null);
            foreach (var f in t.GetFields()) Console.WriteLine(f.Name);
            try { Thrower(3); } catch (Exception e) { Console.WriteLine(e.StackTrace); }
            return 0;
        }
    }
}
